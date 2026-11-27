"""샘플 파일 기반 회귀 테스트: 벤더별 파서 + 분석 판정이 기대값과 같은지 확인."""
from pathlib import Path

import pytest

from fwclean import parsers
from fwclean.analyzer import analyze
from fwclean.report import cleaned_table, commands, excel_report, to_json

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def run(name, vendor="auto"):
    data = (SAMPLES / name).read_bytes()
    p = parsers.parse(data, name, vendor)
    a = analyze(p)
    codes = {r.rid: {f.code for f in a.findings[r.meta["uid"]]} for r in p.rules}
    return p, a, codes


def test_detect():
    assert parsers.detect((SAMPLES / "paloalto_running.xml").read_bytes(), "x.xml") == "paloalto"
    assert parsers.detect((SAMPLES / "fortigate.conf").read_bytes(), "x.conf") == "fortigate"
    assert parsers.detect((SAMPLES / "cisco_asa.txt").read_bytes(), "x.txt") == "cisco_asa"
    assert parsers.detect((SAMPLES / "juniper_srx.set").read_bytes(), "x.txt") == "juniper_srx"
    assert parsers.detect((SAMPLES / "checkpoint_export.csv").read_bytes(), "x.csv") == "checkpoint"


def test_paloalto():
    p, a, c = run("paloalto_running.xml")
    assert len(p.rules) == 11
    assert "REDUNDANT" in c["team1-to-web"]          # OFFICE ⊇ TEAM1, WEB-NET ⊇ WEB-GRP, WEB-PORTS ⊇ https
    assert "DUPLICATE" in c["office-to-web-copy"]
    assert "SHADOWED" in c["bad-host-web-allow"]     # 위의 deny 가 완전히 가림
    assert "REDUNDANT_DOWN" in c["web-to-db-mysql"]  # 아래 web-to-db 가 포함
    assert "REDUNDANT" in c["web2-to-db"]
    assert "DISABLED" in c["old-temp-rule"]
    assert "ANY" in c["trust-out-any"]
    assert "CONFLICT" not in c["trust-out-any"]      # 예외(특정 호스트 차단) 패턴은 충돌 아님
    assert c["office-to-web"] == set()
    assert c["update-out"] == set()                  # FQDN 은 이름 비교 → 보수적으로 유지


def test_fortigate():
    p, a, c = run("fortigate.conf")
    assert "REDUNDANT" in c["11"]
    assert "SHADOWED" in c["13"]                     # action 미지정 = deny (FortiOS 기본값)
    assert "REDUNDANT_DOWN" in c["14"]
    assert "DISABLED" in c["16"]
    assert "MERGE" in c["10"] and "MERGE" in c["17"]
    assert "ANY" in c["18"]
    cmd = commands(a)
    assert "delete 11" in cmd and "set status disable" in cmd


def test_cisco_asa():
    p, a, c = run("cisco_asa.txt")
    rules = {r.rid: r for r in p.rules}
    assert rules["OUTSIDE_IN:2"].hits == 1850       # 확장 라인 hitcnt 합산
    assert "REDUNDANT" in c["OUTSIDE_IN:3"]          # WEB-SERVERS(host 객체) ⊆ WEB-NET
    assert "SHADOWED" in c["OUTSIDE_IN:5"]
    assert "REDUNDANT" in c["OUTSIDE_IN:6"]
    assert "DISABLED" in c["OUTSIDE_IN:7"]
    assert "REDUNDANT" in c["INSIDE_IN:2"]
    assert "REDUNDANT_DOWN" in c["INSIDE_IN:3"]      # 아래 'permit ip OFFICE any' 가 포함
    assert not any(r.scope.startswith("OUTSIDE_IN;") for r in p.rules)
    assert not any("UNRESOLVED" in v for v in c.values())
    cmd = commands(a)
    assert "no access-list OUTSIDE_IN extended permit tcp object TEAM host WEB1 eq ssh" in cmd


def test_juniper():
    p, a, c = run("juniper_srx.set")
    assert "REDUNDANT" in c["team-web"]
    assert "SHADOWED" in c["team-ssh"]
    assert "REDUNDANT_DOWN" in c["web-db"]
    assert "DISABLED" in c["old"]
    assert "deactivate security policies from-zone trust to-zone dmz policy team-ssh" in commands(a)


def test_korean_table():
    p, a, c = run("korean_vendor_export.xlsx", "secui")
    assert len(p.rules) == 11
    assert "REDUNDANT" in c["2"]
    assert "SHADOWED" in c["4"]
    assert "REDUNDANT_DOWN" in c["5"]
    assert "DISABLED" in c["7"]
    assert "DUPLICATE" in c["10"]
    assert "MERGE" in c["8"] and "MERGE" in c["9"]
    assert "REDUNDANT_DOWN" not in c["3"]            # Cleanup(전체 차단)을 근거로 삼지 않음
    assert "CONFLICT" not in c["11"]                 # Cleanup 은 충돌로 보지 않음
    assert {r.rid: r.hits for r in p.rules}["1"] == 15320
    out = cleaned_table(a)
    assert out and len(out) > 1000


def test_legacy_multirow():
    p, a, c = run("legacy_multirow.xlsx")
    assert len(p.rules) == 7                         # Rule 100 이 2행 → 1개 정책
    r100 = next(r for r in p.rules if r.rid == "100")
    assert r100.svc.contains(parsers.tabular.parse_service_literal("tcp/443"))
    assert "REDUNDANT" in c["101"]
    assert "SHADOWED" in c["103"]
    assert "REDUNDANT_DOWN" not in c["104"]          # 맨 아래 any 허용을 근거로 삼지 않음
    assert "MERGE" in c["104"] and "MERGE" in c["105"]


def test_checkpoint():
    p, a, c = run("checkpoint_export.csv")
    assert "REDUNDANT" in c["3"] and "UNUSED" in c["3"]
    assert "mgmt_cli" in commands(a)


def test_screenos():
    p, a, c = run("screenos_getconfig.txt")
    assert p.vendor == "screenos"
    r10 = next(r for r in p.rules if r.rid == "10")
    assert "HTTP" in r10.text["svc"]                 # 하위 컨텍스트의 set service 반영
    assert "REDUNDANT" in c["11"]
    assert "SHADOWED" in c["13"]
    assert "REDUNDANT_DOWN" in c["14"]
    assert "DISABLED" in c["16"]
    assert c["17"] & {"DUPLICATE", "REDUNDANT"}
    assert "set policy id 13 disable" in commands(a)


def test_name_ip_inference_and_multisheet():
    """웹 화면 복사본 형태: 시트별 'From X To Y' 제목 + 이름에 IP 가 든 객체."""
    import io
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "A_Untrust"
    ws.append(["From Untrust To Trust"])
    ws.append(["ID", "Source", "Destination", "Service", "Action", "Enable"])
    ws.append(["1", "10.1.1.0_24", "172.16.0.5_WEB", "TCP8080", "", ""])
    ws.append(["2", "10.1.1.7(PC)", "172.16.0.5/32", "TCP8080", "", ""])
    ws.append(["3", "10.2.3.0", "172.16.0.5", "TCP2000_2001", "", ""])
    ws2 = wb.create_sheet("B_Trust")
    ws2.append(["From Trust To Untrust"])
    ws2.append(["ID", "Source", "Destination", "Service", "Action", "Enable"])
    ws2.append(["9", "172.16.0.5", "Any", "MAIL", "", ""])
    buf = io.BytesIO()
    wb.save(buf)
    p = parsers.parse(buf.getvalue(), "copy.xlsx")
    a = analyze(p)
    assert {r.scope for r in p.rules} == {"A_Untrust", "B_Trust"}
    r1, r2, r3 = p.rules[:3]
    assert str(r1.src_zone) == "Untrust"
    assert r1.src.contains(r2.src) and not r1.unresolved and not r2.unresolved
    # 동작 열이 비어 있으면 동작 미확인 → '위쪽에 완전히 포함'만 판정(DEAD), 하위 포함/통합은 하지 않음
    assert {f.code for f in a.findings[r2.meta["uid"]]} == {"DEAD"}
    assert all(r.action == "unknown" for r in p.rules)
    assert not any(f.code in ("REDUNDANT_DOWN", "MERGE", "CONFLICT")
                   for fs in a.findings.values() for f in fs)
    assert r3.src.contains(parsers.tabular.try_parse_literal_addr("10.2.3.99"))   # .0 → /24
    assert any("동작(허용/차단) 정보가 없는 시트" in w for w in p.warnings)
    cleaned = cleaned_table(a)
    from openpyxl import load_workbook
    assert load_workbook(io.BytesIO(cleaned)).sheetnames == ["A_Untrust", "B_Trust"]


@pytest.mark.parametrize("name", [f.name for f in SAMPLES.iterdir()])
def test_reports_build(name):
    p, a, c = run(name)
    j = to_json(a)
    assert j["summary"]["total"] == len(p.rules)
    assert excel_report(a)[:2] == b"PK"
