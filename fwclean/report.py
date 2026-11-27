"""분석 결과 출력: 웹 UI 용 JSON, 엑셀 리포트, 정리된 정책 파일, 장비 명령어."""
from __future__ import annotations

import io
from collections import Counter
from datetime import datetime

from .analyzer import CODES, STATUS_LABEL, Analysis
from .model import Rule
from .sets import describe_addr, describe_svc


def _finding_json(f):
    label, cat, sev, desc = CODES[f.code]
    return {"code": f.code, "label": label, "category": cat, "severity": sev, "desc": desc,
            "refs": f.refs, "detail": f.detail}


def rule_json(a: Analysis, r: Rule) -> dict:
    uid = r.meta["uid"]
    t = r.text or {}
    return {
        "uid": uid, "scope": r.scope, "seq": r.seq + 1, "rid": r.rid, "name": r.name, "action": r.action,
        "enabled": r.enabled, "hits": r.hits, "comment": r.comment,
        "src_zone": t.get("src_zone", str(r.src_zone)), "dst_zone": t.get("dst_zone", str(r.dst_zone)),
        "src": t.get("src", ""), "dst": t.get("dst", ""), "svc": t.get("svc", ""),
        "app": t.get("app", "any"), "users": t.get("users", "any"),
        "resolved": {"src": describe_addr(r.src), "dst": describe_addr(r.dst), "svc": describe_svc(r.svc)},
        "status": a.status(uid), "removed": uid in a.removed,
        "findings": [_finding_json(f) for f in a.findings[uid]],
    }


def summary(a: Analysis) -> dict:
    rules = a.policy.rules
    by_code = Counter(f.code for fs in a.findings.values() for f in fs)
    by_status = Counter(a.status(r.meta["uid"]) for r in rules)
    return {
        "vendor": a.policy.vendor, "source": a.policy.source_name, "total": len(rules),
        "enabled": sum(1 for r in rules if r.enabled), "scopes": len(a.policy.scopes()),
        "removed": len(a.removed), "remaining": len(rules) - len(a.removed),
        "by_code": {k: {"count": by_code.get(k, 0), "label": v[0], "category": v[1], "severity": v[2],
                        "desc": v[3]} for k, v in CODES.items()},
        "by_status": {k: {"count": by_status.get(k, 0), "label": STATUS_LABEL[k]} for k in STATUS_LABEL},
        "merge_groups": len(a.merge_groups), "elapsed": round(a.elapsed, 3),
        "hotspots": hotspots(a),
        "warnings": a.policy.warnings[:50], "has_hits": any(r.hits is not None for r in rules),
        "commands_supported": a.policy.vendor in COMMANDS,
        "options": vars(a.options), "meta": {k: v for k, v in a.policy.meta.items() if k != "header"},
    }


def hotspots(a: Analysis, limit=5) -> list[dict]:
    """다른 정책을 많이 가리는 '주요 근거 정책' (중간에 낀 any 정책 등)."""
    from collections import Counter
    cnt = Counter(f.refs[0] for fs in a.findings.values() for f in fs
                  if f.code in ("DUPLICATE", "REDUNDANT", "SHADOWED", "DEAD") and f.refs)
    out = []
    for uid, n in cnt.most_common(limit):
        if n < 10:
            break
        r = a.policy.rules[uid]
        t = r.text or {}
        out.append({"uid": uid, "count": n, "scope": r.scope, "rid": r.rid, "name": r.name, "action": r.action,
                    "src": t.get("src", ""), "dst": t.get("dst", ""), "svc": t.get("svc", "")})
    return out


def to_json(a: Analysis) -> dict:
    return {"summary": summary(a), "rules": [rule_json(a, r) for r in a.policy.rules],
            "merge_groups": a.merge_groups}


# --------------------------------------------------------------------------- 엑셀 리포트

FILL = {"remove": "F8D7DA", "candidate": "FFF3CD", "review": "FFE5CC", "info": "E7F1FF", "keep": "FFFFFF"}


def excel_report(a: Analysis) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    thin = Side(style="thin", color="BBBBBB")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    head_font = Font(bold=True, color="FFFFFF")
    head_fill = PatternFill("solid", fgColor="2F3B52")
    wrap = Alignment(wrap_text=True, vertical="top")
    s = summary(a)
    uid2label = {r.meta["uid"]: f"[{r.scope}] {r.label}" for r in a.policy.rules}

    # 요약
    ws = wb.active
    ws.title = "요약"
    rows = [("방화벽 정책 정리 리포트", ""), ("", ""),
            ("입력 파일", s["source"]), ("벤더", s["vendor"]), ("분석 일시", datetime.now().strftime("%Y-%m-%d %H:%M")),
            ("전체 정책", s["total"]), ("활성 정책", s["enabled"]), ("정리 후 정책", s["remaining"]),
            ("정리 대상(제외)", s["removed"]), ("", ""), ("판정", "건수")]
    for code, v in s["by_code"].items():
        rows.append((v["label"], v["count"]))
    rows += [("", ""), ("판정 기준", "")]
    for code, v in CODES.items():
        rows.append((v[0], v[3]))
    if s["hotspots"]:
        rows += [("", ""), ("주요 근거 정책", "아래 정책 하나가 다른 정책을 많이 가립니다. 활성 상태·동작을 먼저 확인하세요.")]
        rows += [(f"[{h['scope']}] {h['rid']}", f"{h['count']}개 정책을 가림 — {h['src']} → {h['dst']} / {h['svc']}")
                 for h in s["hotspots"]]
    if s["warnings"]:
        rows += [("", ""), ("경고", "")] + [("", w) for w in s["warnings"]]
    for row in rows:
        ws.append(row)
    ws["A1"].font = Font(bold=True, size=14)
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 100
    for row in ws.iter_rows(min_row=3):
        for c in row:
            c.alignment = wrap

    def table(title, header, data, status_col=None, widths=None):
        sh = wb.create_sheet(title)
        sh.append(header)
        for c in sh[1]:
            c.font, c.fill, c.border = head_font, head_fill, border
        for row, status in data:
            sh.append(row)
            fill = PatternFill("solid", fgColor=FILL.get(status, "FFFFFF"))
            for c in sh[sh.max_row]:
                c.border, c.alignment = border, wrap
                if status_col is not None:
                    c.fill = fill
        sh.freeze_panes = "A2"
        sh.auto_filter.ref = sh.dimensions
        for i, w in enumerate(widths or [], start=1):
            sh.column_dimensions[get_column_letter(i)].width = w
        return sh

    header = ["상태", "판정", "그룹", "순서", "정책 ID", "정책명", "동작", "사용", "출발지 존", "목적지 존",
              "출발지", "목적지", "서비스", "애플리케이션", "Hit", "근거 / 관련 정책", "설명"]
    widths = [10, 24, 16, 6, 14, 20, 7, 6, 14, 14, 30, 30, 26, 16, 8, 50, 30]

    def row_of(r):
        uid = r.meta["uid"]
        fs = a.findings[uid]
        st = a.status(uid)
        reasons = []
        for f in fs:
            refs = ", ".join(uid2label[x] for x in f.refs[:5])
            reasons.append(f"[{CODES[f.code][0]}] " + (f.detail or "") + (f" → {refs}" if refs and not f.detail else ""))
        t = r.text or {}
        return ([STATUS_LABEL[st], ", ".join(CODES[f.code][0] for f in fs), r.scope, r.seq + 1, r.rid, r.name,
                 {"allow": "허용", "deny": "차단"}.get(r.action, "미확인"), "Y" if r.enabled else "N", t.get("src_zone", ""), t.get("dst_zone", ""),
                 t.get("src", ""), t.get("dst", ""), t.get("svc", ""), t.get("app", ""),
                 "" if r.hits is None else r.hits, "\n".join(reasons), r.comment], st)

    table("전체 정책", header, [row_of(r) for r in a.policy.rules], 0, widths)
    table("정리 대상", header, [row_of(r) for r in a.policy.rules if r.meta["uid"] in a.removed], 0, widths)
    table("검토 필요", header,
          [row_of(r) for r in a.policy.rules if a.status(r.meta["uid"]) == "review"], 0, widths)
    mg = []
    for gi, g in enumerate(a.merge_groups, 1):
        for uid in g:
            r = a.policy.rules[uid]
            t = r.text or {}
            mg.append(([gi, r.scope, r.rid, r.name, r.action, t.get("src", ""), t.get("dst", ""), t.get("svc", "")],
                       "info"))
    table("통합 후보", ["묶음", "그룹", "정책 ID", "정책명", "동작", "출발지", "목적지", "서비스"], mg, 0,
          [6, 16, 14, 20, 7, 30, 30, 26])

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# --------------------------------------------------------------------------- 정리된 정책 파일 (표 형식 입력)

def cleaned_table(a: Analysis) -> bytes | None:
    """표 형식으로 입력된 경우: 원본과 같은 열 구조로 정리 대상을 뺀 파일."""
    header = a.policy.meta.get("header")
    if not header:
        return None
    from openpyxl import Workbook
    wb = Workbook()
    wb.remove(wb.active)
    sheets = a.policy.meta.get("sheets") or [{"sheet": "정리된 정책", "header": header}]
    for info in sheets:
        ws = wb.create_sheet(str(info["sheet"])[:31])
        if info.get("zones"):
            ws.append([f"From {info['zones'][0]} To {info['zones'][1]}"])
        ws.append(info["header"])
        for r in a.policy.rules:
            if r.meta["uid"] in a.removed or r.meta.get("sheet", info["sheet"]) != info["sheet"]:
                continue
            for row in r.meta.get("rows", []):
                ws.append(["" if c is None else c for c in row])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# --------------------------------------------------------------------------- 장비 명령어

def _q(s):
    return '"' + str(s).replace('"', '\\"') + '"'


def _pan(a, rules, mode):
    vsyses = {r.meta.get("container") for r in a.policy.rules if not str(r.scope).startswith("DG:")}
    out = []
    for r in rules:
        rb = r.meta.get("rulebase", "rulebase")
        cont = r.meta.get("container", "")
        if rb.startswith("shared"):
            path = f"shared {rb.split()[1]} security rules {_q(r.rid)}"
        elif str(r.scope).startswith("DG:"):
            path = f"device-group {_q(cont)} {rb} security rules {_q(r.rid)}"
        elif len(vsyses) > 1:
            path = f"vsys {cont} rulebase security rules {_q(r.rid)}"
        else:
            path = f"rulebase security rules {_q(r.rid)}"
        out.append(f"set {path} disabled yes" if mode == "disable" else f"delete {path}")
    return ["configure"] + out + ["commit"]


def _forti(a, rules, mode):
    multi = len({r.scope for r in a.policy.rules}) > 1 or any(r.scope != "root" for r in a.policy.rules)
    out = []
    by_vdom: dict[str, list] = {}
    for r in rules:
        by_vdom.setdefault(r.scope, []).append(r)
    for vdom, rs in by_vdom.items():
        if multi:
            out += ["config vdom", f"edit {vdom}"]
        out.append("config firewall policy")
        for r in rs:
            if mode == "disable":
                out += [f"    edit {r.rid}", "        set status disable", "    next"]
            else:
                out.append(f"    delete {r.rid}")
        out.append("end")
        if multi:
            out.append("end")
    return out


def _asa(a, rules, mode):
    out = []
    for r in rules:
        raw = r.raw
        if not raw:
            continue
        if mode == "disable":
            out.append(raw if raw.endswith(" inactive") else raw + " inactive")
        else:
            out.append("no " + raw)
    return out + ["write memory"]


def _srx(a, rules, mode):
    out = []
    verb = "deactivate" if mode == "disable" else "delete"
    for r in rules:
        ctx = r.meta.get("context", r.scope)
        if ctx == "global":
            path = f"security policies global policy {r.rid}"
        else:
            path = f"security policies from-zone {r.meta['from_zone'][0]} to-zone {r.meta['to_zone'][0]} policy {r.rid}"
        out.append(f"{verb} {path}")
    return ["configure"] + out + ["commit check", "commit"]


def _cp(a, rules, mode):
    out = ["# Check Point Management API (mgmt_cli). <LAYER> 를 실제 정책 레이어 이름으로 바꾸세요.",
           "mgmt_cli login > id.txt"]
    for r in rules:
        layer = r.scope if r.scope != "default" else "<LAYER>"
        ident = f"rule-number {r.rid}" if str(r.rid).isdigit() else f"name {_q(r.name or r.rid)}"
        if mode == "disable":
            out.append(f"mgmt_cli set access-rule layer {_q(layer)} {ident} enabled false -s id.txt")
        else:
            out.append(f"mgmt_cli delete access-rule layer {_q(layer)} {ident} -s id.txt")
    out += ["mgmt_cli publish -s id.txt", "mgmt_cli logout -s id.txt"]
    return out


def _screenos(a, rules, mode):
    if mode == "disable":
        return [f"set policy id {r.rid} disable" for r in rules] + ["save"]
    return [f"unset policy id {r.rid}" for r in rules] + ["save"]


COMMANDS = {"screenos": _screenos,"paloalto": _pan, "fortigate": _forti, "cisco_asa": _asa, "juniper_srx": _srx, "checkpoint": _cp}


def commands(a: Analysis) -> str:
    rules = [r for r in a.policy.rules if r.meta["uid"] in a.removed]
    if a.policy.vendor == "checkpoint":
        rules = sorted(rules, key=lambda r: (r.scope, -r.seq))  # 번호 기준 삭제는 아래부터
    head = [f"# 방화벽 정책 정리 명령어 - {a.policy.source_name}",
            f"# 생성: {datetime.now():%Y-%m-%d %H:%M}  /  대상 {len(rules)}건",
            "# 반드시 설정을 백업한 뒤 점검 시간에 적용하세요.",
            "# 권장 절차: 1) 비활성화 적용 → 2) 일정 기간 모니터링 → 3) 삭제", ""]
    gen = COMMANDS.get(a.policy.vendor)
    if not gen:
        lines = head + ["# 이 벤더는 CLI 명령어 생성을 지원하지 않습니다. 아래 정책을 관리 화면에서 정리하세요.", ""]
        for r in rules:
            reasons = ", ".join(CODES[f.code][0] for f in a.findings[r.meta["uid"]])
            lines.append(f"[{r.scope}] {r.label}  -  {reasons}")
        return "\n".join(lines) + "\n"
    lines = head + ["# ===== 1단계: 비활성화 =====", *gen(a, rules, "disable"), "",
                    "# ===== 2단계: 삭제 (모니터링 후) =====", *gen(a, rules, "delete"), ""]
    return "\n".join(lines)
