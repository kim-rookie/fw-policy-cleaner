"""표 형식(엑셀/CSV) 정책 export 파서.

국산 장비(SECUI, AXGATE, AhnLab TrusGuard, WINS SNIPER 등)와 Check Point SmartConsole,
Palo Alto GUI 의 정책 export 는 대부분 표 형식이다. 벤더·버전마다 열 이름이 조금씩 달라서
열 이름을 자동으로 인식하고, 인식하지 못하면 화면에서 열을 직접 지정할 수 있게 한다.

지원하는 형태
  - 한 행에 정책 하나 (셀 안에 여러 값이 줄바꿈 / ; / , 로 들어 있음)
  - 한 정책이 여러 행에 걸친 형태 (ID 칸이 비어 있거나 같은 ID 가 연속되면 이어지는 행으로 처리)
  - 같은 파일 안의 주소/서비스 객체 시트 (시트 이름에 '주소', 'address', '서비스', 'service' 등)
"""
from __future__ import annotations

import csv
import io
import re

from ..model import ALLOW, UNKNOWN, ObjectResolver, PolicySet, Rule, normalize_action
from ..sets import TokenSet, addr_from_network, try_parse_literal_addr
from .common import norm_header, parse_service_literal, split_values

FIELDS = {
    "id": ["ruleid", "policyid", "id", "no", "번호", "순번", "정책번호", "정책id", "ruleno", "rulenumber",
           "seq", "순서", "정책순서", "규칙번호", "rule", "정책"],
    "name": ["name", "rulename", "policyname", "정책명", "정책이름", "규칙이름", "이름"],
    "src_zone": ["sourcezone", "srczone", "fromzone", "from", "출발지존", "출발지zone", "srcintf",
                 "sourceinterface", "출발지인터페이스", "입력인터페이스", "inbound", "ingress"],
    "dst_zone": ["destinationzone", "dstzone", "tozone", "to", "목적지존", "목적지zone", "dstintf",
                 "destinationinterface", "목적지인터페이스", "출력인터페이스", "outbound", "egress"],
    "src": ["sourceaddress", "source", "src", "srcaddr", "srcaddress", "sourceip", "srcip", "출발지",
            "출발지주소", "출발지ip", "출발지객체", "출발지네트워크", "출발지주소ip", "송신지", "출발주소"],
    "dst": ["destinationaddress", "destination", "dst", "dest", "dstaddr", "dstaddress", "destinationip",
            "dstip", "목적지", "목적지주소", "목적지ip", "목적지객체", "목적지네트워크", "수신지", "목적주소"],
    "svc": ["service", "services", "servicesapplications", "서비스", "서비스포트", "포트", "port", "dstport",
            "destinationport", "protocolport", "프로토콜포트", "프로토콜", "서비스객체"],
    "app": ["application", "applications", "app", "애플리케이션", "어플리케이션", "응용프로그램"],
    "users": ["sourceuser", "user", "users", "사용자", "사용자그룹"],
    "action": ["action", "동작", "행위", "허용여부", "처리", "정책동작", "허용차단", "규칙동작", "액션", "allow/deny"],
    "enabled": ["enabled", "enable", "status", "state", "사용", "사용여부", "상태", "활성", "활성화", "활성여부",
                "use", "disabled"],
    "hits": ["rulehitcount", "ruleusagehitcount", "hitcount", "hits", "hit", "히트", "히트카운트", "hit수",
             "사용횟수", "매칭횟수", "적중횟수", "hitcnt"],
    "comment": ["comment", "comments", "description", "설명", "비고", "메모", "desc", "remark"],
    "scope": ["location", "vsys", "devicegroup", "vdom", "layer", "policypackage"],
    "schedule": ["schedule", "time", "스케줄", "시간", "시간대"],
}
FIELD_LABELS = {
    "id": "정책 ID/번호", "name": "정책명", "src_zone": "출발지 존/인터페이스", "dst_zone": "목적지 존/인터페이스",
    "src": "출발지", "dst": "목적지", "svc": "서비스", "app": "애플리케이션", "users": "사용자",
    "action": "동작", "enabled": "사용 여부", "hits": "Hit count", "comment": "설명", "scope": "정책 그룹",
    "schedule": "스케줄",
}

_DISABLED_WORDS = {"n", "no", "false", "0", "disable", "disabled", "off", "미사용", "비활성", "비활성화", "사용안함",
                   "x", "inactive", "중지"}
_ENABLED_WORDS = {"y", "yes", "true", "1", "enable", "enabled", "on", "사용", "활성", "활성화", "o", "active"}


# --------------------------------------------------------------------------- 파일 읽기

def read_sheets(data: bytes, filename: str) -> dict[str, list[list]]:
    name = filename.lower()
    if name.endswith((".xlsx", ".xlsm")):
        from openpyxl import load_workbook
        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        sheets = {}
        for ws in wb.worksheets:
            rows = [[("" if c is None else c) for c in row] for row in ws.iter_rows(values_only=True)]
            sheets[ws.title] = rows
        wb.close()
        return sheets
    if name.endswith(".xls"):
        raise ValueError("구형 .xls 형식은 지원하지 않습니다. 엑셀에서 .xlsx 로 다시 저장해 주세요.")
    text = decode_text(data)
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
    except csv.Error:
        dialect = csv.excel
    return {"Sheet1": [row for row in csv.reader(io.StringIO(text), dialect)]}


def decode_text(data: bytes) -> str:
    for enc in ("utf-8-sig", "cp949", "euc-kr", "utf-16"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- 헤더 인식

def map_headers(header: list) -> dict[str, int]:
    norms = [norm_header(h) for h in header]
    mapping: dict[str, int] = {}
    used: set[int] = set()
    # 1차: 완전 일치 (alias 순서 = 우선순위)
    for field, aliases in FIELDS.items():
        for alias in aliases:
            a = norm_header(alias)
            for idx, n in enumerate(norms):
                if idx not in used and n == a:
                    mapping[field] = idx
                    used.add(idx)
                    break
            if field in mapping:
                break
    # 2차: 부분 일치 (긴 alias 부터 → '출발지존' 이 '출발지' 보다 먼저)
    def partial_ok(a):  # 'to', 'id' 같은 짧은 영문은 부분 일치에 쓰지 않음 ('protocol' 오인 방지)
        return len(a) >= 3 or (len(a) >= 2 and not a.isascii())
    cands = sorted(((norm_header(a), f) for f, al in FIELDS.items() for a in al if partial_ok(norm_header(a))),
                   key=lambda x: -len(x[0]))
    for alias, field in cands:
        if field in mapping:
            continue
        for idx, n in enumerate(norms):
            if idx not in used and n and alias in n:
                mapping[field] = idx
                used.add(idx)
                break
    return mapping


def find_header_row(rows: list[list]) -> tuple[int, dict[str, int]]:
    best = (-1, {}, 0)
    for i, row in enumerate(rows[:40]):
        m = map_headers(row)
        score = len(m) + (3 if {"src", "dst"} <= m.keys() else 0)
        if score > best[2]:
            best = (i, m, score)
    if best[0] < 0 or not {"src", "dst"} <= best[1].keys():
        raise ValueError("정책 표의 헤더(출발지/목적지 열)를 찾지 못했습니다. 화면에서 열을 직접 지정해 주세요.")
    return best[0], best[1]


def preview(data: bytes, filename: str) -> dict:
    """열 매핑 UI 용 미리보기."""
    sheets = read_sheets(data, filename)
    out = []
    for name, rows in sheets.items():
        try:
            hi, mapping = find_header_row(rows)
        except ValueError:
            hi, mapping = 0, {}
        header = [str(h) for h in rows[hi]] if rows else []
        out.append({"sheet": name, "header_row": hi, "header": header,
                    "mapping": {k: header[v] for k, v in mapping.items() if v < len(header)},
                    "sample": [[str(c) for c in r] for r in rows[hi + 1: hi + 6]]})
    return {"sheets": out, "fields": list(FIELD_LABELS.items())}


# --------------------------------------------------------------------------- 객체 시트

_ADDR_SHEET = re.compile(r"addr|주소|address|network|네트워크|host|호스트|객체", re.I)
_SVC_SHEET = re.compile(r"service|서비스|port|포트", re.I)


def load_object_sheets(sheets: dict, policy_sheet: str, resolver: ObjectResolver):
    for name, rows in sheets.items():
        if name == policy_sheet or not rows:
            continue
        is_svc = bool(_SVC_SHEET.search(name))
        is_addr = bool(_ADDR_SHEET.search(name)) and not is_svc
        if not (is_svc or is_addr):
            continue
        hi = None
        for i, row in enumerate(rows[:10]):
            norms = [norm_header(c) for c in row]
            if any(n in ("name", "이름", "객체명", "객체이름", "주소명", "서비스명", "objectname") for n in norms):
                hi = i
                break
        if hi is None:
            continue
        norms = [norm_header(c) for c in rows[hi]]
        ni = next(i for i, n in enumerate(norms) if n in ("name", "이름", "객체명", "객체이름", "주소명", "서비스명",
                                                           "objectname"))
        vkeys = ("value", "ip", "address", "주소", "ip주소", "값", "members", "member", "멤버", "구성원", "내용",
                 "port", "포트", "서비스", "protocol", "프로토콜", "프로토콜포트", "subnet", "range", "범위")
        vis = [i for i, n in enumerate(norms) if i != ni and n in vkeys]
        if not vis:
            continue
        for row in rows[hi + 1:]:
            if ni >= len(row) or not str(row[ni]).strip():
                continue
            obj = str(row[ni]).strip()
            vals = []
            for vi in vis:
                if vi < len(row):
                    vals += split_values(row[vi])
            if not vals:
                continue
            if is_svc:
                # '프로토콜' 과 '포트' 가 따로 있는 경우 합친다
                if len(vals) == 2 and vals[0].lower() in ("tcp", "udp", "sctp"):
                    vals = [f"{vals[0]}/{vals[1]}"]
                resolver.svc_groups[obj] = vals
            else:
                resolver.addr_groups[obj] = vals


# --------------------------------------------------------------------------- 파싱

_FROM_TO = re.compile(r"from\s+[\"']?([^\s\"']+)[\"']?\s+to\s+[\"']?([^\s\"']+)", re.I)


def _policy_sheets(sheets: dict, options: dict):
    """정책 표가 있는 시트 목록 [(시트명, 헤더행, 매핑, 존 쌍)]."""
    sheet_name = options.get("sheet")
    names = [sheet_name] if sheet_name and sheet_name in sheets else list(sheets)
    found, errors = [], []
    for sn in names:
        rows = sheets[sn]
        if not rows:
            continue
        try:
            if options.get("mapping") and (not sheet_name or sn == sheet_name):
                hi = int(options.get("header_row", 0))
                header = [str(h) for h in rows[hi]]
                mapping = {f: header.index(h) for f, h in options["mapping"].items() if h in header}
                if not {"src", "dst"} <= mapping.keys():
                    raise ValueError("출발지/목적지 열 지정이 필요합니다.")
            else:
                hi, mapping = find_header_row(rows)
        except ValueError as e:
            errors.append(f"[{sn}] {e}")
            continue
        # 헤더 위 제목 줄의 'From X To Y' → 존 정보 (ScreenOS 등 웹 화면 복사본)
        zones = None
        for row in rows[:hi]:
            m = _FROM_TO.search(" ".join(str(c) for c in row if c))
            if m:
                zones = (m.group(1), m.group(2))
                break
        found.append((sn, hi, mapping, zones))
    if not found:
        raise ValueError(" / ".join(errors) or "읽을 수 있는 시트가 없습니다.")
    return found


def parse(data: bytes, filename: str, vendor: str = "generic", options: dict | None = None) -> PolicySet:
    options = options or {}
    sheets = read_sheets(data, filename)
    found = _policy_sheets(sheets, options)
    multi = len(found) > 1
    resolver = ObjectResolver()
    for sn, *_ in found:
        load_object_sheets(sheets, sn, resolver)
    infer = _AddrInference(options.get("infer_ip_from_name", True), options.get("zero_as_24", True))

    policy = PolicySet(vendor=vendor, rules=[], source_name=filename, meta={
        "sheets": [{"sheet": sn, "header_row": hi, "header": [str(h) for h in sheets[sn][hi]],
                    "mapping": {f: str(sheets[sn][hi][i]) for f, i in mp.items()},
                    "zones": list(z) if z else None} for sn, hi, mp, z in found]})
    first = policy.meta["sheets"][0]
    policy.meta.update({"sheet": first["sheet"], "header_row": first["header_row"], "header": first["header"],
                        "mapping": first["mapping"]})

    empty_action_sheets = []
    for sn, hi, mapping, zones in found:
        rows = sheets[sn]
        groups = _group_rows(rows, hi, mapping, options.get("merge_same_id", True))
        no_action = "action" not in mapping or not any(g["action"] for g in groups)
        if no_action:
            empty_action_sheets.append(sn)
        seq_by_scope: dict[str, int] = {}
        for n, g in enumerate(groups):
            scope = g["scope"] or (sn if multi else "default")
            seq = seq_by_scope.get(scope, 0)
            seq_by_scope[scope] = seq + 1
            rid = g["rid"] or str(n + 1)
            r = Rule(seq=seq, rid=rid, name=g["name"], scope=scope, comment=g["comment"])
            act = normalize_action(g["action"]) if g["action"] else (UNKNOWN if no_action else ALLOW)
            if act is None:
                policy.warnings.append(f"[{sn}] 정책 {rid}: 알 수 없는 동작 '{g['action']}' → 분석 제외")
                r.unanalyzable = f"알 수 없는 동작: {g['action']}"
                act = ALLOW
            r.action = act
            r.enabled = _parse_enabled(g["enabled"], mapping, rows[hi])
            name_low = (g["name"] or "").lower()
            if "[disabled]" in name_low or "(disabled)" in name_low:
                r.enabled = False
            if g["hits"]:
                try:
                    r.hits = int(float(str(g["hits"]).replace(",", "")))
                except ValueError:
                    pass
            if zones and not g["src_zone"] and not g["dst_zone"]:
                g["src_zone"], g["dst_zone"] = [zones[0]], [zones[1]]
            r.meta.update({"rows": g["rows"], "sheet": sn})
            _fill_match(r, g, resolver, infer)
            policy.rules.append(r)

    if empty_action_sheets:
        policy.warnings.append(
            "동작(허용/차단) 정보가 없는 시트: " + ", ".join(empty_action_sheets[:8])
            + " — 웹 화면에서 복사하면 아이콘으로 표시되던 동작·사용여부가 빠집니다. 이 시트는 동작과 무관하게 확실한 "
            "'상위 정책에 포함(동작 미확인)'만 판정하고, 하위 포함·충돌·통합 판정은 하지 않았습니다. "
            "사용여부(비활성)도 알 수 없으니 근거 정책이 실제로 활성 상태인지 꼭 확인하세요.")
    if infer.inferred:
        policy.warnings.append(
            f"객체 이름에 들어 있는 IP 로 주소를 추정한 객체 {len(infer.inferred)}개 "
            f"(예: {', '.join(sorted(infer.inferred)[:4])}). 상세 화면의 '해석된 실제 값'을 확인하세요.")
    if infer.zero24:
        policy.warnings.append(f"마스크 없이 .0 으로 끝나는 주소 {len(infer.zero24)}개를 /24 대역으로 간주했습니다 "
                               f"(예: {', '.join(sorted(infer.zero24)[:4])}).")
    if resolver.unresolved:
        policy.warnings.append(
            f"정의를 찾지 못한 객체 {len(resolver.unresolved)}개는 이름으로만 비교했습니다 "
            f"(예: {', '.join(sorted(resolver.unresolved)[:5])}). 객체 시트를 함께 넣으면 정확도가 올라갑니다.")
    return policy


def _group_rows(rows, hi, mapping, merge_same_id):
    def cell(row, field):
        idx = mapping.get(field)
        if idx is None or idx >= len(row):
            return ""
        v = row[idx]
        return "" if v is None else str(v).strip()

    groups: list[dict] = []
    for row in rows[hi + 1:]:
        if not any(str(c).strip() for c in row):
            continue
        rid = cell(row, "id")
        body = {f: split_values(cell(row, f)) for f in ("src", "dst", "svc", "src_zone", "dst_zone", "app", "users")}
        if not rid and not any(body.values()):
            continue
        cont = groups and ((not rid and not cell(row, "action")) or (merge_same_id and rid and rid == groups[-1]["rid"]))
        if cont:
            g = groups[-1]
            g["rows"].append(list(row))
            for f, vals in body.items():
                g[f] += vals
            for f in ("action", "enabled", "hits", "name", "comment", "scope", "schedule"):
                if not g[f]:
                    g[f] = cell(row, f)
            continue
        g = {"rid": rid, "rows": [list(row)], **body}
        for f in ("action", "enabled", "hits", "name", "comment", "scope", "schedule"):
            g[f] = cell(row, f)
        groups.append(g)
    return groups


_EMBED_IP = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:\s*([/_])\s*(\d{1,2}))?(?![\d.])")
_PLAIN_V4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class _AddrInference:
    """표 형식 export 에서 객체 정의 없이 이름만 있을 때의 보조 해석.

    - '10.1.1.5_WEB', 'DB(172.16.0.10)', '10.1.2.0_24' → 이름 속 IP(대역) 사용
    - 마스크 없는 'x.x.x.0' → /24 (기존 툴과 같은 처리)
    """

    def __init__(self, from_name: bool, zero_as_24: bool):
        self.from_name, self.zero_as_24 = from_name, zero_as_24
        self.inferred: set[str] = set()
        self.zero24: set[str] = set()

    @staticmethod
    def _norm_ip(ip: str):
        parts = ip.split(".")
        if any(int(x) > 255 for x in parts):
            return None
        return ".".join(str(int(x)) for x in parts)   # '10.001.2.3' 같은 앞자리 0 정리

    def literal(self, v: str):
        t = v.strip()
        if self.zero_as_24 and _PLAIN_V4.match(t) and t.endswith(".0"):
            ip = self._norm_ip(t)
            if ip:
                self.zero24.add(t)
                return addr_from_network(ip + "/24")
        lit = try_parse_literal_addr(t)
        if lit is not None:
            return lit
        if not self.from_name:
            return None
        found = _EMBED_IP.findall(t)
        if len(found) != 1:
            return None
        ip, sep, plen = found[0]
        ip = self._norm_ip(ip)
        if not ip:
            return None
        try:
            if plen and 8 <= int(plen) <= 32 and (sep == "/" or ip.endswith(".0")):
                a = addr_from_network(f"{ip}/{plen}")
            elif self.zero_as_24 and ip.endswith(".0"):
                a = addr_from_network(ip + "/24")
            else:
                a = addr_from_network(ip)
        except ValueError:
            return None
        self.inferred.add(t)
        return a


def _parse_enabled(value: str, mapping, header) -> bool:
    if not value:
        return True
    v = value.strip().lower()
    col = norm_header(header[mapping["enabled"]]) if "enabled" in mapping else ""
    if col == "disabled":  # 'Disabled' 열이면 의미가 반대
        return v not in _ENABLED_WORDS and v not in ("yes", "true", "y", "1")
    if v in _DISABLED_WORDS:
        return False
    return True


_NEG = re.compile(r"^(!|not\s+|negated?\s*[:：]?\s*)", re.I)


def _fill_match(r: Rule, g: dict, resolver: ObjectResolver, infer=None):
    neg = []
    for f in ("src", "dst", "svc"):
        vals = g[f]
        if vals and _NEG.match(vals[0]):
            neg.append(f)
            g[f] = [_NEG.sub("", vals[0])] + vals[1:]
    if neg:
        r.unanalyzable = "부정(negate) 조건: " + ", ".join(neg)

    r.src, miss1 = _resolve_addr(resolver, g["src"], infer)
    r.dst, miss2 = _resolve_addr(resolver, g["dst"], infer)
    r.svc, miss3 = resolver.resolve_svc(g["svc"], parse_literal=parse_service_literal)
    r.unresolved = miss1 + miss2 + miss3
    r.src_zone = TokenSet.of(g["src_zone"], ("any", "all", "전체"))
    r.dst_zone = TokenSet.of(g["dst_zone"], ("any", "all", "전체"))
    r.app = TokenSet.of(g["app"], ("any", "all", "전체"))
    r.users = TokenSet.of(g["users"], ("any", "all", "전체"))
    sch = g.get("schedule") or ""
    if sch and sch.lower() not in ("any", "always", "항상", "전체", ""):
        r.extra["schedule"] = TokenSet.of([sch])
    r.text = {k: ", ".join(g[k]) or "any" for k in ("src", "dst", "svc", "src_zone", "dst_zone", "app", "users")}


def _resolve_addr(resolver: ObjectResolver, values: list, infer):
    """객체 시트 → 리터럴 → 이름 속 IP 순으로 해석."""
    if infer is None:
        return resolver.resolve_addr(values)
    from ..sets import ANY_ADDR, AddrSet
    if not any(v.strip() for v in values):
        return ANY_ADDR, []
    result, missing = AddrSet(), []
    for v in values:
        if not v.strip():
            continue
        if v in resolver.addr or v in resolver.addr_groups:
            a, miss = resolver.resolve_addr([v])
            missing += miss
        else:
            a = infer.literal(v)
            if a is None:
                a, miss = resolver.resolve_addr([v], literal_fallback=False)
                missing += miss
        result = result.union(a)
        if result.any:
            break
    return result, missing
