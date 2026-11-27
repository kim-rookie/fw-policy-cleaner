"""Juniper ScreenOS (NetScreen / SSG / ISG) 설정 파서.

입력: `get config` 출력 (또는 WebUI Configuration > Update > Config File 저장본).
웹 화면 정책 목록을 엑셀로 복사한 파일은 동작·사용여부가 빠지므로, 가능하면 이 형식을 쓰는 게 정확하다.

주소록은 zone 별이다. 정책의 출발지는 from-zone 주소록, 목적지는 to-zone 주소록에서 찾는다.
"""
from __future__ import annotations

import shlex

from ..model import ObjectResolver, PolicySet, Rule
from ..sets import ANY_ADDR, Intervals, SvcSet, TokenSet, addr_from_network, svc_proto
from .common import parse_service_literal
from .tabular import decode_text

PREDEF = {
    "TRACEROUTE": SvcSet.build(protos=["icmp"]).union(SvcSet.build({"udp": Intervals([(33400, 34000)])})),
    "SQL*Net V2": SvcSet.build({"tcp": Intervals([(1521, 1521)])}),
    "NBNAME": SvcSet.build({"udp": Intervals([(137, 137)])}),
    "NBDS": SvcSet.build({"udp": Intervals([(138, 138)])}),
    "MS-RPC-EPM": SvcSet.build({"tcp": Intervals([(135, 135)]), "udp": Intervals([(135, 135)])}),
    "ICMP-ANY": svc_proto("icmp"), "PING": svc_proto("icmp"),
}


def _ports(spec: str) -> Intervals:
    a, _, b = spec.partition("-")
    return Intervals([(int(a), int(b or a))])


def parse(data: bytes, filename: str, vendor: str = "screenos", options: dict | None = None) -> PolicySet:
    text = decode_text(data)
    policy = PolicySet(vendor="screenos", rules=[], source_name=filename)
    zone_res: dict[str, ObjectResolver] = {}
    services: dict[str, SvcSet] = {}
    svc_groups: dict[str, list[str]] = {}
    pols: dict[str, dict] = {}      # 정의 순서 = 평가 순서
    ctx = None                      # 'set policy id N' 하위 컨텍스트

    def zres(zone):
        return zone_res.setdefault(zone.lower(), ObjectResolver())

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            t = shlex.split(line)
        except ValueError:
            t = line.split()
        if t == ["exit"]:
            ctx = None
            continue
        if not t or t[0] != "set":
            continue
        t = t[1:]
        try:
            if ctx is not None and t and t[0] in ("src-address", "dst-address", "service"):
                key = {"src-address": "src", "dst-address": "dst", "service": "svc"}[t[0]]
                pols[ctx][key].append(t[1])
                continue
            if t[:1] == ["address"] and len(t) >= 4:
                zone, name, val = t[1], t[2], t[3]
                r = zres(zone)
                if len(t) >= 5 and "." in t[4] and t[4][0].isdigit():
                    r.addr[name] = addr_from_network(f"{val} {t[4]}")
                elif "/" in val or val.count(".") == 3 and val[0].isdigit() or ":" in val:
                    r.addr[name] = addr_from_network(val)
                else:
                    from ..sets import AddrSet
                    r.addr[name] = AddrSet(tokens=frozenset(["fqdn:" + val]))
            elif t[:2] == ["group", "address"] and len(t) >= 4:
                r = zres(t[2])
                r.addr_groups.setdefault(t[3], [])
                if len(t) >= 6 and t[4] == "add":
                    r.addr_groups[t[3]].append(t[5])
            elif t[:1] == ["service"] and len(t) >= 3:
                name = t[1]
                rest = t[2:]
                if rest[0] == "+":
                    rest = ["protocol"] + rest[1:]
                if rest[0] == "protocol" and len(rest) >= 2:
                    proto = rest[1].lower()
                    s = services.get(name, SvcSet.build())
                    if proto in ("tcp", "udp") and "dst-port" in rest:
                        s = s.union(SvcSet.build({proto: _ports(rest[rest.index("dst-port") + 1])}))
                        if "src-port" in rest and rest[rest.index("src-port") + 1] != "0-65535":
                            s = s.union(SvcSet.build(tokens=["srcport:" + name]))
                    else:
                        s = s.union(svc_proto(proto))
                    services[name] = s
            elif t[:2] == ["group", "service"] and len(t) >= 3:
                svc_groups.setdefault(t[2], [])
                if len(t) >= 5 and t[3] == "add":
                    svc_groups[t[2]].append(t[4])
            elif t[:2] == ["policy", "id"] and len(t) >= 3:
                pid = t[2]
                rest = t[3:]
                if not rest:
                    ctx = pid if pid in pols else None
                    continue
                if rest == ["disable"]:
                    if pid in pols:
                        pols[pid]["enabled"] = False
                    continue
                name = ""
                if rest[0] == "name":
                    name, rest = rest[1], rest[2:]
                if rest[:1] == ["from"] and len(rest) >= 7 and rest[2] == "to":
                    fz, tz, src, dst, svc = rest[1], rest[3], rest[4], rest[5], rest[6]
                    tail = [x.lower() for x in rest[7:]]
                    action = next((a for a in ("permit", "deny", "reject", "tunnel") if a in tail), "deny")
                    pols[pid] = {"name": name, "fz": fz, "tz": tz, "src": [src], "dst": [dst], "svc": [svc],
                                 "action": action, "enabled": True, "raw": line, "nat": "nat" in tail}
        except (IndexError, ValueError) as e:
            policy.warnings.append(f"해석 실패: {line[:100]} ({e})")

    if not pols:
        raise ValueError("'set policy id ... from ... to ...' 정책을 찾지 못했습니다. `get config` 출력인지 확인하세요.")

    svc_res = ObjectResolver()
    svc_res.svc = {**PREDEF, **services}
    svc_res.svc_groups = svc_groups
    seqs: dict[str, int] = {}
    for pid, d in pols.items():
        is_global = d["fz"].lower() == "global" and d["tz"].lower() == "global"
        scope = "Global" if is_global else f"{d['fz']} → {d['tz']}"
        seq = seqs.get(scope, 0)
        seqs[scope] = seq + 1
        r = Rule(seq=seq, rid=pid, name=d["name"], scope=scope, raw=d["raw"])
        r.action = "allow" if d["action"] in ("permit", "tunnel") else "deny"
        r.enabled = d["enabled"]
        r.src, m1 = _resolve(zone_res, d["fz"], d["src"])
        r.dst, m2 = _resolve(zone_res, d["tz"], d["dst"])
        r.svc, m3 = svc_res.resolve_svc(d["svc"], parse_literal=parse_service_literal)
        r.unresolved = m1 + m2 + m3
        r.src_zone = TokenSet.of([d["fz"]], ("global",))
        r.dst_zone = TokenSet.of([d["tz"]], ("global",))
        if d["action"] == "tunnel":
            r.extra["tunnel"] = TokenSet.of(["vpn-tunnel"])
        r.text = {"src": ", ".join(d["src"]), "dst": ", ".join(d["dst"]), "svc": ", ".join(d["svc"]),
                  "src_zone": d["fz"], "dst_zone": d["tz"], "app": "any", "users": "any"}
        r.meta.update({"from_zone": d["fz"], "to_zone": d["tz"]})
        policy.rules.append(r)
    return policy


def _resolve(zone_res, zone, names):
    if any(n.lower() == "any" for n in names):
        return ANY_ADDR, []
    res = zone_res.get(zone.lower()) or ObjectResolver()
    glob = zone_res.get("global")
    if glob and glob is not res:  # Global 주소록 객체도 참조 가능
        merged = ObjectResolver()
        merged.addr = {**glob.addr, **res.addr}
        merged.addr_groups = {**glob.addr_groups, **res.addr_groups}
        res = merged
    return res.resolve_addr(names)
