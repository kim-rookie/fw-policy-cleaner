"""Juniper SRX (Junos) 설정 파서.

입력: `show configuration | display set` 출력 (set 형식).
zone 쌍(from-zone → to-zone) 정책은 쌍별로, global 정책은 따로 분석한다.
"""
from __future__ import annotations

import shlex

from ..model import ObjectResolver, PolicySet, Rule, normalize_action
from ..sets import (AddrSet, Intervals, SvcSet, TokenSet, addr_from_network, addr_from_range, svc_ports,
                    svc_proto, PORT_MAX)
from .tabular import decode_text

PREDEFINED = {
    "junos-http": svc_ports("tcp", 80), "junos-https": svc_ports("tcp", 443), "junos-ssh": svc_ports("tcp", 22),
    "junos-telnet": svc_ports("tcp", 23), "junos-ftp": svc_ports("tcp", 21), "junos-smtp": svc_ports("tcp", 25),
    "junos-dns-udp": svc_ports("udp", 53), "junos-dns-tcp": svc_ports("tcp", 53),
    "junos-ntp": svc_ports("udp", 123), "junos-ldap": svc_ports("tcp", 389), "junos-ms-sql": svc_ports("tcp", 1433),
    "junos-snmp-get": svc_ports("udp", 161), "junos-syslog": svc_ports("udp", 514),
    "junos-pop3": svc_ports("tcp", 110), "junos-imap": svc_ports("tcp", 143), "junos-imaps": svc_ports("tcp", 993),
    "junos-icmp-all": svc_proto("icmp"), "junos-icmp-ping": svc_proto("icmp"), "junos-ping": svc_proto("icmp"),
    "junos-icmp6-all": svc_proto("icmp6"), "junos-tftp": svc_ports("udp", 69), "junos-radius": svc_ports("udp", 1812),
    "junos-ike": svc_ports("udp", 500), "junos-bgp": svc_ports("tcp", 179), "junos-smb": svc_ports("tcp", 445),
    "junos-rdp": svc_ports("tcp", 3389), "junos-mysql": svc_ports("tcp", 3306),
}


def _ports(spec: str) -> Intervals:
    if spec in ("0-65535", "any"):
        return Intervals([(0, PORT_MAX)])
    if "-" in spec:
        a, b = spec.split("-", 1)
        return Intervals([(int(a), int(b))])
    from ..sets import port_number
    p = port_number(spec)
    return Intervals([(p, p)])


def parse(data: bytes, filename: str, vendor: str = "juniper_srx", options: dict | None = None) -> PolicySet:
    text = decode_text(data)
    policy = PolicySet(vendor="juniper_srx", rules=[], source_name=filename)
    res = ObjectResolver()
    apps: dict[str, dict] = {}            # name → {term: {protocol, dport, sport}}
    app_sets: dict[str, list[str]] = {}
    pol: dict[tuple, dict] = {}           # (ctx, name) → data  (dict 순서 = 정의 순서)
    deactivated: set[tuple] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith(("set ", "deactivate ")):
            continue
        try:
            t = shlex.split(line)
        except ValueError:
            t = line.split()
        verb, t = t[0], t[1:]
        # ----- 주소록
        ab = None
        if t[:2] == ["security", "address-book"] and len(t) > 3:
            ab = t[3:]
        elif t[:2] == ["security", "zones"] and "address-book" in t:
            ab = t[t.index("address-book") + 1:]
        if ab and verb == "set":
            try:
                if ab[0] == "address" and len(ab) >= 3:
                    name, rest = ab[1], ab[2:]
                    if rest[0] == "range-address":
                        res.addr[name] = addr_from_range(rest[1], rest[3])
                    elif rest[0] == "dns-name":
                        res.addr[name] = AddrSet(tokens=frozenset(["fqdn:" + rest[1]]))
                    elif rest[0] == "wildcard-address":
                        res.addr[name] = AddrSet(tokens=frozenset(["wildcard:" + rest[1]]))
                    elif rest[0] == "description":
                        pass
                    else:
                        res.addr[name] = addr_from_network(rest[0])
                elif ab[0] == "address-set" and len(ab) >= 4 and ab[2] in ("address", "address-set"):
                    res.addr_groups.setdefault(ab[1], []).append(ab[3])
            except (ValueError, IndexError):
                policy.warnings.append(f"주소 해석 실패: {line}")
            continue
        # ----- 애플리케이션
        if t[:2] == ["applications", "application"] and len(t) >= 5 and verb == "set":
            name = t[2]
            rest = t[3:]
            term = "_"
            if rest[0] == "term":
                term, rest = rest[1], rest[2:]
            d = apps.setdefault(name, {}).setdefault(term, {})
            if len(rest) >= 2:
                d[rest[0]] = rest[1]
            continue
        if t[:2] == ["applications", "application-set"] and len(t) >= 5 and verb == "set":
            app_sets.setdefault(t[2], []).append(t[4])
            continue
        # ----- 정책
        if t[:2] == ["security", "policies"]:
            if len(t) >= 7 and t[2] == "from-zone" and t[4] == "to-zone" and t[6] == "policy" and len(t) >= 8:
                ctx, name, rest = f"{t[3]} → {t[5]}", t[7], t[8:]
                fz, tz = t[3], t[5]
            elif len(t) >= 5 and t[2] == "global" and t[3] == "policy":
                ctx, name, rest = "global", t[4], t[5:]
                fz = tz = None
            else:
                continue
            key = (ctx, name)
            if verb == "deactivate":
                if not rest:
                    deactivated.add(key)
                continue
            d = pol.setdefault(key, {"src": [], "dst": [], "app": [], "dynapp": [], "users": [], "then": None,
                                     "fz": [fz] if fz else [], "tz": [tz] if tz else [], "excl": [],
                                     "desc": "", "sched": ""})
            if not rest:
                continue
            if rest[0] == "match" and len(rest) >= 3:
                k, v = rest[1], rest[2]
                if k == "source-address":
                    d["src"].append(v)
                elif k == "destination-address":
                    d["dst"].append(v)
                elif k == "application":
                    d["app"].append(v)
                elif k == "dynamic-application":
                    d["dynapp"].append(v)
                elif k in ("source-identity", "source-end-user-profile"):
                    d["users"].append(v)
                elif k in ("source-address-excluded", "destination-address-excluded"):
                    d["excl"].append(k)
                elif k == "from-zone":
                    d["fz"].append(v)
                elif k == "to-zone":
                    d["tz"].append(v)
            elif rest[0] == "then" and len(rest) >= 2:
                if rest[1] in ("permit", "deny", "reject"):
                    d["then"] = rest[1]
            elif rest[0] == "description" and len(rest) >= 2:
                d["desc"] = rest[1]
            elif rest[0] == "scheduler-name" and len(rest) >= 2:
                d["sched"] = rest[1]

    # 애플리케이션 → 서비스 집합
    for name, terms in apps.items():
        s = SvcSet.build()
        for term in terms.values():
            proto = term.get("protocol", "tcp")
            try:
                if proto in ("tcp", "udp", "sctp") and "destination-port" in term:
                    s = s.union(SvcSet.build({proto: _ports(term["destination-port"])}))
                else:
                    s = s.union(svc_proto(proto))
                if "source-port" in term and term["source-port"] not in ("0-65535", "any"):
                    s = s.union(SvcSet.build(tokens=["srcport:" + name]))
            except ValueError:
                s = s.union(SvcSet.build(tokens=[name]))
        res.svc[name] = s
    res.svc.update({k: v for k, v in PREDEFINED.items() if k not in res.svc})
    from ..sets import ANY_ADDR, V4_MAX, V6_MAX
    res.addr.setdefault("any", ANY_ADDR)
    res.addr.setdefault("any-ipv4", AddrSet(v4=Intervals([(0, V4_MAX)])))
    res.addr.setdefault("any-ipv6", AddrSet(v6=Intervals([(0, V6_MAX)])))
    res.svc_groups.update(app_sets)

    if not pol:
        raise ValueError("'set security policies' 정책을 찾지 못했습니다. `show configuration | display set` 형식인지 확인하세요.")
    seqs: dict[str, int] = {}
    for (ctx, name), d in pol.items():
        seq = seqs.get(ctx, 0)
        seqs[ctx] = seq + 1
        r = Rule(seq=seq, rid=name, name=name, scope=ctx, comment=d["desc"])
        r.action = normalize_action(d["then"] or "deny") or "deny"
        if d["then"] is None:
            policy.warnings.append(f"{ctx} / {name}: then 동작이 없어 deny 로 간주")
        r.enabled = (ctx, name) not in deactivated
        r.src, m1 = res.resolve_addr(d["src"], literal_fallback=False)
        r.dst, m2 = res.resolve_addr(d["dst"], literal_fallback=False)
        r.svc, m3 = res.resolve_svc(d["app"])
        r.unresolved = m1 + m2 + m3
        r.src_zone = TokenSet.of(d["fz"])
        r.dst_zone = TokenSet.of(d["tz"])
        r.users = TokenSet.of(d["users"])
        r.app = TokenSet.of(d["dynapp"]) if d["dynapp"] else TokenSet(any=True)
        if d["sched"]:
            r.extra["schedule"] = TokenSet.of([d["sched"]])
        if d["excl"]:
            r.unanalyzable = "제외(excluded) 조건: " + ", ".join(sorted(set(d["excl"])))
        r.text = {"src": ", ".join(d["src"]) or "any", "dst": ", ".join(d["dst"]) or "any",
                  "svc": ", ".join(d["app"]) or "any", "src_zone": ", ".join(d["fz"]) or "any",
                  "dst_zone": ", ".join(d["tz"]) or "any", "app": ", ".join(d["dynapp"]) or "any",
                  "users": ", ".join(d["users"]) or "any"}
        r.meta.update({"context": ctx, "from_zone": d["fz"], "to_zone": d["tz"]})
        policy.rules.append(r)
    return policy
