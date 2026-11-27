"""Cisco ASA / FTD(LINA) 설정 파서.

입력: `show running-config` 출력. `show access-list` 출력을 같은 파일 뒤에 붙여 넣으면
(hitcnt=N) 값을 읽어 미사용 정책(Hit 0) 판정에도 사용한다. `show access-list` 만 있어도 동작하지만
객체 정의가 없으므로 정확도가 떨어진다.
"""
from __future__ import annotations

import re

from ..model import ObjectResolver, PolicySet, Rule, normalize_action
from ..sets import (ANY_ADDR, PORT_MAX, AddrSet, Intervals, SvcSet, TokenSet, V4_MAX, V6_MAX, addr_from_network,
                    addr_from_range, port_number, svc_proto)
from .tabular import decode_text

_HIT = re.compile(r"\(hitcnt=(\d+)\)")
_LINE = re.compile(r"^access-list\s+(\S+)\s+line\s+(\d+)\s+(.*)$")
_TAIL = re.compile(r"\s*\(hitcnt=\d+\).*$")


class AsaObjects:
    def __init__(self):
        self.res = ObjectResolver()
        self.port_groups: dict[str, tuple[list[str], list]] = {}   # name → (protos, [Intervals])
        self.proto_groups: dict[str, list[str]] = {}
        self.names: dict[str, str] = {}                              # 'name' 명령 alias


def _port_op(tokens, i):
    """tokens[i] 에서 포트 연산자 해석. (Intervals, 소비한 토큰 수) 또는 (None, 0)."""
    if i >= len(tokens):
        return None, 0
    op = tokens[i]
    try:
        if op == "eq":
            p = port_number(tokens[i + 1])
            return Intervals([(p, p)]), 2
        if op == "lt":
            p = port_number(tokens[i + 1])
            return Intervals([(0, p - 1)]), 2
        if op == "gt":
            p = port_number(tokens[i + 1])
            return Intervals([(p + 1, PORT_MAX)]), 2
        if op == "neq":
            p = port_number(tokens[i + 1])
            return Intervals([(0, p - 1), (p + 1, PORT_MAX)]), 2
        if op == "range":
            return Intervals([(port_number(tokens[i + 1]), port_number(tokens[i + 2]))]), 3
    except (IndexError, ValueError):
        return None, 0
    return None, 0


def _proto_svc(proto: str, ports: Intervals | None) -> SvcSet:
    p = proto.lower()
    if p == "tcp-udp":
        return _proto_svc("tcp", ports).union(_proto_svc("udp", ports))
    if p in ("tcp", "udp", "sctp") and ports is not None:
        return SvcSet.build({p: ports})
    return svc_proto(p)


def _parse_objects(lines: list[str], obj: AsaObjects, warnings):
    res = obj.res
    cur = None   # (kind, name, extra)
    for raw in lines:
        if not raw.strip() or raw.startswith("!"):
            cur = None if not raw.startswith(" ") else cur
            continue
        if not raw.startswith(" "):
            t = raw.split()
            cur = None
            if t[0] == "name" and len(t) >= 3:
                obj.names[t[2]] = t[1]
                res.addr[t[2]] = addr_from_network(t[1])
            elif t[0] == "object" and len(t) >= 3:
                cur = ("obj-" + t[1], t[2], None)
                if t[1] == "service":
                    res.svc.setdefault(t[2], SvcSet.build(tokens=[t[2]]))
            elif t[0] == "object-group" and len(t) >= 3:
                kind = t[1]
                name = t[2]
                if kind == "network":
                    res.addr_groups.setdefault(name, [])
                elif kind == "service" and len(t) >= 4:
                    obj.port_groups[name] = (["tcp", "udp"] if t[3] == "tcp-udp" else [t[3]], [])
                    kind = "port"
                elif kind == "service":
                    res.svc_groups.setdefault(name, [])
                elif kind == "protocol":
                    obj.proto_groups[name] = []
                cur = ("grp-" + kind, name, None)
            continue
        # 들여쓴 하위 명령
        if cur is None:
            continue
        kind, name, _ = cur
        t = raw.split()
        try:
            if kind == "obj-network":
                if t[0] == "host":
                    res.addr[name] = addr_from_network(t[1])
                elif t[0] == "subnet":
                    res.addr[name] = addr_from_network(" ".join(t[1:3]) if len(t) > 2 else t[1])
                elif t[0] == "range":
                    res.addr[name] = addr_from_range(t[1], t[2])
                elif t[0] == "fqdn":
                    res.addr[name] = AddrSet(tokens=frozenset(["fqdn:" + t[-1]]))
            elif kind == "obj-service" and t[0] == "service":
                res.svc[name] = _service_spec(t[1:], name)
            elif kind == "grp-network":
                if t[0] == "network-object":
                    if t[1] == "host":
                        key = f"__lit_{name}_{len(res.addr_groups[name])}"
                        res.addr[key] = addr_from_network(obj.names.get(t[2], t[2]))
                        res.addr_groups[name].append(key)
                    elif t[1] == "object":
                        res.addr_groups[name].append(t[2])
                    else:
                        key = f"__lit_{name}_{len(res.addr_groups[name])}"
                        res.addr[key] = addr_from_network(obj.names.get(t[1], t[1]) + (" " + t[2] if len(t) > 2 else ""))
                        res.addr_groups[name].append(key)
                elif t[0] == "group-object":
                    res.addr_groups[name].append(t[1])
            elif kind == "grp-port":
                protos, ivs = obj.port_groups[name]
                if t[0] == "port-object":
                    iv, _n = _port_op(t, 1)
                    if iv is not None:
                        ivs.append(iv)
                elif t[0] == "group-object" and t[1] in obj.port_groups:
                    ivs.extend(obj.port_groups[t[1]][1])
            elif kind == "grp-service":
                if t[0] == "service-object":
                    if t[1] == "object":
                        res.svc_groups[name].append(t[2])
                    else:
                        key = f"__svc_{name}_{len(res.svc_groups[name])}"
                        res.svc[key] = _service_spec(t[1:], key)
                        res.svc_groups[name].append(key)
                elif t[0] == "group-object":
                    res.svc_groups[name].append(t[1])
            elif kind == "grp-protocol" and t[0] == "protocol-object":
                obj.proto_groups[name].append(t[1])
        except (IndexError, ValueError) as e:
            warnings.append(f"객체 '{name}' 해석 실패: {raw.strip()} ({e})")


def _service_spec(t: list[str], name: str) -> SvcSet:
    """'tcp destination eq 80', 'tcp eq 80', 'tcp source range 1 2 destination eq 80', 'icmp', 'ip'."""
    proto = t[0]
    dst = None
    src_limited = False
    i = 1
    while i < len(t):
        if t[i] == "source":
            iv, n = _port_op(t, i + 1)
            src_limited = src_limited or iv is not None
            i += 1 + n
        elif t[i] == "destination":
            iv, n = _port_op(t, i + 1)
            dst = iv
            i += 1 + n
        else:
            iv, n = _port_op(t, i)
            if iv is not None:
                dst = iv
                i += n
            else:
                i += 1
    s = _proto_svc(proto, dst)
    if src_limited:
        s = s.union(SvcSet.build(tokens=["srcport:" + name]))
    return s


def _addr(tokens, i, obj: AsaObjects):
    """주소 지정 해석 → (AddrSet, 소비 토큰 수, 표시 문자열, 미해석 목록)."""
    t = tokens[i]
    if t in ("any",):
        return ANY_ADDR, 1, "any", []
    if t == "any4":
        return AddrSet(v4=Intervals([(0, V4_MAX)])), 1, "any4", []
    if t == "any6":
        return AddrSet(v6=Intervals([(0, V6_MAX)])), 1, "any6", []
    if t == "host":
        v = tokens[i + 1]
        ip = obj.names.get(v, v)
        return addr_from_network(ip), 2, v, []
    if t in ("object", "object-group"):
        name = tokens[i + 1]
        a, miss = obj.res.resolve_addr([name], literal_fallback=False)
        return a, 2, name, miss
    if t == "interface":
        return AddrSet(tokens=frozenset(["interface:" + tokens[i + 1]])), 2, "interface " + tokens[i + 1], []
    # IP MASK 또는 IPv6/len 또는 name alias
    v = obj.names.get(t, t)
    if "/" in v:
        return addr_from_network(v), 1, t, []
    return addr_from_network(f"{v} {tokens[i + 1]}"), 2, f"{t} {tokens[i + 1]}", []


def _parse_ace(acl: str, body: str, obj: AsaObjects):
    """'extended permit tcp ...' 부분 해석. 반환 dict 또는 None(대상 아님)."""
    t = body.split()
    if not t or t[0] != "extended":
        return None
    out = {"action": t[1], "inactive": "inactive" in t, "time_range": None, "users": []}
    if "time-range" in t:
        out["time_range"] = t[t.index("time-range") + 1]
    i = 2
    # 사용자 조건 (Identity firewall)
    while i < len(t) and t[i] in ("user", "user-group", "object-group-user"):
        out["users"].append(t[i + 1])
        i += 2
    proto_kind = t[i]
    if proto_kind in ("object", "object-group"):
        pname = t[i + 1]
        i += 2
        if pname in obj.proto_groups:
            protos = obj.proto_groups[pname]
            svc_base = None
        else:
            protos = None
            svc_base, miss = obj.res.resolve_svc([pname])
            out.setdefault("miss", []).extend(miss)
        out["proto_text"] = pname
    else:
        protos = [proto_kind]
        svc_base = None
        out["proto_text"] = proto_kind
        i += 1
    if i < len(t) and t[i] in ("security-group", "object-group-security"):
        out["unanalyzable"] = "SGT(security-group) 조건"
        return out
    src, n, stext, m1 = _addr(t, i, obj)
    i += n
    src_ports = None
    iv, n = _port_op(t, i)
    if iv is not None:
        src_ports = iv
        i += n
    elif i + 1 < len(t) and t[i] == "object-group" and t[i + 1] in obj.port_groups:
        src_ports = Intervals([x for v in obj.port_groups[t[i + 1]][1] for x in v.iv])
        i += 2
    dst, n, dtext, m2 = _addr(t, i, obj)
    i += n
    dst_ports = None
    ptext = ""
    iv, n = _port_op(t, i)
    if iv is not None:
        dst_ports = iv
        ptext = " ".join(t[i:i + n])
        i += n
    elif i + 1 < len(t) and t[i] == "object-group" and t[i + 1] in obj.port_groups:
        dst_ports = Intervals([x for v in obj.port_groups[t[i + 1]][1] for x in v.iv])
        ptext = t[i + 1]
        i += 2
    if svc_base is not None:
        svc = svc_base
    else:
        svc = SvcSet.build()
        for p in protos:
            svc = svc.union(_proto_svc(p, dst_ports))
    out.update({"src": src, "dst": dst, "svc": svc, "src_ports": src_ports, "src_text": stext, "dst_text": dtext,
                "svc_text": (out["proto_text"] + (" " + ptext if ptext else "")).strip(),
                "miss": out.get("miss", []) + m1 + m2})
    return out


def parse(data: bytes, filename: str, vendor: str = "cisco_asa", options: dict | None = None) -> PolicySet:
    text = decode_text(data)
    lines = [ln.rstrip() for ln in text.splitlines()]
    policy = PolicySet(vendor="cisco_asa", rules=[], source_name=filename)
    obj = AsaObjects()
    _parse_objects(lines, obj, policy.warnings)

    # show access-list 형식의 hitcnt 수집 (들여쓴 확장 라인은 상위 line 번호에 합산)
    hits: dict[tuple[str, int], int] = {}
    showacl_rules: dict[str, list[tuple[int, str]]] = {}
    for raw in lines:
        s = raw.strip()
        m = _LINE.match(s)
        if not m:
            continue
        acl, ln, body = m.group(1), int(m.group(2)), m.group(3)
        h = _HIT.search(s)
        if h:
            if raw.startswith(" "):
                hits[(acl, ln)] = hits.get((acl, ln), 0) + int(h.group(1))
            else:
                hits.setdefault((acl, ln), int(h.group(1)))
        if not raw.startswith(" "):
            showacl_rules.setdefault(acl, []).append((ln, _TAIL.sub("", body)))

    # running-config 형식의 ACL (line 번호 없음 → remark 포함 순서대로 번호 부여)
    run_rules: dict[str, list[tuple[int, str, str]]] = {}
    counters: dict[str, int] = {}
    for raw in lines:
        if raw.startswith(" "):
            continue
        t = raw.split()
        if len(t) < 3 or t[0] != "access-list" or t[2] == "line" or t[1].endswith(";"):
            continue
        acl = t[1]
        counters[acl] = counters.get(acl, 0) + 1
        body = raw.split(None, 2)[2]
        run_rules.setdefault(acl, []).append((counters[acl], body, raw.strip()))

    bindings: dict[str, str] = {}
    for raw in lines:
        t = raw.split()
        if len(t) >= 3 and t[0] == "access-group":
            bindings[t[1]] = " ".join(t[2:])

    acls: dict[str, list[tuple[int, str, str]]] = dict(run_rules)
    for acl, items in showacl_rules.items():
        if acl not in acls:
            acls[acl] = [(ln, body, f"access-list {acl} {body}") for ln, body in items]
    if not acls:
        raise ValueError("access-list 를 찾지 못했습니다.")

    for acl, items in acls.items():
        scope = acl + (f" ({bindings[acl]})" if acl in bindings else "")
        seq = 0
        for ln, body, raw in items:
            try:
                ace = _parse_ace(acl, body, obj)
            except (IndexError, ValueError) as e:
                policy.warnings.append(f"{acl} line {ln} 해석 실패: {body} ({e})")
                continue
            if ace is None:
                continue
            r = Rule(seq=seq, rid=f"{acl}:{ln}", name="", scope=scope, raw=raw)
            seq += 1
            r.action = normalize_action(ace["action"]) or "deny"
            r.enabled = not ace["inactive"]
            if ace.get("unanalyzable"):
                r.unanalyzable = ace["unanalyzable"]
                r.text = {"src": body, "dst": "", "svc": ""}
                policy.rules.append(r)
                continue
            r.src, r.dst, r.svc = ace["src"], ace["dst"], ace["svc"]
            if ace["src_ports"] is not None:
                r.extra["srcport"] = TokenSet.of([str(ace["src_ports"].iv)])
            if ace["time_range"]:
                r.extra["schedule"] = TokenSet.of([ace["time_range"]])
            if ace["users"]:
                r.users = TokenSet.of(ace["users"])
            r.unresolved = ace["miss"]
            r.hits = hits.get((acl, ln))
            r.text = {"src": ace["src_text"], "dst": ace["dst_text"], "svc": ace["svc_text"],
                      "src_zone": "any", "dst_zone": "any", "app": "any",
                      "users": ", ".join(ace["users"]) or "any"}
            r.meta.update({"acl": acl, "line": ln, "binding": bindings.get(acl, "")})
            policy.rules.append(r)
    unbound = [a for a in acls if a not in bindings]
    if bindings and unbound:
        policy.warnings.append(f"access-group 에 연결되지 않은 ACL: {', '.join(unbound[:10])} "
                               "(NAT/VPN/캡처 용도일 수 있으니 확인하세요)")
    return policy

