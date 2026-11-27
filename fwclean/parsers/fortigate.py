"""Fortinet FortiGate (FortiOS) 설정 백업 파서.

입력: System > Configuration > Backup 으로 받은 .conf 또는 `show full-configuration` / `show` 출력.
멀티 VDOM 설정이면 VDOM 별로 따로 분석한다.
"""
from __future__ import annotations

import shlex

from ..model import ObjectResolver, PolicySet, Rule, normalize_action
from ..sets import (ANY_ADDR, V4_MAX, AddrSet, Intervals, SvcSet, TokenSet, addr_from_network,
                    addr_from_range, svc_proto)
from .tabular import decode_text


class Node:
    __slots__ = ("sets", "configs", "entries")

    def __init__(self):
        self.sets: dict[str, list[str]] = {}
        self.configs: dict[str, "Node"] = {}
        self.entries: dict[str, "Node"] = {}   # 순서 유지 (dict)


def parse_tree(text: str) -> Node:
    root = Node()
    stack = [root]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tok = shlex.split(line, posix=True)
        except ValueError:
            tok = line.split()
        if not tok:
            continue
        kw = tok[0]
        cur = stack[-1]
        if kw == "config":
            path = " ".join(tok[1:])
            node = cur.configs.get(path)
            if node is None:
                node = cur.configs[path] = Node()
            stack.append(node)
        elif kw == "edit":
            name = " ".join(tok[1:])
            node = cur.entries.get(name)
            if node is None:
                node = cur.entries[name] = Node()
            stack.append(node)
        elif kw in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif kw == "set" and len(tok) >= 2:
            cur.sets[tok[1]] = tok[2:]
        elif kw == "unset" and len(tok) >= 2:
            cur.sets.pop(tok[1], None)
    return root


def _first(node: Node, key, default=""):
    v = node.sets.get(key)
    return v[0] if v else default


def _portrange(spec: list[str]) -> Intervals:
    items = []
    for part in spec:
        dst = part.split(":", 1)[0]
        if "-" in dst:
            a, b = dst.split("-", 1)
            items.append((int(a), int(b)))
        elif dst:
            items.append((int(dst), int(dst)))
    return Intervals(items)


def _load_objects(scope: Node, res: ObjectResolver, warnings: list[str]):
    for cfg in ("firewall address", "firewall address6"):
        node = scope.configs.get(cfg)
        if not node:
            continue
        for name, e in node.entries.items():
            typ = _first(e, "type", "ipmask")
            try:
                if typ in ("ipmask", "ipprefix"):
                    if "ip6" in e.sets:
                        a = addr_from_network(_first(e, "ip6"))
                    else:
                        sub = e.sets.get("subnet", ["0.0.0.0", "0.0.0.0"])
                        a = addr_from_network(" ".join(sub[:2]) if len(sub) > 1 else sub[0])
                    if a.v4.iv == ((0, V4_MAX),) and not a.v6:
                        a = ANY_ADDR
                    elif a.v6.iv == ((0, (1 << 128) - 1),) and not a.v4:
                        a = ANY_ADDR
                elif typ == "iprange":
                    a = addr_from_range(_first(e, "start-ip"), _first(e, "end-ip"))
                elif typ == "fqdn":
                    a = AddrSet(tokens=frozenset(["fqdn:" + _first(e, "fqdn")]))
                else:  # geography, wildcard, dynamic, interface-subnet, mac ...
                    a = AddrSet(tokens=frozenset([f"{typ}:{name}"]))
            except ValueError:
                warnings.append(f"주소 객체 '{name}' 해석 실패")
                a = AddrSet(tokens=frozenset([name]))
            res.addr[name] = a
    for cfg in ("firewall addrgrp", "firewall addrgrp6"):
        node = scope.configs.get(cfg)
        if not node:
            continue
        for name, e in node.entries.items():
            if _first(e, "exclude") == "enable":
                res.addr[name] = AddrSet(tokens=frozenset(["exclude-group:" + name]))
            else:
                res.addr_groups[name] = e.sets.get("member", [])
    node = scope.configs.get("firewall service custom")
    if node:
        for name, e in node.entries.items():
            proto = _first(e, "protocol", "TCP/UDP/SCTP").upper()
            s = SvcSet.build()
            try:
                if proto in ("TCP/UDP/SCTP", "TCP/UDP/UDP-LITE/SCTP"):
                    pm = {}
                    for key, p in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"), ("sctp-portrange", "sctp")):
                        if key in e.sets:
                            pm[p] = _portrange(e.sets[key])
                    s = SvcSet.build(pm)
                    if any(":" in x for k in ("tcp-portrange", "udp-portrange", "sctp-portrange")
                           for x in e.sets.get(k, [])):
                        s = s.union(SvcSet.build(tokens=["srcport:" + name]))
                elif proto in ("ICMP", "ICMP6"):
                    s = svc_proto("icmp" if proto == "ICMP" else "icmp6")
                    if "icmptype" in e.sets:
                        s = SvcSet.build(protos=[f"{proto.lower()}:type{_first(e, 'icmptype')}"])
                elif proto == "IP":
                    num = _first(e, "protocol-number", "0")
                    s = SvcSet(any=True) if num == "0" else svc_proto(num)
                else:
                    s = SvcSet.build(tokens=[name])
                if _first(e, "iprange") not in ("", "0.0.0.0") or _first(e, "fqdn"):
                    s = s.union(SvcSet.build(tokens=["svc-addr:" + name]))
            except ValueError:
                warnings.append(f"서비스 객체 '{name}' 해석 실패")
                s = SvcSet.build(tokens=[name])
            res.svc[name] = s if not s.is_empty() else SvcSet.build(tokens=[name])
    node = scope.configs.get("firewall service group")
    if node:
        for name, e in node.entries.items():
            res.svc_groups[name] = e.sets.get("member", [])


def _policies(scope_name: str, scope: Node, policy: PolicySet):
    res = ObjectResolver()
    _load_objects(scope, res, policy.warnings)
    res.svc.setdefault("ALL", SvcSet(any=True))
    res.addr.setdefault("all", ANY_ADDR)
    res.addr.setdefault("none", AddrSet())
    node = scope.configs.get("firewall policy")
    if not node:
        return
    for seq, (pid, e) in enumerate(node.entries.items()):
        name = _first(e, "name")
        r = Rule(seq=seq, rid=pid, name=name, scope=scope_name)
        r.action = normalize_action(_first(e, "action", "deny")) or "deny"
        r.enabled = _first(e, "status", "enable") != "disable"
        src_names = e.sets.get("srcaddr", []) + e.sets.get("srcaddr6", [])
        dst_names = e.sets.get("dstaddr", []) + e.sets.get("dstaddr6", [])
        svc_names = e.sets.get("service", [])
        r.src, m1 = res.resolve_addr(src_names, literal_fallback=False)
        if _first(e, "internet-service") == "enable":
            isdb = e.sets.get("internet-service-name", []) + e.sets.get("internet-service-id", [])
            r.dst = AddrSet(tokens=frozenset("isdb:" + x for x in isdb) or frozenset(["isdb"]))
            r.svc = SvcSet.build(tokens=["isdb-service"])
            m2, m3 = [], []
            dst_text = "ISDB: " + ", ".join(isdb)
        else:
            r.dst, m2 = res.resolve_addr(dst_names, literal_fallback=False)
            r.svc, m3 = res.resolve_svc(svc_names)
            dst_text = ", ".join(dst_names)
        r.unresolved = m1 + m2 + m3
        r.src_zone = TokenSet.of(e.sets.get("srcintf", []))
        r.dst_zone = TokenSet.of(e.sets.get("dstintf", []))
        users = e.sets.get("users", []) + e.sets.get("groups", [])
        r.users = TokenSet.of(users)
        sched = _first(e, "schedule", "always")
        if sched != "always":
            r.extra["schedule"] = TokenSet.of([sched])
        neg = [k for k in ("srcaddr-negate", "dstaddr-negate", "service-negate") if _first(e, k) == "enable"]
        if neg:
            r.unanalyzable = "부정 조건: " + ", ".join(neg)
        r.comment = _first(e, "comments")
        r.text = {"src": ", ".join(src_names), "dst": dst_text, "svc": ", ".join(svc_names) or "any",
                  "src_zone": ", ".join(e.sets.get("srcintf", [])) or "any",
                  "dst_zone": ", ".join(e.sets.get("dstintf", [])) or "any", "app": "any",
                  "users": ", ".join(users) or "any"}
        r.meta["vdom"] = scope_name
        policy.rules.append(r)


def parse(data: bytes, filename: str, vendor: str = "fortigate", options: dict | None = None) -> PolicySet:
    text = decode_text(data)
    root = parse_tree(text)
    policy = PolicySet(vendor="fortigate", rules=[], source_name=filename)
    vdoms = root.configs.get("vdom")
    if vdoms and any("firewall policy" in v.configs for v in vdoms.entries.values()):
        for name, v in vdoms.entries.items():
            _policies(name, v, policy)
    else:
        _policies("root", root, policy)
    if not policy.rules:
        raise ValueError("'config firewall policy' 섹션을 찾지 못했습니다.")
    return policy

