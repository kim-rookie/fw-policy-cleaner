"""Palo Alto Networks (PAN-OS / Panorama) XML 설정 파서.

입력: `show config running` 결과 또는 Device > Setup > Operations > Export named configuration
      으로 받은 XML. Panorama 설정(device-group 의 pre/post-rulebase)도 지원한다.
"""
from __future__ import annotations

from defusedxml import ElementTree as ET

from ..model import ObjectResolver, PolicySet, Rule, normalize_action
from ..sets import AddrSet, Intervals, SvcSet, TokenSet, addr_from_network, addr_from_range, svc_ports

PREDEFINED_SVC = {
    "service-http": svc_ports("tcp", 80).union(svc_ports("tcp", 8080)),
    "service-https": svc_ports("tcp", 443),
}


def _members(el, tag):
    node = el.find(tag)
    if node is None:
        return []
    return [m.text.strip() for m in node.findall("member") if m.text]


def _parse_ports(spec: str) -> Intervals:
    items = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            items.append((int(a), int(b)))
        else:
            items.append((int(part), int(part)))
    return Intervals(items)


def _load_objects(container, resolver: ObjectResolver, warnings):
    if container is None:
        return
    for e in container.findall("./address/entry"):
        name = e.get("name")
        try:
            if e.find("ip-netmask") is not None:
                resolver.addr[name] = addr_from_network(e.findtext("ip-netmask"))
            elif e.find("ip-range") is not None:
                a, b = e.findtext("ip-range").split("-", 1)
                resolver.addr[name] = addr_from_range(a, b)
            elif e.find("fqdn") is not None:
                resolver.addr[name] = AddrSet(tokens=frozenset(["fqdn:" + e.findtext("fqdn").strip()]))
            else:
                resolver.addr[name] = AddrSet(tokens=frozenset([name]))
        except ValueError:
            warnings.append(f"주소 객체 '{name}' 해석 실패")
            resolver.addr[name] = AddrSet(tokens=frozenset([name]))
    for e in container.findall("./address-group/entry"):
        name = e.get("name")
        static = e.find("static")
        if static is not None:
            resolver.addr_groups[name] = [m.text for m in static.findall("member") if m.text]
        else:  # dynamic group → 실제 구성원을 알 수 없음
            resolver.addr[name] = AddrSet(tokens=frozenset(["dynamic:" + name]))
    for e in container.findall("./service/entry"):
        name = e.get("name")
        s = SvcSet.build()
        proto = e.find("protocol")
        ok = False
        if proto is not None:
            for p in ("tcp", "udp", "sctp"):
                node = proto.find(p)
                if node is not None and node.findtext("port"):
                    try:
                        s = s.union(SvcSet.build({p: _parse_ports(node.findtext("port"))}))
                        ok = True
                    except ValueError:
                        pass
                    if node.find("source-port") is not None:
                        # 출발지 포트 제한이 있는 서비스는 목적지 포트만으로 포함 판정하면 안 됨
                        s = s.union(SvcSet.build(tokens=["srcport:" + name]))
        resolver.svc[name] = s if ok else SvcSet.build(tokens=[name])
    for e in container.findall("./service-group/entry"):
        resolver.svc_groups[e.get("name")] = _members(e, "members")
    for e in container.findall("./application-group/entry"):
        resolver.app_groups[e.get("name")] = _members(e, "members")


def _rules_from(rulebase, scope, resolver, policy: PolicySet, start_seq, label):
    if rulebase is None:
        return start_seq
    seq = start_seq
    for e in rulebase.findall("./security/rules/entry"):
        name = e.get("name")
        r = Rule(seq=seq, rid=name, name=name, scope=scope)
        seq += 1
        act = normalize_action(e.findtext("action") or "allow")
        r.action = act or "allow"
        r.enabled = (e.findtext("disabled") or "no").strip().lower() != "yes"
        src_names, dst_names = _members(e, "source"), _members(e, "destination")
        svc_names = _members(e, "service")
        apps = _members(e, "application")
        r.src, m1 = resolver.resolve_addr(src_names)
        r.dst, m2 = resolver.resolve_addr(dst_names)
        svc_res = ObjectResolver()
        svc_res.svc = {**PREDEFINED_SVC, **resolver.svc}
        svc_res.svc_groups = resolver.svc_groups
        if [s.lower() for s in svc_names] == ["application-default"]:
            r.svc = SvcSet.build(tokens=["application-default"])
            m3 = []
        else:
            r.svc, m3 = svc_res.resolve_svc(svc_names)
        r.unresolved = m1 + m2 + m3
        r.src_zone = TokenSet.of(_members(e, "from"))
        r.dst_zone = TokenSet.of(_members(e, "to"))
        r.app = TokenSet.of(resolver.expand_apps(apps))
        r.users = TokenSet.of(_members(e, "source-user"))
        cat = _members(e, "category")
        if cat and cat != ["any"]:
            r.extra["category"] = TokenSet.of(cat)
        rtype = (e.findtext("rule-type") or "universal").strip()
        if rtype != "universal":
            r.extra["rule-type"] = TokenSet.of([rtype])
        sched = e.findtext("schedule")
        if sched:
            r.extra["schedule"] = TokenSet.of([sched])
        hip = _members(e, "source-hip") + _members(e, "hip-profiles")
        if hip and hip != ["any"]:
            r.extra["hip"] = TokenSet.of(hip)
        neg = [n for n in ("negate-source", "negate-destination") if (e.findtext(n) or "no") == "yes"]
        if neg:
            r.unanalyzable = "부정 조건: " + ", ".join(neg)
        r.comment = (e.findtext("description") or "").strip()
        r.text = {"src": ", ".join(src_names) or "any", "dst": ", ".join(dst_names) or "any",
                  "svc": ", ".join(svc_names) or "any", "src_zone": ", ".join(_members(e, "from")) or "any",
                  "dst_zone": ", ".join(_members(e, "to")) or "any", "app": ", ".join(apps) or "any",
                  "users": ", ".join(_members(e, "source-user")) or "any"}
        r.meta.update({"rulebase": label, "container": scope})
        policy.rules.append(r)
    return seq


def parse(data: bytes, filename: str, vendor: str = "paloalto", options: dict | None = None) -> PolicySet:
    root = ET.fromstring(data)
    if root.tag != "config":
        found = root.find(".//config")
        if found is None:
            raise ValueError("PAN-OS 설정 XML(<config>)이 아닙니다.")
        root = found
    policy = PolicySet(vendor="paloalto", rules=[], source_name=filename)
    shared = root.find("shared")
    base = ObjectResolver()
    _load_objects(shared, base, policy.warnings)

    def child_resolver(container):
        r = ObjectResolver()
        r.addr, r.addr_groups = dict(base.addr), dict(base.addr_groups)
        r.svc, r.svc_groups = dict(base.svc), dict(base.svc_groups)
        r.app_groups = dict(base.app_groups)
        _load_objects(container, r, policy.warnings)
        return r

    found_any = False
    for dev in root.findall("./devices/entry"):
        for vsys in dev.findall("./vsys/entry"):
            res = child_resolver(vsys)
            _rules_from(vsys.find("rulebase"), vsys.get("name"), res, policy, 0, "rulebase")
            found_any = True
        for dg in dev.findall("./device-group/entry"):
            res = child_resolver(dg)
            scope = "DG:" + dg.get("name")
            n = 0
            if shared is not None:
                n = _rules_from(shared.find("pre-rulebase"), scope, res, policy, n, "shared pre-rulebase")
            n = _rules_from(dg.find("pre-rulebase"), scope, res, policy, n, "pre-rulebase")
            n = _rules_from(dg.find("post-rulebase"), scope, res, policy, n, "post-rulebase")
            if shared is not None:
                _rules_from(shared.find("post-rulebase"), scope, res, policy, n, "shared post-rulebase")
            found_any = True
    if not found_any:
        raise ValueError("vsys 또는 device-group 정책을 찾지 못했습니다.")
    # Panorama 공유 정책이 여러 DG 에 복제되므로 중복 표시를 피하려고 경고만 남김
    if any(r.meta.get("rulebase", "").startswith("shared") for r in policy.rules):
        policy.warnings.append("Panorama 공유(shared) 정책은 각 device-group 마다 함께 비교했습니다.")
    return policy
