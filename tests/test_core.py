"""집합 연산과 분석 엔진 단위 테스트."""
from fwclean.analyzer import analyze
from fwclean.model import ALLOW, DENY, PolicySet, Rule
from fwclean.parsers.common import parse_service_literal as svc
from fwclean.sets import AddrSet, Intervals, try_parse_literal_addr as addr


def test_intervals():
    a = Intervals([(1, 5), (6, 10), (20, 30)])
    assert a.iv == ((1, 10), (20, 30))
    assert a.contains(Intervals([(2, 3), (25, 30)]))
    assert not a.contains(Intervals([(9, 21)]))
    assert a.intersects(Intervals([(15, 20)]))
    assert not a.intersects(Intervals([(11, 19)]))


def test_addr_literals():
    assert addr("10.0.0.0/8").contains(addr("10.1.2.3"))
    assert addr("10.0.0.0 255.255.255.0").contains(addr("10.0.0.0/25"))
    assert addr("10.0.0.1-10.0.0.9").contains(addr("10.0.0.5"))
    assert addr("10.0.0.1-9").contains(addr("10.0.0.9"))           # 축약형 범위
    assert addr("10.1.*.*").contains(addr("10.1.200.0/24"))         # 와일드카드
    assert addr("any").contains(addr("2001:db8::/32"))
    assert not addr("10.0.0.0/8").contains(addr("any"))
    assert addr("server.example.com") is None


def test_svc_literals():
    assert svc("tcp/80-90").contains(svc("tcp/85"))
    assert svc("80/tcp").contains(svc("tcp 80"))
    assert not svc("tcp/80").contains(svc("80"))   # 프로토콜 없는 포트 = tcp+udp
    assert svc("80").contains(svc("udp/80"))
    assert svc("tcp").contains(svc("tcp/65535"))
    assert svc("any").contains(svc("icmp"))
    assert not svc("icmp").contains(svc("tcp/1"))
    assert svc("TCP5000_6000").contains(svc("tcp/5500"))   # 웹 화면 export 의 범위 표기
    assert svc("TCP8443").contains(svc("tcp/8443"))


def R(seq, action, src, dst, service, enabled=True):
    r = Rule(seq=seq, rid=str(seq + 1), action=action, enabled=enabled)
    r.src, r.dst, r.svc = addr(src), addr(dst), svc(service)
    return r


def codes(rules):
    a = analyze(PolicySet("test", rules))
    return [sorted(f.code for f in a.findings[r.meta["uid"]] if f.category == "remove") for r in rules], a


def test_identical_pair_only_one_removed():
    c, a = codes([R(0, ALLOW, "10.0.0.0/24", "1.1.1.1", "tcp/80"),
                  R(1, ALLOW, "10.0.0.0/24", "1.1.1.1", "tcp/80")])
    assert c == [[], ["DUPLICATE"]]
    assert len(a.removed) == 1


def test_down_blocked_by_conflicting_rule():
    # 1번을 지우면 10.0.0.5 트래픽이 2번(deny)에 걸리므로 결과가 바뀜 → 삭제 불가
    c, _ = codes([R(0, ALLOW, "10.0.0.5", "1.1.1.1", "tcp/80"),
                  R(1, DENY, "10.0.0.0/24", "1.1.1.1", "tcp/80"),
                  R(2, ALLOW, "10.0.0.0/16", "1.1.1.1", "tcp/80")])
    assert c[0] == []


def test_down_not_blocked_by_disjoint_rule():
    c, _ = codes([R(0, ALLOW, "10.0.0.5", "1.1.1.1", "tcp/80"),
                  R(1, DENY, "10.9.0.0/24", "1.1.1.1", "tcp/80"),
                  R(2, ALLOW, "10.0.0.0/16", "1.1.1.1", "tcp/80")])
    assert c[0] == ["REDUNDANT_DOWN"]


def test_disabled_rule_ignored_for_coverage():
    c, _ = codes([R(0, ALLOW, "any", "any", "any", enabled=False),
                  R(1, ALLOW, "10.0.0.5", "1.1.1.1", "tcp/80")])
    assert c[1] == []


def test_token_rule_blocks_down_pass():
    # 2번은 FQDN(미해석 토큰) → 실제로 겹칠 수 있으므로 1번 삭제 불가로 판정해야 함
    fq = Rule(seq=1, rid="2", action=DENY)
    fq.src = addr("any")
    fq.dst = AddrSet(tokens=frozenset(["fqdn:x.example.com"]))
    fq.svc = svc("tcp/80")
    c, _ = codes([R(0, ALLOW, "10.0.0.5", "1.1.1.1", "tcp/80"), fq,
                  R(2, ALLOW, "10.0.0.0/16", "1.1.1.0/24", "tcp/80")])
    assert c[0] == []


def test_semantics_preserved_random():
    """무작위 정책에서 정리 전후 first-match 결과가 같은지 검증."""
    import random
    rnd = random.Random(7)
    nets = ["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "10.1.1.5", "10.2.0.0/16", "any"]
    svcs = ["tcp/80", "tcp/443", "tcp/1-1024", "any", "udp/53"]
    probes = [(s, d, p) for s in ["10.1.1.5", "10.1.2.9", "10.2.3.4", "192.0.2.1"]
              for d in ["10.1.1.5", "10.1.9.9", "172.16.0.1"]
              for p in ["tcp/80", "tcp/443", "tcp/2000", "udp/53"]]
    for _ in range(300):
        rules = [R(i, rnd.choice([ALLOW, DENY]), rnd.choice(nets), rnd.choice(nets), rnd.choice(svcs))
                 for i in range(rnd.randint(2, 9))]
        a = analyze(PolicySet("t", rules))
        kept = [r for r in rules if r.meta["uid"] not in a.removed]

        def first(rs, s, d, p):
            ps, pd, pp = addr(s), addr(d), svc(p)
            for r in rs:
                if r.src.contains(ps) and r.dst.contains(pd) and r.svc.contains(pp):
                    return r.action
            return "implicit-deny"
        for pr in probes:
            assert first(rules, *pr) == first(kept, *pr), [(r.rid, r.action, r.text) for r in rules]
