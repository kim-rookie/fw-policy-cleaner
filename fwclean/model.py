"""벤더 중립 정책 모델."""
from __future__ import annotations

from dataclasses import dataclass, field

from .sets import ANY_ADDR, ANY_SVC, ANY_TOKENS, AddrSet, SvcSet, TokenSet

ALLOW = "allow"
DENY = "deny"
UNKNOWN = "unknown"   # export 에 동작 정보가 없음

_ALLOW_WORDS = {"allow", "accept", "permit", "pass", "허용", "통과", "accept-log", "trust"}
_DENY_WORDS = {"deny", "drop", "reject", "block", "reset-client", "reset-server", "reset-both",
               "거부", "차단", "deny-log", "reset", "discard"}


def normalize_action(value: str) -> str | None:
    v = (value or "").strip().lower()
    if v in _ALLOW_WORDS:
        return ALLOW
    if v in _DENY_WORDS:
        return DENY
    for w in _ALLOW_WORDS:
        if v.startswith(w):
            return ALLOW
    for w in _DENY_WORDS:
        if v.startswith(w):
            return DENY
    return None


@dataclass
class Rule:
    seq: int                      # 평가 순서 (scope 안에서 0부터)
    rid: str                      # 장비상의 정책 ID 또는 이름
    name: str = ""
    scope: str = "default"        # 서로 비교 가능한 정책 묶음 (vsys, VDOM, ACL 이름, zone 쌍 등)
    action: str = ALLOW
    enabled: bool = True

    src_zone: TokenSet = ANY_TOKENS
    dst_zone: TokenSet = ANY_TOKENS
    src: AddrSet = ANY_ADDR
    dst: AddrSet = ANY_ADDR
    svc: SvcSet = ANY_SVC
    app: TokenSet = ANY_TOKENS
    users: TokenSet = ANY_TOKENS
    extra: dict = field(default_factory=dict)   # 기타 매칭 조건 이름 → TokenSet (schedule 등)

    hits: int | None = None       # hit count (export 에 있을 때만)
    comment: str = ""
    # 화면 표시용 원문
    text: dict = field(default_factory=dict)    # src/dst/svc/src_zone/dst_zone/app/users
    raw: str = ""                 # 원본 라인 (ASA 등 삭제 명령 생성에 필요)
    meta: dict = field(default_factory=dict)    # 벤더별 부가 정보 (컨텍스트, rulebase 등)
    unanalyzable: str = ""        # 비어 있지 않으면 포함 관계 분석에서 제외한 사유
    unresolved: list = field(default_factory=list)  # 해석 못 한 객체 이름

    # 비교 함수 --------------------------------------------------------------
    def _extra_dims(self, other: "Rule"):
        keys = set(self.extra) | set(other.extra)
        for k in keys:
            yield self.extra.get(k, ANY_TOKENS), other.extra.get(k, ANY_TOKENS)

    def covers(self, other: "Rule") -> bool:
        """self 의 매칭 범위가 other 를 완전히 포함하는가."""
        return (self.src_zone.contains(other.src_zone)
                and self.dst_zone.contains(other.dst_zone)
                and self.src.contains(other.src)
                and self.dst.contains(other.dst)
                and self.svc.contains(other.svc)
                and self.app.contains(other.app)
                and self.users.contains(other.users)
                and all(a.contains(b) for a, b in self._extra_dims(other)))

    def overlaps(self, other: "Rule") -> bool:
        return (self.src_zone.intersects(other.src_zone)
                and self.dst_zone.intersects(other.dst_zone)
                and self.src.intersects(other.src)
                and self.dst.intersects(other.dst)
                and self.svc.intersects(other.svc)
                and self.app.intersects(other.app)
                and self.users.intersects(other.users)
                and all(a.intersects(b) for a, b in self._extra_dims(other)))

    def same_match(self, other: "Rule") -> bool:
        return self.covers(other) and other.covers(self)

    @property
    def label(self) -> str:
        if self.name and self.name != self.rid:
            return f"{self.rid} ({self.name})"
        return self.rid


@dataclass
class PolicySet:
    vendor: str
    rules: list[Rule]
    source_name: str = ""
    warnings: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def scopes(self) -> dict[str, list[Rule]]:
        out: dict[str, list[Rule]] = {}
        for r in self.rules:
            out.setdefault(r.scope, []).append(r)
        for rules in out.values():
            rules.sort(key=lambda r: r.seq)
        return out


class ObjectResolver:
    """주소/서비스 객체와 그룹을 재귀적으로 해석. 파서들이 공통으로 사용."""

    def __init__(self):
        self.addr: dict[str, AddrSet] = {}
        self.addr_groups: dict[str, list[str]] = {}
        self.svc: dict[str, SvcSet] = {}
        self.svc_groups: dict[str, list[str]] = {}
        self.app_groups: dict[str, list[str]] = {}
        self.unresolved: set[str] = set()

    # 주소 -----------------------------------------------------------------
    def resolve_addr(self, names, literal_fallback=True, _stack=()) -> tuple[AddrSet, list[str]]:
        from .sets import try_parse_literal_addr
        result = AddrSet()
        missing: list[str] = []
        for n in names:
            n = n.strip()
            if not n:
                continue
            if n in self.addr:
                result = result.union(self.addr[n])
            elif n in self.addr_groups:
                if n in _stack:
                    missing.append(n)
                    continue
                sub, miss = self.resolve_addr(self.addr_groups[n], literal_fallback, _stack + (n,))
                result = result.union(sub)
                missing += miss
            else:
                lit = try_parse_literal_addr(n) if literal_fallback else None
                if lit is not None:
                    result = result.union(lit)
                else:
                    missing.append(n)
                    result = result.union(AddrSet(tokens=frozenset([n])))
            if result.any:
                break
        self.unresolved.update(missing)
        if not any(n.strip() for n in names):
            return ANY_ADDR, missing   # 값이 비어 있으면 any 로 본다
        return result, missing

    # 서비스 ---------------------------------------------------------------
    def resolve_svc(self, names, parse_literal=None, _stack=()) -> tuple[SvcSet, list[str]]:
        from .sets import svc_well_known
        result = SvcSet.build()
        missing: list[str] = []
        for n in names:
            n = n.strip()
            if not n:
                continue
            if n.lower() in ("any", "all", "*", "전체"):
                return ANY_SVC, missing
            if n in self.svc:
                result = result.union(self.svc[n])
            elif n in self.svc_groups:
                if n in _stack:
                    missing.append(n)
                    continue
                sub, miss = self.resolve_svc(self.svc_groups[n], parse_literal, _stack + (n,))
                result = result.union(sub)
                missing += miss
            else:
                lit = parse_literal(n) if parse_literal else None
                if lit is None:
                    lit = svc_well_known(n)
                if lit is not None:
                    result = result.union(lit)
                else:
                    missing.append(n)
                    result = result.union(SvcSet.build(tokens=[n]))
            if result.any:
                break
        self.unresolved.update(missing)
        if not any(n.strip() for n in names):
            return ANY_SVC, missing
        return result, missing

    def expand_apps(self, names, _stack=()) -> list[str]:
        out = []
        for n in names:
            if n in self.app_groups and n not in _stack:
                out += self.expand_apps(self.app_groups[n], _stack + (n,))
            else:
                out.append(n)
        return out
