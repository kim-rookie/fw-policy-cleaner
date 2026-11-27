"""정책 정리 분석 엔진.

방화벽은 위에서부터 처음 매칭되는 정책을 적용한다(first match). 이 전제를 두고,
"지워도 어떤 트래픽의 처리 결과도 바뀌지 않는 정책"만 삭제 권고로 판정한다.

판정 순서
  1단계(위→아래) : 위쪽 정책 하나가 아래 정책을 완전히 포함하면, 아래 정책은 절대 매칭되지 않는다.
                    - 동작 같음 + 조건 동일 → DUPLICATE (완전 중복)
                    - 동작 같음            → REDUNDANT (상위 정책에 포함)
                    - 동작 다름            → SHADOWED (상위 정책에 가려짐, 의도 확인 필요)
  2단계(아래→위) : 정책 A 를 아래쪽 정책 B(동작 같음)가 포함하고, 그 사이에 A 와 겹치는
                    반대 동작 정책이 없으면 A 를 지워도 결과가 같다 → REDUNDANT_DOWN
  두 단계 모두 "남아 있는 정책"만 근거로 삼기 때문에, 서로를 근거로 둘 다 지우는 일은 없다.

그 외 참고 판정: 비활성(DISABLED), 미사용(UNUSED, hit 0), Any 과허용(ANY),
부분 중첩 충돌(CONFLICT), 통합 후보(MERGE), 객체 미해석(UNRESOLVED).
"""
from __future__ import annotations

import time
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field

from .model import ALLOW, UNKNOWN, PolicySet, Rule

# 판정 코드 정의: (한글 이름, 분류, 심각도, 설명)
#   분류 remove  = 삭제 권고 (트래픽 결과 불변이 보장됨)
#        candidate = 삭제 후보 (운영 확인 필요)
#        review  = 검토 (보안상 위험 또는 정리 대상)
#        info    = 참고
CODES = {
    "DUPLICATE": ("완전 중복", "remove", "high",
                  "위쪽에 조건과 동작이 완전히 같은 정책이 있어 이 정책은 매칭되지 않습니다."),
    "REDUNDANT": ("상위 정책에 포함", "remove", "high",
                  "위쪽 정책이 이 정책의 범위를 모두 포함하고 동작도 같아 이 정책은 매칭되지 않습니다."),
    "DEAD": ("상위 정책에 포함 (동작 미확인)", "remove", "high",
             "위쪽 정책이 이 정책의 범위를 모두 포함해 이 정책은 매칭되지 않습니다. 동작 정보가 없어 "
             "중복인지 가려짐인지는 구분하지 못했습니다. 근거 정책이 활성 상태인지 확인하세요."),
    "SHADOWED": ("상위 정책에 가려짐", "remove", "critical",
                 "위쪽의 반대 동작 정책이 범위를 모두 포함해 이 정책은 절대 적용되지 않습니다. "
                 "의도한 동작과 실제 동작이 다를 수 있으니 확인 후 삭제하세요."),
    "REDUNDANT_DOWN": ("하위 정책에 포함", "remove", "medium",
                       "아래쪽의 같은 동작 정책이 범위를 모두 포함하고, 그 사이에 충돌하는 정책이 없어 "
                       "삭제해도 결과가 같습니다."),
    "DISABLED": ("비활성 정책", "candidate", "low", "비활성화된 정책입니다. 장기 미사용이면 삭제를 검토하세요."),
    "UNUSED": ("미사용 정책 (Hit 0)", "candidate", "medium",
               "export 에 포함된 Hit count 가 0 입니다. 집계 기간을 확인한 뒤 삭제를 검토하세요."),
    "ANY": ("Any 과허용", "review", "high", "허용 정책의 출발지·목적지·서비스 중 any 가 포함되어 있습니다."),
    "CONFLICT": ("부분 중첩 충돌", "review", "medium",
                 "위쪽의 반대 동작 정책과 범위가 일부 겹칩니다. 정책 순서에 따라 결과가 달라집니다."),
    "PARTIAL": ("부분 중복", "info", "low",
                "위쪽의 같은 동작 정책과 일부 조건(출발지·목적지·서비스 조합)이 겹칩니다. "
                "정책 전체를 지울 수는 없지만 겹치는 객체를 한쪽에서 빼서 정리할 수 있습니다."),
    "MERGE": ("통합 후보", "info", "low", "조건 하나만 다르고 나머지가 같은 정책들입니다. 하나로 합칠 수 있습니다."),
    "UNRESOLVED": ("객체 미해석", "info", "low",
                   "정의를 찾지 못한 객체가 있어 이름 비교로만 판정했습니다 (보수적으로 판정)."),
    "UNANALYZABLE": ("분석 제외", "info", "low", "포함 관계를 계산할 수 없는 조건이 있어 분석에서 제외했습니다."),
}

STATUS_ORDER = ["remove", "candidate", "review", "info", "keep"]
STATUS_LABEL = {"remove": "삭제 권고", "candidate": "삭제 후보", "review": "검토 필요", "info": "참고", "keep": "유지"}

MAX_REFS = 20


@dataclass
class Finding:
    code: str
    refs: list[int] = field(default_factory=list)   # 관련 정책 uid
    detail: str = ""

    @property
    def category(self):
        return CODES[self.code][1]


@dataclass
class Options:
    include_disabled: bool = True    # 정리본에서 비활성 정책도 제외
    include_unused: bool = False     # 정리본에서 hit 0 정책도 제외
    detect_down: bool = True         # 2단계(하위 정책 포함) 판정 수행
    detect_merge: bool = True


@dataclass
class Analysis:
    policy: PolicySet
    findings: dict[int, list[Finding]]
    removed: set[int]                # 정리본에서 빠지는 uid
    elapsed: float
    options: Options
    merge_groups: list[list[int]] = field(default_factory=list)

    def status(self, uid: int) -> str:
        cats = {f.category for f in self.findings.get(uid, [])}
        for s in STATUS_ORDER[:-1]:
            if s in cats:
                return s
        return "keep"


# --------------------------------------------------------------------------- 보조 함수

def _addr_has_tokens(a):
    return not a.any and bool(a.tokens)


def _may_overlap(a: Rule, b: Rule) -> bool:
    """겹칠 '가능성'이 있는가. 미해석 토큰(FQDN 등)이 있으면 겹칠 수 있다고 본다 (보수적)."""
    if a.unanalyzable or b.unanalyzable:
        return True
    if a.overlaps(b):
        return True
    # 토큰이 포함된 차원은 실제로 겹칠 수 있음 → 나머지 차원이 겹치면 겹친다고 가정
    def dim(x, y, has_tok):
        return x.intersects(y) or has_tok
    return (a.src_zone.intersects(b.src_zone) and a.dst_zone.intersects(b.dst_zone)
            and dim(a.src, b.src, _addr_has_tokens(a.src) or _addr_has_tokens(b.src))
            and dim(a.dst, b.dst, _addr_has_tokens(a.dst) or _addr_has_tokens(b.dst))
            and dim(a.svc, b.svc, bool(a.svc.tokens or b.svc.tokens))
            and a.app.intersects(b.app) and a.users.intersects(b.users))


def _catch_all(r: Rule) -> bool:
    """모든 트래픽에 매칭되는 정책 (맨 아래 Cleanup 정책 등)."""
    return r.src.any and r.dst.any and r.svc.any and r.app.any and r.users.any and not r.extra


def _bbox(a):
    """빠른 사전 필터용 IPv4 범위. any → (0, max), 계산 불가 → None."""
    if a.any:
        return (0, (1 << 32) - 1)
    if a.v6 or a.tokens:
        return None
    return a.v4.bounds()


def _bcover(A, B):
    if A is None or B is None:
        return True  # 판단 불가 → 상세 비교로 넘김
    return A[0] <= B[0] and A[1] >= B[1]


def _boverlap(A, B):
    if A is None or B is None:
        return True
    return A[0] <= B[1] and B[0] <= A[1]


# --------------------------------------------------------------------------- 본체

def analyze(policy: PolicySet, options: Options | None = None) -> Analysis:
    opt = options or Options()
    t0 = time.perf_counter()
    rules = policy.rules
    for i, r in enumerate(rules):
        r.meta["uid"] = i
    findings: dict[int, list[Finding]] = {i: [] for i in range(len(rules))}

    def add(uid, code, refs=(), detail=""):
        findings[uid].append(Finding(code, list(refs)[:MAX_REFS], detail))

    # 개별 판정 ---------------------------------------------------------------
    for r in rules:
        u = r.meta["uid"]
        if not r.enabled:
            add(u, "DISABLED")
        if r.hits is not None and r.hits == 0 and r.enabled:
            add(u, "UNUSED")
        if r.unanalyzable:
            add(u, "UNANALYZABLE", detail=r.unanalyzable)
        if r.unresolved:
            add(u, "UNRESOLVED", detail=", ".join(sorted(set(r.unresolved))[:10]))
        if r.enabled and r.action in (ALLOW, UNKNOWN):
            anys = [n for n, v in (("출발지", r.src.any), ("목적지", r.dst.any), ("서비스", r.svc.any)) if v]
            if anys:
                add(u, "ANY", detail=" / ".join(anys) + " any")

    merge_groups: list[list[int]] = []
    for scope, srules in policy.scopes().items():
        live = [r for r in srules if r.enabled]
        _shadow_pass(live, add)
        if opt.detect_down:
            _down_pass(live, findings, add)
        if opt.detect_merge:
            merge_groups += _merge_pass(live, findings, add)

    removed = set()
    for uid, fs in findings.items():
        codes = {f.code for f in fs}
        if any(f.category == "remove" for f in fs):
            removed.add(uid)
        elif opt.include_disabled and "DISABLED" in codes:
            removed.add(uid)
        elif opt.include_unused and "UNUSED" in codes:
            removed.add(uid)

    return Analysis(policy, findings, removed, time.perf_counter() - t0, opt, merge_groups)


def _is_dead(findings_list):
    return any(f.category == "remove" for f in findings_list)


class _DstIndex:
    """목적지 IPv4 범위 기준 후보 인덱스.

    정책마다 목적지 범위를 감싸는 가장 작은 블록(/32, /24, /16, /8)에 넣어 두고,
    '포함할 수 있는 후보'(같은 블록이거나 상위 블록)와 '겹칠 수 있는 후보'(상위 + 하위 블록)만
    골라 비교한다. 목적지가 any, IPv6, FQDN 이거나 분석 불가 정책은 항상 후보(wide)로 둔다.
    """

    LEVELS = (0, 8, 16, 24)   # 오른쪽 shift 비트 수 (0 = /32 단위)

    def __init__(self, rules: list[Rule]):
        self.n = len(rules)
        self.wide: list[int] = []
        self.buckets = {s: {} for s in self.LEVELS}
        self.info: list[tuple] = []
        for pos, r in enumerate(rules):
            b = None if r.unanalyzable else _bbox(r.dst)
            level = 32
            if b is not None and not r.dst.any:
                for s in self.LEVELS:
                    if b[0] >> s == b[1] >> s:
                        level = s
                        break
            if level == 32:
                self.wide.append(pos)
            else:
                self.buckets[level].setdefault(b[0] >> level, []).append(pos)
            self.info.append((level, b))
        self.keys = {s: sorted(self.buckets[s]) for s in self.LEVELS}

    def cover_candidates(self, pos: int) -> list[int]:
        level, b = self.info[pos]
        if level == 32:
            return self.wide
        out = list(self.wide)
        for s in self.LEVELS:
            if s >= level:
                out += self.buckets[s].get(b[0] >> s, ())
        out.sort()
        return out

    def overlap_candidates(self, pos: int):
        level, b = self.info[pos]
        if level == 32:
            return range(self.n)
        out = self.cover_candidates(pos)
        extra = []
        for s in self.LEVELS:
            if s < level:
                ks = self.keys[s]
                i = bisect_left(ks, b[0] >> s)
                j = bisect_right(ks, b[1] >> s)
                for k in ks[i:j]:
                    extra += self.buckets[s][k]
        if extra:
            out = sorted(set(out).union(extra))
        return out


def _shadow_pass(live: list[Rule], add):
    """1단계: 위쪽 정책에 완전히 포함되는 정책 + 부분 충돌."""
    idx = _DstIndex(live)
    kept = [False] * len(live)
    boxes = [(_bbox(r.src), _bbox(r.dst)) for r in live]
    for pos, r in enumerate(live):
        if r.unanalyzable:
            kept[pos] = True
            continue
        rb = boxes[pos]
        verdict = None
        conflicts: list[int] = []
        partials: list[int] = []
        r_catch = _catch_all(r)
        for k in idx.overlap_candidates(pos):
            if k >= pos:
                break
            if not kept[k]:
                continue
            p = live[k]
            if p.unanalyzable:
                continue
            pb = boxes[k]
            if not (_boverlap(pb[0], rb[0]) and _boverlap(pb[1], rb[1])):
                continue
            if _bcover(pb[0], rb[0]) and _bcover(pb[1], rb[1]) and p.covers(r):
                if UNKNOWN in (p.action, r.action):
                    code = "DEAD"
                elif p.action == r.action:
                    code = "DUPLICATE" if r.covers(p) else "REDUNDANT"
                else:
                    code = "SHADOWED"
                verdict = (code, p)
                break
            # 부분 중첩 충돌: 서로 일부만 겹치는 반대 동작 정책.
            # 아래 정책이 위 정책을 포함하는 경우(예외 처리 패턴)와 Cleanup 정책은 제외.
            if UNKNOWN in (p.action, r.action) or r_catch or _catch_all(p):
                continue
            if p.action != r.action:
                if len(conflicts) < MAX_REFS and p.overlaps(r) and not r.covers(p):
                    conflicts.append(p.meta["uid"])
            elif len(partials) < MAX_REFS and p.overlaps(r) and not r.covers(p):
                partials.append(p.meta["uid"])
        u = r.meta["uid"]
        if verdict:
            code, p = verdict
            add(u, code, [p.meta["uid"]] + conflicts if code == "SHADOWED" else [p.meta["uid"]],
                f"근거 정책: {p.label}")
        else:
            if conflicts:
                add(u, "CONFLICT", conflicts)
            if partials:
                add(u, "PARTIAL", partials)
            kept[pos] = True


def _down_pass(live: list[Rule], findings, add):
    """2단계: 아래쪽 같은 동작 정책에 포함되는 정책."""
    alive = [r for r in live if not _is_dead(findings[r.meta["uid"]])]
    idx = _DstIndex(alive)
    boxes = [(_bbox(r.src), _bbox(r.dst)) for r in alive]
    removed = [False] * len(alive)
    for pos in range(len(alive) - 1, -1, -1):
        r = alive[pos]
        if r.unanalyzable or r.action == UNKNOWN:
            continue
        rb = boxes[pos]
        # 목적지가 겹칠 수 없는 정책은 차단도 포함도 할 수 없으므로 후보만 순서대로 본다
        for k in idx.overlap_candidates(pos):
            if k <= pos or removed[k]:
                continue
            q = alive[k]
            qb = boxes[k]
            if q.action != r.action:   # UNKNOWN 도 반대 동작일 수 있으므로 차단으로 취급
                if (q.unanalyzable or (_boverlap(qb[0], rb[0]) and _boverlap(qb[1], rb[1]))) and _may_overlap(q, r):
                    break          # 사이에 반대 동작 정책이 끼어 있음 → 지우면 결과가 바뀜
                continue
            if q.unanalyzable or _catch_all(q):
                # 맨 아래 any 정책(Cleanup / 전체 허용)을 근거로 삼지 않음 → 정리 대상이 과도해지는 것 방지
                continue
            if _bcover(qb[0], rb[0]) and _bcover(qb[1], rb[1]) and q.covers(r):
                removed[pos] = True
                add(r.meta["uid"], "REDUNDANT_DOWN", [q.meta["uid"]], f"근거 정책: {q.label}")
                break


def _merge_pass(live: list[Rule], findings, add) -> list[list[int]]:
    """조건이 하나만 다른 같은 동작 정책 묶음을 통합 후보로 표시."""
    alive = [r for r in live if not _is_dead(findings[r.meta["uid"]])]   # 분석 불가 정책도 '사이' 검사엔 포함
    idx = _DstIndex(alive)
    pos = {r.meta["uid"]: i for i, r in enumerate(alive)}
    groups_out: list[list[int]] = []
    used: set[int] = set()

    def key(r: Rule, skip: str):
        parts = [r.action, r.src_zone, r.dst_zone, r.app, r.users, frozenset(r.extra.items())]
        for d in ("src", "dst", "svc"):
            parts.append(None if d == skip else getattr(r, d))
        return tuple(parts)

    for dim, label in (("svc", "서비스"), ("src", "출발지"), ("dst", "목적지")):
        buckets: dict = {}
        for r in alive:
            if r.meta["uid"] in used or r.unanalyzable or r.action == UNKNOWN:
                continue
            buckets.setdefault(key(r, dim), []).append(r)
        for members in buckets.values():
            if len(members) < 2:
                continue
            first = members[0]
            lo = pos[first.meta["uid"]]
            safe = [first]
            for m in members[1:]:
                # first 위치로 합칠 때, 사이에 m 과 겹치는 반대 동작 정책이 있으면 제외
                hi = pos[m.meta["uid"]]
                if any(lo < k < hi and (alive[k].action != m.action or alive[k].action == UNKNOWN) and _may_overlap(alive[k], m)
                       for k in idx.overlap_candidates(hi)):
                    continue
                safe.append(m)
            if len(safe) < 2:
                continue
            uids = [m.meta["uid"] for m in safe]
            used.update(uids)
            groups_out.append(uids)
            for m in safe:
                add(m.meta["uid"], "MERGE", [x for x in uids if x != m.meta["uid"]],
                    f"{label}만 다른 정책 {len(uids)}개 → 1개로 통합 가능")
    return groups_out
