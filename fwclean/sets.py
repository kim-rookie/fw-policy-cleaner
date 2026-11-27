"""정책 비교용 집합 타입.

모든 매칭 조건(주소, 서비스, 존, 애플리케이션 등)을 "포함(covers)"과 "겹침(overlaps)"
두 연산으로 비교할 수 있게 표현한다.

- Intervals : 정수 구간의 합집합 (IP, 포트 범위)
- AddrSet   : IPv4/IPv6 구간 + 해석 불가 토큰(FQDN, 동적 그룹 등)
- SvcSet    : 프로토콜별 포트 구간 + 해석 불가 토큰
- TokenSet  : 이름 집합 (존, 인터페이스, 애플리케이션, 사용자 등)

해석 불가 토큰은 "같은 이름끼리만 같다"로 취급한다. 따라서 결과는 보수적이다
(실제로는 포함 관계여도 이름이 다르면 포함으로 판정하지 않는다 → 오탐으로 정책을 지우는 일이 없음).
"""
from __future__ import annotations

import ipaddress
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Iterable

V4_MAX = (1 << 32) - 1
V6_MAX = (1 << 128) - 1
PORT_MAX = 65535


class Intervals:
    """닫힌 정수 구간 [lo, hi] 들의 정규화된(정렬·병합된) 합집합."""

    __slots__ = ("iv",)

    def __init__(self, items: Iterable[tuple[int, int]] = ()):
        self.iv: tuple[tuple[int, int], ...] = self._normalize(items)

    @staticmethod
    def _normalize(items):
        pts = sorted((min(a, b), max(a, b)) for a, b in items)
        out: list[list[int]] = []
        for lo, hi in pts:
            if out and lo <= out[-1][1] + 1:
                if hi > out[-1][1]:
                    out[-1][1] = hi
            else:
                out.append([lo, hi])
        return tuple((a, b) for a, b in out)

    def __bool__(self):
        return bool(self.iv)

    def __eq__(self, other):
        return isinstance(other, Intervals) and self.iv == other.iv

    def __hash__(self):
        return hash(self.iv)

    def union(self, other: "Intervals") -> "Intervals":
        return Intervals(self.iv + other.iv)

    def contains(self, other: "Intervals") -> bool:
        """self ⊇ other"""
        if not other.iv:
            return True
        if not self.iv:
            return False
        starts = [a for a, _ in self.iv]
        for lo, hi in other.iv:
            k = bisect_right(starts, lo) - 1
            if k < 0 or self.iv[k][1] < hi:
                return False
        return True

    def intersects(self, other: "Intervals") -> bool:
        i = j = 0
        a, b = self.iv, other.iv
        while i < len(a) and j < len(b):
            if a[i][1] < b[j][0]:
                i += 1
            elif b[j][1] < a[i][0]:
                j += 1
            else:
                return True
        return False

    def bounds(self):
        if not self.iv:
            return None
        return self.iv[0][0], self.iv[-1][1]

    def size(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.iv)


# --------------------------------------------------------------------------- tokens

@dataclass(frozen=True)
class TokenSet:
    """이름 집합. any=True 이면 전체."""

    any: bool = False
    items: frozenset = frozenset()

    @staticmethod
    def of(values: Iterable[str] | None, any_words=("any",)) -> "TokenSet":
        vals = [v.strip() for v in (values or []) if v and v.strip()]
        if not vals or any(v.lower() in any_words for v in vals):
            return TokenSet(any=True)
        return TokenSet(items=frozenset(vals))

    def contains(self, other: "TokenSet") -> bool:
        if self.any:
            return True
        if other.any:
            return False
        return other.items <= self.items

    def intersects(self, other: "TokenSet") -> bool:
        if self.any or other.any:
            return True
        return bool(self.items & other.items)

    def __str__(self):
        return "any" if self.any else ", ".join(sorted(self.items))


ANY_TOKENS = TokenSet(any=True)


# --------------------------------------------------------------------------- addresses

@dataclass(frozen=True)
class AddrSet:
    any: bool = False
    v4: Intervals = field(default_factory=Intervals)
    v6: Intervals = field(default_factory=Intervals)
    tokens: frozenset = frozenset()  # FQDN, 동적 그룹, 미해석 객체 등

    def union(self, other: "AddrSet") -> "AddrSet":
        if self.any or other.any:
            return ANY_ADDR
        return AddrSet(False, self.v4.union(other.v4), self.v6.union(other.v6), self.tokens | other.tokens)

    def contains(self, other: "AddrSet") -> bool:
        if self.any:
            return True
        if other.any:
            # any 를 IPv4 전체 + IPv6 전체로 명시한 경우도 any 로 인정
            return self.is_full()
        return self.v4.contains(other.v4) and self.v6.contains(other.v6) and other.tokens <= self.tokens

    def intersects(self, other: "AddrSet") -> bool:
        if self.any or other.any:
            return True
        return (self.v4.intersects(other.v4) or self.v6.intersects(other.v6)
                or bool(self.tokens & other.tokens))

    def is_full(self) -> bool:
        return self.v4.iv == ((0, V4_MAX),) and self.v6.iv == ((0, V6_MAX),)

    def is_empty(self) -> bool:
        return not self.any and not self.v4 and not self.v6 and not self.tokens


ANY_ADDR = AddrSet(any=True)


def _v4(lo, hi):
    return AddrSet(v4=Intervals([(lo, hi)]))


def _v6(lo, hi):
    return AddrSet(v6=Intervals([(lo, hi)]))


def addr_from_network(text: str) -> AddrSet:
    """'10.0.0.0/8', '10.0.0.1', '10.0.0.0 255.0.0.0', '2001:db8::/32' 형태."""
    t = text.strip()
    if " " in t:
        ip, mask = t.split(None, 1)
        t = f"{ip}/{mask.strip()}"
    net = ipaddress.ip_network(t, strict=False)
    lo, hi = int(net.network_address), int(net.broadcast_address)
    return _v4(lo, hi) if net.version == 4 else _v6(lo, hi)


def addr_from_range(start: str, end: str) -> AddrSet:
    a, b = ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())
    if a.version != b.version:
        raise ValueError(f"IP 버전 불일치: {start} - {end}")
    lo, hi = sorted((int(a), int(b)))
    return _v4(lo, hi) if a.version == 4 else _v6(lo, hi)


def addr_from_wildcard(text: str) -> AddrSet:
    """'10.1.*.*' 또는 '10.1.1.*' 형태 (국산 장비 export 에서 종종 보임)."""
    parts = text.strip().split(".")
    if len(parts) != 4:
        raise ValueError(text)
    lo = hi = 0
    for p in parts:
        lo <<= 8
        hi <<= 8
        if p == "*":
            hi |= 0xFF
        else:
            n = int(p)
            if not 0 <= n <= 255:
                raise ValueError(text)
            lo |= n
            hi |= n
    return _v4(lo, hi)


def try_parse_literal_addr(text: str) -> AddrSet | None:
    """문자열이 IP/대역/범위/와일드카드로 해석되면 AddrSet, 아니면 None."""
    t = text.strip()
    if not t:
        return None
    low = t.lower()
    if low in ("any", "any4", "any6", "all", "*", "0.0.0.0/0", "전체", "모두"):
        if low == "any4":
            return _v4(0, V4_MAX)
        if low == "any6":
            return _v6(0, V6_MAX)
        return ANY_ADDR
    try:
        for sep in ("-", "~"):
            if sep in t and t.count(sep) == 1 and ":" not in t.replace(sep, ""):
                a, b = t.split(sep)
                b = b.strip()
                # '10.0.0.1-50' 처럼 마지막 옥텟만 쓴 축약형
                if b.isdigit() and a.count(".") == 3:
                    b = a.rsplit(".", 1)[0] + "." + b
                return addr_from_range(a, b)
        if "-" in t and ":" in t and t.count("-") == 1:
            a, b = t.split("-")
            return addr_from_range(a, b)
        if "*" in t:
            return addr_from_wildcard(t)
        return addr_from_network(t)
    except ValueError:
        return None


def describe_addr(a: AddrSet) -> str:
    if a.any:
        return "any"
    parts = []
    for lo, hi in a.v4.iv:
        parts.append(_fmt_range(lo, hi, 4))
    for lo, hi in a.v6.iv:
        parts.append(_fmt_range(lo, hi, 6))
    parts += sorted(a.tokens)
    return ", ".join(parts)


def _fmt_range(lo, hi, ver):
    mk = ipaddress.IPv4Address if ver == 4 else ipaddress.IPv6Address
    if lo == hi:
        return str(mk(lo))
    nets = list(ipaddress.summarize_address_range(mk(lo), mk(hi)))
    if len(nets) == 1:
        return str(nets[0])
    return f"{mk(lo)}-{mk(hi)}"


# --------------------------------------------------------------------------- services

PORT_PROTOS = ("tcp", "udp", "sctp")


@dataclass(frozen=True)
class SvcSet:
    """프로토콜별 목적지 포트 구간.

    ports : {'tcp': Intervals, 'udp': Intervals, 'sctp': Intervals}
    protos: 포트 개념이 없는 프로토콜 전체 허용 (예: 'icmp', 'ip:47')
    tokens: 해석 불가 서비스 이름 / 'application-default' 등
    """

    any: bool = False
    ports: tuple = ()  # ((proto, Intervals), ...) - frozen dataclass 용 튜플
    protos: frozenset = frozenset()
    tokens: frozenset = frozenset()

    @staticmethod
    def build(ports: dict | None = None, protos=(), tokens=()) -> "SvcSet":
        ports = {k: v for k, v in (ports or {}).items() if v}
        return SvcSet(False, tuple(sorted(ports.items())), frozenset(protos), frozenset(tokens))

    def port_map(self) -> dict:
        return dict(self.ports)

    def union(self, other: "SvcSet") -> "SvcSet":
        if self.any or other.any:
            return ANY_SVC
        pm = self.port_map()
        for k, v in other.port_map().items():
            pm[k] = pm[k].union(v) if k in pm else v
        return SvcSet.build(pm, self.protos | other.protos, self.tokens | other.tokens)

    def contains(self, other: "SvcSet") -> bool:
        if self.any:
            return True
        if other.any:
            return False
        mine = self.port_map()
        for proto, iv in other.port_map().items():
            if proto in self.protos:  # 프로토콜 전체 허용
                continue
            if proto not in mine or not mine[proto].contains(iv):
                return False
        return other.protos <= self.protos and other.tokens <= self.tokens

    def intersects(self, other: "SvcSet") -> bool:
        if self.any or other.any:
            return True
        a, b = self.port_map(), other.port_map()
        for proto, iv in a.items():
            if proto in b and iv.intersects(b[proto]):
                return True
            if proto in other.protos:
                return True
        for proto in b:
            if proto in self.protos:
                return True
        return bool(self.protos & other.protos) or bool(self.tokens & other.tokens)

    def is_empty(self):
        return not self.any and not self.ports and not self.protos and not self.tokens


ANY_SVC = SvcSet(any=True)


def svc_ports(proto: str, lo: int, hi: int | None = None) -> SvcSet:
    hi = lo if hi is None else hi
    return SvcSet.build({proto.lower(): Intervals([(lo, hi)])})


def svc_proto(proto: str) -> SvcSet:
    """포트 없는 프로토콜 전체. tcp/udp 를 포트 없이 쓰면 전체 포트로 본다."""
    p = proto.lower()
    if p in PORT_PROTOS:
        return svc_ports(p, 0, PORT_MAX)
    if p in ("ip", "any", "all"):
        return ANY_SVC
    if p.isdigit():
        n = int(p)
        named = {6: "tcp", 17: "udp", 132: "sctp", 1: "icmp", 58: "icmp6"}
        if n in (6, 17, 132):
            return svc_ports(named[n], 0, PORT_MAX)
        p = named.get(n, f"ip:{n}")
    if p in ("icmpv6", "ipv6-icmp"):
        p = "icmp6"
    return SvcSet.build(protos=[p])


def describe_svc(s: SvcSet) -> str:
    if s.any:
        return "any"
    parts = []
    for proto, iv in s.ports:
        for lo, hi in iv.iv:
            if lo == 0 and hi == PORT_MAX:
                parts.append(f"{proto}/all")
            elif lo == hi:
                parts.append(f"{proto}/{lo}")
            else:
                parts.append(f"{proto}/{lo}-{hi}")
    parts += sorted(s.protos)
    parts += sorted(s.tokens)
    return ", ".join(parts)


# 잘 알려진 서비스 이름 → (프로토콜, 포트). 벤더 공통으로 사용.
WELL_KNOWN = {
    "ftp": [("tcp", 21)], "ftp-data": [("tcp", 20)], "ssh": [("tcp", 22)], "telnet": [("tcp", 23)],
    "smtp": [("tcp", 25)], "mail": [("tcp", 25)], "dns": [("tcp", 53), ("udp", 53)], "domain": [("tcp", 53), ("udp", 53)],
    "tftp": [("udp", 69)], "http": [("tcp", 80)], "www": [("tcp", 80)], "pop3": [("tcp", 110)],
    "ntp": [("udp", 123)], "nntp": [("tcp", 119)], "imap": [("tcp", 143)], "snmp": [("udp", 161)],
    "snmptrap": [("udp", 162)], "snmp-trap": [("udp", 162)], "ldap": [("tcp", 389)],
    "https": [("tcp", 443)], "smb": [("tcp", 445)], "syslog": [("udp", 514)], "ldaps": [("tcp", 636)],
    "imaps": [("tcp", 993)], "pop3s": [("tcp", 995)], "mssql": [("tcp", 1433)], "ms-sql": [("tcp", 1433)],
    "oracle": [("tcp", 1521)], "sqlnet": [("tcp", 1521)], "mysql": [("tcp", 3306)],
    "rdp": [("tcp", 3389)], "ms-rdp": [("tcp", 3389)], "postgres": [("tcp", 5432)],
    "postgresql": [("tcp", 5432)], "vnc": [("tcp", 5900)], "kerberos": [("tcp", 88), ("udp", 88)],
    "netbios-ns": [("udp", 137)], "netbios-dgm": [("udp", 138)], "netbios-ssn": [("tcp", 139)],
    "bgp": [("tcp", 179)], "radius": [("udp", 1812)], "sip": [("tcp", 5060), ("udp", 5060)],
    "http-alt": [("tcp", 8080)], "dhcp": [("udp", 67), ("udp", 68)], "bootps": [("udp", 67)],
    "bootpc": [("udp", 68)], "lpd": [("tcp", 515)], "sunrpc": [("tcp", 111), ("udp", 111)],
    "nfs": [("tcp", 2049), ("udp", 2049)], "smtps": [("tcp", 465)], "submission": [("tcp", 587)],
    "redis": [("tcp", 6379)], "mongodb": [("tcp", 27017)], "kerberos-adm": [("tcp", 749)],
}


def svc_well_known(name: str) -> SvcSet | None:
    key = name.strip().lower()
    if key in ("ping", "icmp", "all_icmp", "icmp-any", "echo"):
        return svc_proto("icmp")
    if key not in WELL_KNOWN:
        return None
    s = SvcSet.build()
    for proto, port in WELL_KNOWN[key]:
        s = s.union(svc_ports(proto, port))
    return s


def port_number(name: str) -> int:
    """포트 이름 또는 숫자 → 포트 번호 (Cisco 'www', 'https' 등)."""
    n = name.strip().lower()
    if n.isdigit():
        return int(n)
    if n in WELL_KNOWN:
        return WELL_KNOWN[n][0][1]
    raise ValueError(f"알 수 없는 포트 이름: {name}")
