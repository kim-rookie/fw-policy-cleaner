"""파서 공통 유틸."""
from __future__ import annotations

import re

from ..sets import ANY_SVC, PORT_MAX, SvcSet, svc_ports, svc_proto

_SPLIT_RE = re.compile(r"[\r\n;,]+")


def split_values(cell) -> list[str]:
    """엑셀 셀 하나에 여러 값이 들어 있는 경우 분리 (줄바꿈, ;, ,)."""
    if cell is None:
        return []
    text = str(cell).strip()
    if not text:
        return []
    return [v.strip().strip('"').strip() for v in _SPLIT_RE.split(text) if v.strip().strip('"').strip()]


_SVC_A = re.compile(r"^(tcp|udp|sctp|icmp6?|icmpv6|ip|any|gre|esp|ah|\d{1,3})\s*[/:_ ]?\s*"
                    r"(any|all|\*|\d{1,5})?(?:\s*[-~]\s*(\d{1,5}))?$", re.I)
_SVC_B = re.compile(r"^(\d{1,5})(?:\s*[-~]\s*(\d{1,5}))?\s*/\s*(tcp|udp|sctp)$", re.I)
_SVC_PAIR = re.compile(r"^(tcp|udp)\s*(\d{1,5})_(\d{1,5})$", re.I)
_PORT_ONLY = re.compile(r"^(\d{1,5})(?:\s*[-~]\s*(\d{1,5}))?$")


def parse_service_literal(text: str) -> SvcSet | None:
    """'tcp/80', 'TCP 80-90', '80/tcp', 'udp:53', 'icmp', 'tcp' → SvcSet.

    프로토콜 없이 포트만 있는 경우('80')는 tcp+udp 둘 다로 본다. 이렇게 하면
    'tcp/80' 정책이 '80' 정책을 포함한다고 잘못 판정하지 않는다 (보수적).
    """
    t = text.strip()
    if not t:
        return None
    if t.lower() in ("any", "all", "*", "전체", "모두", "any/any"):
        return ANY_SVC
    m = _SVC_PAIR.match(t)   # 'TCP5000_6000' → tcp 5000-6000 (밑줄 = 범위 표기)
    if m:
        a, b = sorted((int(m.group(2)), int(m.group(3))))
        if _valid(a, b):
            return svc_ports(m.group(1), a, b)
    m = _SVC_B.match(t)
    if m:
        lo = int(m.group(1))
        hi = int(m.group(2) or lo)
        return svc_ports(m.group(3), lo, hi) if _valid(lo, hi) else None
    m = _PORT_ONLY.match(t)
    if m:
        lo = int(m.group(1))
        hi = int(m.group(2) or lo)
        if not _valid(lo, hi):
            return None
        return svc_ports("tcp", lo, hi).union(svc_ports("udp", lo, hi))
    m = _SVC_A.match(t)
    if m:
        proto = m.group(1).lower()
        port = m.group(2)
        if proto.isdigit():
            if int(proto) > 255:
                return None
            base = svc_proto(proto)
            if port is None or base.protos:
                return base if port is None else None
            proto = base.ports[0][0]
        if port is None or port.lower() in ("any", "all", "*"):
            return svc_proto(proto)
        if proto not in ("tcp", "udp", "sctp"):
            return None
        lo = int(port)
        hi = int(m.group(3) or lo)
        return svc_ports(proto, lo, hi) if _valid(lo, hi) else None
    return None


def _valid(lo, hi):
    return 0 <= lo <= PORT_MAX and 0 <= hi <= PORT_MAX


def norm_header(h) -> str:
    return re.sub(r"[\s_\-\.\(\)\[\]&/:#]+", "", str(h or "")).lower()
