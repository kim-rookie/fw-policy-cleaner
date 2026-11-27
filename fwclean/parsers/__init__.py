"""벤더별 파서 등록 및 자동 판별."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..model import PolicySet
from . import cisco_asa, fortigate, juniper_srx, paloalto, screenos, tabular


@dataclass(frozen=True)
class Vendor:
    key: str
    label: str
    formats: str          # 화면에 보여줄 입력 형식 안내
    kind: str             # 'config' | 'table'
    parse: Callable
    verified: bool = True  # 실제 장비 export 샘플로 형식 검증 여부


def _table(vendor_key):
    def p(data, filename, vendor=vendor_key, options=None):
        return tabular.parse(data, filename, vendor_key, options)
    return p


VENDORS = [
    Vendor("paloalto", "Palo Alto Networks (PAN-OS / Panorama)",
           "XML 설정 파일 (show config running / Export named configuration)", "config", paloalto.parse),
    Vendor("paloalto_csv", "Palo Alto Networks - 정책 CSV",
           "웹 UI Policies > Security 화면의 CSV export", "table", _table("paloalto_csv")),
    Vendor("fortigate", "Fortinet FortiGate (FortiOS)",
           "설정 백업 .conf (show full-configuration)", "config", fortigate.parse),
    Vendor("cisco_asa", "Cisco ASA / FTD",
           "show running-config (+ show access-list 를 뒤에 붙이면 hit count 반영)", "config", cisco_asa.parse),
    Vendor("juniper_srx", "Juniper SRX",
           "show configuration | display set", "config", juniper_srx.parse),
    Vendor("screenos", "Juniper ScreenOS (NetScreen / SSG)",
           "get config 출력 (웹 화면 복사본은 '기타 / 표 형식' 사용)", "config", screenos.parse),
    Vendor("checkpoint", "Check Point (SmartConsole)",
           "SmartConsole 정책 화면의 CSV/Excel export", "table", _table("checkpoint"), verified=False),
    Vendor("secui", "SECUI (MF2 / BLUEMAX NGF)", "관리 화면 정책 목록 엑셀/CSV export", "table",
           _table("secui"), verified=False),
    Vendor("axgate", "AXGATE", "관리 화면 정책 목록 엑셀/CSV export", "table", _table("axgate"), verified=False),
    Vendor("trusguard", "AhnLab TrusGuard", "관리 화면 정책 목록 엑셀/CSV export", "table",
           _table("trusguard"), verified=False),
    Vendor("wins", "WINS SNIPER ONE-i", "관리 화면 정책 목록 엑셀/CSV export", "table", _table("wins"),
           verified=False),
    Vendor("generic", "기타 / 표 형식 (엑셀·CSV)",
           "출발지·목적지·서비스·동작 열이 있는 엑셀/CSV (기존 툴 양식 포함)", "table", _table("generic")),
]
BY_KEY = {v.key: v for v in VENDORS}


def detect(data: bytes, filename: str) -> str:
    """파일 내용으로 벤더 추정."""
    name = filename.lower()
    if name.endswith((".xlsx", ".xlsm", ".xls")):
        return "generic"
    head = data[:200_000].decode("utf-8", errors="ignore")
    low = head.lower()
    if "<config" in low and ("<rulebase" in low or "<devices" in low or "<shared" in low):
        return "paloalto"
    if "config firewall policy" in low or "#config-version=" in low:
        return "fortigate"
    if "set security policies" in low or "set security address-book" in low:
        return "juniper_srx"
    if "set policy id " in low and ("set address " in low or " from " in low):
        return "screenos"
    if "access-list " in low and (" extended " in low or "asa version" in low):
        return "cisco_asa"
    first = low.splitlines()[0] if low else ""
    if "source zone" in first and "source address" in first and "rule usage" in low:
        return "paloalto_csv"
    if "services & applications" in first or "install on" in first:
        return "checkpoint"
    return "generic"


def parse(data: bytes, filename: str, vendor: str = "auto", options: dict | None = None) -> PolicySet:
    key = detect(data, filename) if vendor in ("", "auto", None) else vendor
    if key not in BY_KEY:
        raise ValueError(f"지원하지 않는 벤더: {key}")
    v = BY_KEY[key]
    if v.kind == "config" and filename.lower().endswith((".xlsx", ".xls", ".xlsm")):
        raise ValueError(f"{v.label} 은(는) 설정 파일(텍스트/XML)을 넣어 주세요: {v.formats}")
    policy = v.parse(data, filename, key, options)
    policy.vendor = key
    if not policy.rules:
        raise ValueError("정책을 하나도 읽지 못했습니다. 벤더와 파일 형식을 확인해 주세요.")
    return policy
