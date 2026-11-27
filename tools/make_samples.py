"""표 형식 샘플 파일 생성 (테스트/데모용)."""
import csv
from pathlib import Path

from openpyxl import Workbook

OUT = Path(__file__).resolve().parent.parent / "samples"
OUT.mkdir(exist_ok=True)

# 1) 국산 장비 스타일 (한글 헤더, 셀 안 여러 값, 주소 객체 시트 포함)
wb = Workbook()
ws = wb.active
ws.title = "정책"
ws.append(["방화벽 정책 목록 (export)"])
ws.append([])
ws.append(["순번", "정책명", "출발지", "목적지", "서비스", "동작", "사용여부", "히트카운트", "설명"])
rows = [
    (1, "외부-웹", "any", "WEB-NET", "tcp/80\ntcp/443", "허용", "사용", 15320, "웹 서비스"),
    (2, "외부-웹1", "any", "10.10.1.10", "tcp/443", "허용", "사용", 0, "중복 (1번에 포함)"),
    (3, "SSH차단", "any", "WEB-NET", "tcp/22", "거부", "사용", 120, ""),
    (4, "관리자SSH", "192.168.10.1-192.168.10.50", "10.10.1.10", "tcp/22", "허용", "사용", 0, "3번에 가려짐"),
    (5, "웹-DB", "10.10.1.10", "DB-SRV", "tcp/3306", "허용", "사용", 800, ""),
    (6, "웹망-DB", "WEB-NET", "DB-SRV", "tcp/3306", "허용", "사용", 4100, ""),
    (7, "임시허용", "10.99.0.0/16", "any", "any", "허용", "미사용", 0, "작업용 임시"),
    (8, "사무실-인터넷-http", "OFFICE", "any", "tcp/80", "허용", "사용", 9999, ""),
    (9, "사무실-인터넷-https", "OFFICE", "any", "tcp/443", "허용", "사용", 8888, ""),
    (10, "외부-웹(복사)", "any", "WEB-NET", "tcp/80, tcp/443", "허용", "사용", 0, "1번과 동일"),
    (11, "전체차단", "any", "any", "any", "거부", "사용", 50000, ""),
]
for r in rows:
    ws.append(list(r))
obj = wb.create_sheet("주소객체")
obj.append(["이름", "주소", "설명"])
obj.append(["WEB-NET", "10.10.1.0/24", "웹 서버 대역"])
obj.append(["DB-SRV", "10.20.1.5", "DB"])
obj.append(["OFFICE", "192.168.0.0/16", "사무실"])
wb.save(OUT / "korean_vendor_export.xlsx")

# 2) 한 정책이 여러 행에 걸친 양식 (Sheet1, 같은 Rule ID 가 연속된 행)
wb = Workbook()
ws = wb.active
ws.title = "Sheet1"
ws.append(["Rule ID", "Source", "Destination", "Service", "Action"])
legacy = [
    ("100", "10.1.1.0/24", "172.16.1.10", "tcp/80", "allow"),
    ("100", "10.1.2.0/24", "", "tcp/443", ""),
    ("101", "10.1.1.5", "172.16.1.10", "tcp/443", "allow"),
    ("102", "any", "172.16.1.20", "tcp/22", "deny"),
    ("103", "10.1.1.7", "172.16.1.20", "tcp/22", "allow"),
    ("104", "10.1.3.0/24", "172.16.1.30", "tcp/8080", "allow"),
    ("105", "10.1.4.0/24", "172.16.1.30", "tcp/8080", "allow"),
    ("106", "any", "any", "any", "allow"),
]
for r in legacy:
    ws.append(list(r))
wb.save(OUT / "legacy_multirow.xlsx")

# 3) Check Point SmartConsole CSV 스타일
with open(OUT / "checkpoint_export.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["No.", "Name", "Source", "Destination", "VPN", "Services & Applications", "Action", "Track",
                "Install On", "Time", "Comments", "Hits"])
    w.writerow(["1", "Stealth", "Any", "10.0.0.1", "Any", "Any", "Drop", "Log", "Policy Targets", "Any", "", "120"])
    w.writerow(["2", "Web", "Any", "10.10.1.0/24", "Any", "http;https", "Accept", "Log", "Policy Targets", "Any",
                "", "5000"])
    w.writerow(["3", "Web-single", "Any", "10.10.1.10", "Any", "https", "Accept", "None", "Policy Targets", "Any",
                "", "0"])
    w.writerow(["4", "Mgmt", "192.168.10.0/24", "10.10.1.0/24", "Any", "ssh", "Accept", "Log", "Policy Targets",
                "Any", "", "33"])
    w.writerow(["5", "Cleanup", "Any", "Any", "Any", "Any", "Drop", "Log", "Policy Targets", "Any", "", "9000"])

print("samples written to", OUT)
