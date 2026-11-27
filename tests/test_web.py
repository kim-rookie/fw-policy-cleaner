"""웹 API 테스트."""
import io
import json
from pathlib import Path

from fwclean.web.app import app

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def post(path, name, **form):
    c = app.test_client()
    data = {"file": (io.BytesIO((SAMPLES / name).read_bytes()), name), **form}
    return c, c.post(path, data=data, content_type="multipart/form-data")


def test_analyze_and_downloads():
    c, r = post("/api/analyze", "fortigate.conf", vendor="auto")
    assert r.status_code == 200, r.json
    j = r.json
    assert j["summary"]["vendor"] == "fortigate" and j["summary"]["removed"] >= 3
    rid = j["id"]
    assert c.get(f"/api/result/{rid}/report.xlsx").data[:2] == b"PK"
    assert "config firewall policy" in c.get(f"/api/result/{rid}/commands.txt").data.decode("utf-8-sig")
    assert c.get(f"/api/result/{rid}/cleaned.xlsx").status_code == 400


def test_table_preview_and_mapping_override():
    c, r = post("/api/preview", "korean_vendor_export.xlsx", vendor="secui")
    j = r.json
    sheet = j["sheets"][0]
    assert sheet["mapping"]["src"] == "출발지" and sheet["header_row"] == 2
    mapping = dict(sheet["mapping"])
    mapping.pop("hits")
    c, r = post("/api/analyze", "korean_vendor_export.xlsx", vendor="secui",
                parse_options=json.dumps({"mapping": mapping, "header_row": 2, "sheet": sheet["sheet"]}))
    assert r.status_code == 200
    assert r.json["summary"]["has_hits"] is False
    assert c.get(f"/api/result/{r.json['id']}/cleaned.xlsx").data[:2] == b"PK"


def test_bad_file_message():
    c = app.test_client()
    r = c.post("/api/analyze", data={"file": (io.BytesIO(b"hello"), "x.txt"), "vendor": "auto"},
               content_type="multipart/form-data")
    assert r.status_code == 400 and r.json["error"]
