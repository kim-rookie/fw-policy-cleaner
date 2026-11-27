"""브라우저(Pyodide) 진입점 테스트 — 웹 프레임워크 없이 동작해야 한다."""
import json
import sys
from pathlib import Path

from fwclean.web import bridge

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_bridge_has_no_flask_dependency():
    import importlib
    importlib.reload(bridge)
    import ast
    tree = ast.parse(Path(bridge.__file__).read_text(encoding="utf-8"))
    mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | \
           {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any(m and m.split(".")[0] == "flask" for m in mods)


def test_js_call_roundtrip():
    v = json.loads(bridge.js_call("vendors", "{}", None))
    assert any(x["key"] == "fortigate" for x in v["vendors"])

    data = (SAMPLES / "fortigate.conf").read_bytes()
    out = json.loads(bridge.js_call("analyze", json.dumps({"name": "fortigate.conf", "vendor": "auto"}), data))
    assert out["summary"]["vendor"] == "fortigate" and out["summary"]["removed"] >= 3

    body, filename, mime = bridge.js_download(out["id"], "commands")
    assert filename.endswith("_정리명령어.txt") and b"config firewall policy" in body


def test_js_call_reports_errors_as_json():
    out = json.loads(bridge.js_call("analyze", json.dumps({"name": "x.txt"}), b"hello"))
    assert out["error"]


def test_site_build(tmp_path, monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import build_site
    monkeypatch.setattr(build_site, "OUT", tmp_path / "site")
    build_site.main()
    html = (tmp_path / "site" / "index.html").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in html and "connect-src 'self'" in html
    import zipfile
    names = zipfile.ZipFile(tmp_path / "site" / "py.zip").namelist()
    assert "fwclean/web/bridge.py" in names and "fwclean/web/app.py" not in names
