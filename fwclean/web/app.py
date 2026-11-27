"""로컬 웹 UI (Flask). 127.0.0.1 에서만 열린다."""
from __future__ import annotations

import json
import re
import threading
import uuid
from collections import OrderedDict
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

from .. import __version__, parsers
from ..analyzer import Options, analyze
from ..parsers import tabular
from ..report import cleaned_table, commands, excel_report, to_json

HERE = Path(__file__).resolve().parent
MAX_RESULTS = 10

app = Flask(__name__, static_folder=str(HERE / "static"), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

_results: "OrderedDict[str, object]" = OrderedDict()
_lock = threading.Lock()


def _store(a) -> str:
    rid = uuid.uuid4().hex
    with _lock:
        _results[rid] = a
        while len(_results) > MAX_RESULTS:
            _results.popitem(last=False)
    return rid


def _get(rid):
    with _lock:
        return _results.get(rid)


def _safe_name(name: str) -> str:
    stem = Path(name or "policy").stem
    return re.sub(r"[^\w\-.가-힣]+", "_", stem)[:60] or "policy"


@app.get("/")
def index():
    return send_from_directory(HERE / "static", "index.html")


@app.get("/api/vendors")
def vendors():
    return jsonify({"version": __version__, "vendors": [
        {"key": v.key, "label": v.label, "formats": v.formats, "kind": v.kind, "verified": v.verified}
        for v in parsers.VENDORS]})


def _read_upload():
    f = request.files.get("file")
    if not f or not f.filename:
        raise ValueError("파일을 선택해 주세요.")
    return f.read(), f.filename


@app.post("/api/preview")
def preview():
    try:
        data, name = _read_upload()
        vendor = request.form.get("vendor") or "auto"
        key = parsers.detect(data, name) if vendor == "auto" else vendor
        if parsers.BY_KEY[key].kind != "table":
            return jsonify({"vendor": key, "kind": "config"})
        out = tabular.preview(data, name)
        out.update({"vendor": key, "kind": "table"})
        return jsonify(out)
    except Exception as e:  # noqa: BLE001 - 사용자에게 메시지 전달
        return jsonify({"error": str(e)}), 400


@app.post("/api/analyze")
def run_analyze():
    try:
        data, name = _read_upload()
        vendor = request.form.get("vendor") or "auto"
        opts = json.loads(request.form.get("options") or "{}")
        parse_opts = json.loads(request.form.get("parse_options") or "{}")
        policy = parsers.parse(data, name, vendor, parse_opts)
        options = Options(**{k: bool(v) for k, v in opts.items() if k in Options.__dataclass_fields__})
        a = analyze(policy, options)
        rid = _store(a)
        out = to_json(a)
        out["id"] = rid
        out["vendor_label"] = parsers.BY_KEY[policy.vendor].label
        out["vendor_verified"] = parsers.BY_KEY[policy.vendor].verified
        out["has_cleaned"] = bool(policy.meta.get("header"))
        return jsonify(out)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 400


def _download(body: bytes, filename: str, mime: str):
    from urllib.parse import quote
    return Response(body, mimetype=mime, headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"})


@app.get("/api/result/<rid>/report.xlsx")
def dl_report(rid):
    a = _get(rid)
    if not a:
        return jsonify({"error": "결과가 만료되었습니다. 다시 분석해 주세요."}), 404
    return _download(excel_report(a), f"{_safe_name(a.policy.source_name)}_정리리포트.xlsx",
                     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.get("/api/result/<rid>/cleaned.xlsx")
def dl_cleaned(rid):
    a = _get(rid)
    if not a:
        return jsonify({"error": "결과가 만료되었습니다."}), 404
    body = cleaned_table(a)
    if body is None:
        return jsonify({"error": "설정 파일 입력은 정리 명령어를 사용하세요."}), 400
    return _download(body, f"{_safe_name(a.policy.source_name)}_정리본.xlsx",
                     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.get("/api/result/<rid>/commands.txt")
def dl_commands(rid):
    a = _get(rid)
    if not a:
        return jsonify({"error": "결과가 만료되었습니다."}), 404
    return _download(commands(a).encode("utf-8-sig"), f"{_safe_name(a.policy.source_name)}_정리명령어.txt",
                     "text/plain; charset=utf-8")


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "파일이 너무 큽니다 (최대 100MB)."}), 413
