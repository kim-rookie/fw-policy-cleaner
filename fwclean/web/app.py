"""로컬 웹 UI (Flask). 127.0.0.1 에서만 열린다. 실제 처리는 bridge.py 가 한다."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

from flask import Flask, Response, jsonify, request, send_from_directory

from . import bridge

HERE = Path(__file__).resolve().parent

app = Flask(__name__, static_folder=str(HERE / "static"), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024


@app.get("/")
def index():
    return send_from_directory(HERE / "static", "index.html")


@app.get("/api/vendors")
def vendors():
    return jsonify(bridge.vendors())


def _read_upload():
    f = request.files.get("file")
    if not f or not f.filename:
        raise ValueError("파일을 선택해 주세요.")
    return f.read(), f.filename


@app.post("/api/preview")
def preview():
    try:
        data, name = _read_upload()
        return jsonify(bridge.preview(data, name, request.form.get("vendor") or "auto"))
    except Exception as e:  # noqa: BLE001 - 사용자에게 메시지 전달
        return jsonify({"error": str(e)}), 400


@app.post("/api/analyze")
def run_analyze():
    try:
        data, name = _read_upload()
        return jsonify(bridge.run_analyze(
            data, name, request.form.get("vendor") or "auto",
            json.loads(request.form.get("options") or "{}"),
            json.loads(request.form.get("parse_options") or "{}")))
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 400


@app.get("/api/result/<rid>/<kind>")
def download(rid, kind):
    kind = kind.split(".")[0]          # report.xlsx → report
    try:
        body, filename, mime = bridge.download(rid, kind)
    except LookupError as e:
        return jsonify({"error": str(e)}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return Response(body, mimetype=mime, headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"})


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "파일이 너무 큽니다 (최대 100MB)."}), 413
