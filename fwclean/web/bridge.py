"""UI ↔ 분석 엔진 연결부. Flask 서버와 브라우저(Pyodide) 양쪽에서 같은 코드를 쓴다.

웹 프레임워크에 의존하지 않으므로 브라우저 안에서도 그대로 import 된다.
"""
from __future__ import annotations

import json
import re
import threading
import uuid
from collections import OrderedDict
from pathlib import PurePath

from .. import __version__, parsers
from ..analyzer import Options, analyze
from ..parsers import tabular
from ..report import cleaned_table, commands, excel_report, to_json

MAX_RESULTS = 10
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

_results: "OrderedDict[str, object]" = OrderedDict()
_lock = threading.Lock()


def _store(a) -> str:
    rid = uuid.uuid4().hex
    with _lock:
        _results[rid] = a
        while len(_results) > MAX_RESULTS:
            _results.popitem(last=False)
    return rid


def get_result(rid):
    with _lock:
        return _results.get(rid)


def safe_name(name: str) -> str:
    stem = PurePath(name or "policy").stem
    return re.sub(r"[^\w\-.가-힣]+", "_", stem)[:60] or "policy"


def vendors() -> dict:
    return {"version": __version__, "vendors": [
        {"key": v.key, "label": v.label, "formats": v.formats, "kind": v.kind, "verified": v.verified}
        for v in parsers.VENDORS]}


def preview(data: bytes, name: str, vendor: str = "auto") -> dict:
    key = parsers.detect(data, name) if vendor in ("", "auto", None) else vendor
    if parsers.BY_KEY[key].kind != "table":
        return {"vendor": key, "kind": "config"}
    out = tabular.preview(data, name)
    out.update({"vendor": key, "kind": "table"})
    return out


def run_analyze(data: bytes, name: str, vendor: str = "auto", options: dict | None = None,
                parse_options: dict | None = None) -> dict:
    policy = parsers.parse(data, name, vendor or "auto", parse_options or {})
    opts = Options(**{k: bool(v) for k, v in (options or {}).items() if k in Options.__dataclass_fields__})
    a = analyze(policy, opts)
    out = to_json(a)
    out["id"] = _store(a)
    out["vendor_label"] = parsers.BY_KEY[policy.vendor].label
    out["vendor_verified"] = parsers.BY_KEY[policy.vendor].verified
    out["has_cleaned"] = bool(policy.meta.get("header"))
    return out


def download(rid: str, kind: str) -> tuple[bytes, str, str]:
    """(본문, 파일명, MIME). kind: report | cleaned | commands"""
    a = get_result(rid)
    if not a:
        raise LookupError("결과가 만료되었습니다. 다시 분석해 주세요.")
    base = safe_name(a.policy.source_name)
    if kind == "report":
        return excel_report(a), f"{base}_정리리포트.xlsx", XLSX
    if kind == "cleaned":
        body = cleaned_table(a)
        if body is None:
            raise ValueError("설정 파일 입력은 정리 명령어를 사용하세요.")
        return body, f"{base}_정리본.xlsx", XLSX
    if kind == "commands":
        return commands(a).encode("utf-8-sig"), f"{base}_정리명령어.txt", "text/plain; charset=utf-8"
    raise ValueError(f"알 수 없는 다운로드 종류: {kind}")


# ---------------------------------------------------------------- 브라우저(Pyodide) 진입점
# JS 와는 JSON 문자열로 주고받는다 (타입 변환 문제를 피하려고).

def js_call(fn: str, payload_json: str, data=None) -> str:
    try:
        p = json.loads(payload_json or "{}")
        if data is None or type(data).__name__ == "JsNull":
            raw = b""
        elif hasattr(data, "to_bytes"):      # Pyodide JsProxy(Uint8Array)
            raw = data.to_bytes()
        else:
            raw = bytes(data)
        if fn == "vendors":
            out = vendors()
        elif fn == "preview":
            out = preview(raw, p["name"], p.get("vendor", "auto"))
        elif fn == "analyze":
            out = run_analyze(raw, p["name"], p.get("vendor", "auto"), p.get("options"), p.get("parse_options"))
        else:
            raise ValueError(fn)
        return json.dumps(out, ensure_ascii=False)
    except Exception as e:  # noqa: BLE001 - 사용자에게 메시지 전달
        return json.dumps({"error": str(e)}, ensure_ascii=False)


def js_download(rid: str, kind: str):
    body, filename, mime = download(rid, kind)
    return body, filename, mime
