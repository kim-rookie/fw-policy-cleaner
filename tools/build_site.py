"""정적 웹사이트(GitHub Pages) 빌드: python tools/build_site.py  →  site/

분석은 방문자의 브라우저 안(Pyodide)에서 실행된다. 서버가 없으므로 파일이 업로드되지 않는다.
페이지에는 외부 전송을 막는 CSP 를 건다 (connect-src 는 자기 자신과 Pyodide CDN 만 허용).
"""
import importlib.metadata as md
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "fwclean" / "web" / "static"
OUT = ROOT / "site"
PYODIDE = "https://cdn.jsdelivr.net/pyodide/v0.29.5/full/"
DEPS = ["openpyxl", "et_xmlfile", "defusedxml"]   # 순수 Python 의존성 (Flask 는 브라우저에 불필요)

SAMPLES = [
    ("paloalto_running.xml", "Palo Alto — XML 설정"),
    ("fortigate.conf", "FortiGate — 설정 백업"),
    ("cisco_asa.txt", "Cisco ASA — running-config + hit count"),
    ("juniper_srx.set", "Juniper SRX — display set"),
    ("screenos_getconfig.txt", "Juniper ScreenOS — get config"),
    ("checkpoint_export.csv", "Check Point — CSV export"),
    ("korean_vendor_export.xlsx", "국산 장비 스타일 — 엑셀 export"),
    ("legacy_multirow.xlsx", "여러 행에 걸친 정책 — 엑셀"),
]

CSP = "; ".join([
    "default-src 'self'",
    f"script-src 'self' {PYODIDE.rstrip('/')}/ 'wasm-unsafe-eval'",
    "worker-src blob:",
    f"connect-src 'self' {PYODIDE.rstrip('/')}/",
    "img-src 'self' data: blob:",
    "style-src 'self' 'unsafe-inline'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-src 'none'",
])


def build_py_zip(dest: Path):
    with tempfile.TemporaryDirectory() as tmp:
        pins = [f"{d}=={md.version(d.replace('_', '-'))}" for d in DEPS]
        subprocess.run([sys.executable, "-m", "pip", "download", "-q", "--no-deps", "--only-binary=:all:",
                        "-d", tmp, *pins], check=True)
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
            for whl in Path(tmp).glob("*.whl"):
                with zipfile.ZipFile(whl) as w:
                    for n in w.namelist():
                        if ".dist-info/" in n:
                            continue
                        z.writestr(n, w.read(n))
            for f in sorted((ROOT / "fwclean").rglob("*.py")):
                rel = f.relative_to(ROOT).as_posix()
                if rel == "fwclean/web/app.py":   # Flask 서버 전용
                    continue
                z.write(f, rel)
    return pins


def main():
    OUT.mkdir(exist_ok=True)
    for child in OUT.iterdir():   # 폴더 자체는 두고 내용만 비움 (로컬 미리보기 서버가 열려 있어도 동작)
        shutil.rmtree(child) if child.is_dir() else child.unlink()
    pins = build_py_zip(OUT / "py.zip")
    for name in ("app.css", "app.js"):
        shutil.copy(STATIC / name, OUT / name)
    (OUT / "samples").mkdir()
    for f, _ in SAMPLES:
        shutil.copy(ROOT / "samples" / f, OUT / "samples" / f)

    config = (
        "window.FWCLEAN_STATIC = true;\n"
        f"window.FWCLEAN_PYODIDE = {json.dumps(PYODIDE)};\n"
        f"window.FWCLEAN_SAMPLES = {json.dumps([list(s) for s in SAMPLES], ensure_ascii=False)};\n"
        f"window.FWCLEAN_WORKER_SRC = {json.dumps((STATIC / 'worker.js').read_text(encoding='utf-8'))};\n"
    )
    (OUT / "config.js").write_text(config, encoding="utf-8")

    html = (STATIC / "index.html").read_text(encoding="utf-8")
    html = html.replace('href="/static/app.css"', 'href="app.css"')
    html = html.replace('<script src="/static/app.js"></script>',
                        '<script src="config.js"></script>\n<script src="app.js"></script>')
    html = html.replace('<meta charset="utf-8">',
                        f'<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy" content="{CSP}">\n'
                        '<meta name="description" content="방화벽 정책 정리 도구 — 브라우저 안에서 중복·가려진 정책을 분석합니다. '
                        '파일은 업로드되지 않습니다.">', 1)
    assert "config.js" in html and "Content-Security-Policy" in html
    (OUT / "index.html").write_text(html, encoding="utf-8")
    (OUT / ".nojekyll").write_text("")
    size = sum(f.stat().st_size for f in OUT.rglob("*") if f.is_file())
    print(f"site/ built ({size / 1024:.0f} KB), deps: {', '.join(pins)}")


if __name__ == "__main__":
    main()
