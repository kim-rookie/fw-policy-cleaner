"""방화벽 정책 정리 도구 실행: python run.py  →  브라우저가 자동으로 열린다."""
import argparse
import socket
import threading
import webbrowser

from fwclean.web.app import app


def free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("사용 가능한 포트가 없습니다.")


def main():
    ap = argparse.ArgumentParser(description="방화벽 정책 정리 도구")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    port = free_port(args.port)
    url = f"http://127.0.0.1:{port}/"
    print(f"방화벽 정책 정리 도구: {url}  (종료: Ctrl+C)")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    # 외부 노출 방지를 위해 로컬 루프백에만 바인딩
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
