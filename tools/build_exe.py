"""Windows 실행 파일(exe) 빌드.

    pip install pyinstaller
    python tools/build_exe.py

결과: dist/fw-policy-cleaner.exe (단일 파일, Python 설치 불필요)
공개 배포본은 GitHub Actions(.github/workflows/release.yml)에서 빌드한다.
"""
import os
import sys
from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from fwclean import __version__  # noqa: E402

os.chdir(ROOT)
PyInstaller.__main__.run([
    "run.py",
    "--name", "fw-policy-cleaner",
    "--onefile",
    "--console",                      # 실행 중임을 보여주고 Ctrl+C / 창 닫기로 종료
    "--add-data", f"fwclean/web/static{os.pathsep}fwclean/web/static",
    "--exclude-module", "tkinter",
    "--exclude-module", "pytest",
    "--clean",
    "--noconfirm",
])
print(f"\nbuilt dist/fw-policy-cleaner.exe (v{__version__})")
