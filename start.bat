@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist .venv (
  echo [setup] 가상환경을 만들고 필요한 패키지를 설치합니다...
  python -m venv .venv || goto :err
  .venv\Scripts\python -m pip install -q -r requirements.txt || goto :err
)
.venv\Scripts\python run.py %*
goto :eof
:err
echo 설치에 실패했습니다. Python 3.10 이상이 설치되어 있는지 확인하세요.
pause
