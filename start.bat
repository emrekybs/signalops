@echo off
REM SignalOps — Windows tek tık kurulum + başlatma
cd /d "%~dp0"
where python >nul 2>nul || (echo Python bulunamadi. https://www.python.org/downloads/ adresinden kur. & pause & exit /b 1)
if not exist .venv (
  echo Sanal ortam olusturuluyor...
  python -m venv .venv || (echo venv olusturulamadi & pause & exit /b 1)
  .venv\Scripts\python -m pip install -q --upgrade pip
  .venv\Scripts\python -m pip install -q -r requirements.txt
)
if not exist data echo UYARI: data klasoru yok - kamera katmanlari canli OSM verisiyle calisir.
echo SignalOps baslatiliyor: http://localhost:8080
start "" cmd /c "timeout /t 35 >nul & start http://localhost:8080"
.venv\Scripts\python app_v2.py
pause
