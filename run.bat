@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 app.py
  exit /b %errorlevel%
)
where python >nul 2>nul
if %errorlevel%==0 (
  python app.py
  exit /b %errorlevel%
)
echo Python 3 tidak ditemukan. Instal Python 3 lalu jalankan run.bat kembali.
pause
