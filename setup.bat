@echo off
setlocal enabledelayedexpansion

set VENV_DIR=.venv

echo ==^> Setting up Glasswing Scanner...

:: Check Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python not found. Install Python 3.10+ from https://python.org and try again.
    exit /b 1
)

for /f "tokens=2 delims= " %%V in ('python --version 2^>^&1') do set PY_VERSION=%%V
echo     Python !PY_VERSION! detected

:: Create virtual environment
if not exist "%VENV_DIR%\" (
    echo ==^> Creating virtual environment...
    python -m venv %VENV_DIR%
    if %errorlevel% neq 0 (
        echo Error: Failed to create virtual environment.
        exit /b 1
    )
)

:: Activate and install
echo ==^> Installing dependencies...
call %VENV_DIR%\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo Error: Failed to activate virtual environment.
    exit /b 1
)

python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo Error: Dependency installation failed.
    exit /b 1
)

:: Set ANTHROPIC_API_KEY reminder
if not defined ANTHROPIC_API_KEY (
    if not exist ".env" (
        echo.
        echo [!] ANTHROPIC_API_KEY is not set.
        echo     Create a .env file with your key:
        echo       echo ANTHROPIC_API_KEY=sk-ant-... ^> .env
    )
)

echo.
echo Setup complete.
echo.
echo Next steps:
echo   Activate environment : %VENV_DIR%\Scripts\activate
echo   Run a CVE scan       : python glasswing.py cve --requirements requirements.txt
echo   Run a source scan    : python glasswing.py scan --target .
echo   View a report        : python glasswing.py report --input reports\cve_report.json

endlocal
