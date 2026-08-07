@echo off
title ANISAS Setup
color 0A
echo.
echo  ============================================
echo    ANISAS - Autonomous Network Intelligence
echo    Security Assessment System - Setup
echo  ============================================
echo.

REM Check Python
echo [1/4] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo.
    echo  [ERROR] Python not found!
    echo.
    echo  Install Python 3.10+ from: https://www.python.org/downloads/
    echo  IMPORTANT: Check "Add Python to PATH" during installation!
    echo.
    pause
    exit /b 1
)
python --version
echo.

REM Check pip
echo [2/4] Checking pip...
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo  [WARNING] pip not found. Installing pip...
    python -m ensurepip --default-pip
)
echo.

REM Install dependencies
echo [3/4] Installing dependencies (this may take 2-5 minutes)...
echo.
python -m pip install -r requirements.txt
if errorlevel 1 (
    color 0C
    echo.
    echo  [ERROR] Failed to install dependencies.
    echo  Try: python -m pip install --upgrade pip
    echo.
    pause
    exit /b 1
)
echo.

REM Verify
echo [4/4] Verifying installation...
python -c "import anisas; print('  ANISAS version:', anisas.__version__)"
python -c "import fastapi; print('  FastAPI version:', fastapi.__version__)"
python -c "import uvicorn; print('  Uvicorn version:', uvicorn.__version__)"
echo.

echo  ============================================
echo    SETUP COMPLETE!
echo  ============================================
echo.
echo  To start the dashboard:
echo    python -m anisas.dashboard
echo.
echo  Then open in browser:
echo    http://127.0.0.1:8000
echo.
echo  To access from other devices:
echo    python -m anisas.dashboard --host 0.0.0.0 --port 8000
echo  ============================================
echo.
pause
