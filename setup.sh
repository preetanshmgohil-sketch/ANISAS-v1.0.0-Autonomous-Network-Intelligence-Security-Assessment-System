#!/bin/bash
clear
echo ""
echo "  ============================================"
echo "    ANISAS - Autonomous Network Intelligence"
echo "    Security Assessment System - Setup"
echo "  ============================================"
echo ""

# Check Python3
echo "[1/4] Checking Python3..."
if ! command -v python3 &> /dev/null; then
    echo ""
    echo "  [ERROR] Python3 not found!"
    echo ""
    echo "  Install Python3:"
    echo "    Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "    macOS: brew install python3"
    echo "    Fedora: sudo dnf install python3"
    echo ""
    exit 1
fi
python3 --version
echo ""

# Check pip
echo "[2/4] Checking pip3..."
if ! command -v pip3 &> /dev/null; then
    echo "  [WARNING] pip3 not found. Installing..."
    sudo apt install python3-pip 2>/dev/null || brew install pip 2>/dev/null
fi
echo ""

# Install dependencies
echo "[3/4] Installing dependencies (this may take 2-5 minutes)..."
echo ""
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo ""
    echo "  [ERROR] Failed to install dependencies."
    echo "  Try: pip3 install --upgrade pip"
    echo ""
    exit 1
fi
echo ""

# Verify
echo "[4/4] Verifying installation..."
python3 -c "import anisas; print('  ANISAS version:', anisas.__version__)"
python3 -c "import fastapi; print('  FastAPI version:', fastapi.__version__)"
python3 -c "import uvicorn; print('  Uvicorn version:', uvicorn.__version__)"
echo ""

echo "  ============================================"
echo "    SETUP COMPLETE!"
echo "  ============================================"
echo ""
echo "  To start the dashboard:"
echo "    python3 -m anisas.dashboard"
echo ""
echo "  Then open in browser:"
echo "    http://127.0.0.1:8000"
echo ""
echo "  To access from other devices:"
echo "    python3 -m anisas.dashboard --host 0.0.0.0 --port 8000"
echo "  ============================================"
