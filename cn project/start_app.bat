@echo off
title AI Network Traffic Analyzer & Congestion Prediction
color 0b

echo ======================================================================
echo    AI Network Traffic Analyzer ^& Congestion Prediction System
echo ======================================================================
echo.

:: 1. Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0c
    echo [ERROR] Python is not found in your system PATH!
    echo Please install Python 3.10+ from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [+] Python found:
python --version
echo.

:: 2. Check for virtual environment
if exist .venv\Scripts\activate.bat (
    echo [*] Activating local virtual environment (.venv)...
    call .venv\Scripts\activate.bat
) else if exist venv\Scripts\activate.bat (
    echo [*] Activating local virtual environment (venv)...
    call venv\Scripts\activate.bat
) else (
    echo [*] No local venv folder detected; using global Python environment.
)
echo.

:: 3. Check for trained model
if not exist "models\congestion_rf_model.joblib" (
    echo [*] Model file not found. Generating bootstrap dataset and training initial model...
    python train_model.py
    if %errorlevel% neq 0 (
        color 0c
        echo [ERROR] Model initialization failed!
        pause
        exit /b 1
    )
    echo [+] Model initialized successfully!
    echo.
)

:: 4. Start the application
echo ======================================================================
echo  Server is launching on: http://127.0.0.1:5000
echo  Press Ctrl+C to stop the server.
echo ======================================================================
echo.

python app.py

if %errorlevel% neq 0 (
    color 0c
    echo.
    echo [ERROR] Application terminated with an error.
    pause
)
