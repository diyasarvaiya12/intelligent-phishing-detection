@echo off
title PhishGuard - Intelligent Phishing Detection System
echo =========================================================
echo  Starting PhishGuard Detection System
echo =========================================================
echo.

if exist "venv312\Scripts\python.exe" (
    venv312\Scripts\python.exe run.py
) else (
    python run.py
)

pause
