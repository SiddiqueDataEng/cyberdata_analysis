@echo off
title CyberData Analytics Platform
color 0A

echo.
echo  ================================================================
echo   CYBERSECURITY DATA ENGINEERING - ANALYTICS PLATFORM
echo  ================================================================
echo.

cd /d E:\Cyberdata\analytics

for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":8501 "') do taskkill /PID %%a /F >nul 2>&1
timeout /t 2 /nobreak >nul

echo  [OK] Starting at http://localhost:8501
echo.

start "" /b cmd /c "timeout /t 5 /nobreak >nul && start http://localhost:8501"

streamlit run app_new.py ^
  --server.port 8501 ^
  --server.headless false ^
  --server.enableCORS false ^
  --server.enableXsrfProtection false ^
  --browser.gatherUsageStats false

pause
