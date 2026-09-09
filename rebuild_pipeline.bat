@echo off
title Rebuild Analytics Pipeline
color 0B

echo.
echo  ===============================================================
echo   REBUILD PIPELINE - Regenerate Warehouse + All Marts
echo  ===============================================================
echo.

cd /d E:\Cyberdata

python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found.
    pause
    exit /b 1
)

echo  [RUNNING] ETL + Analytical Engineering...
echo.
python analytics\run_pipeline.py

if errorlevel 1 (
    echo.
    echo  [ERROR] Pipeline failed. Check errors above.
    pause
    exit /b 1
)

echo.
echo  [DONE] Pipeline complete. Run run_dashboard.bat to launch.
echo.
pause
