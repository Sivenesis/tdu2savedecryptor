@echo off
setlocal

echo ======================================================================
echo Test Drive Unlimited 2 Save Repacker
echo ======================================================================

if "%~1"=="" (
    echo Usage:
    echo   Drag and drop a folder containing JSON save files onto this script.
    echo   Or run: pack_save.bat "path\to\folder_or_json"
    echo.
    set /p "TARGET_PATH=Enter path to folder or JSON file: "
) else (
    set "TARGET_PATH=%~1"
)

if "%TARGET_PATH%"=="" (
    echo Error: No target path specified.
    pause
    exit /b 1
)

python "%~dp0tdu2_save_tool.py" pack "%TARGET_PATH%"

echo.
echo Operation complete.
pause
