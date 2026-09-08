@echo off
setlocal

echo ======================================================================
echo Test Drive Unlimited 2 Save Unpacker
echo ======================================================================

if "%~1"=="" (
    echo Usage:
    echo   Drag and drop a PLAYERSAVE folder or save file onto this script.
    echo   Or run: unpack_save.bat "path\to\PLAYERSAVE"
    echo.
    set /p "TARGET_PATH=Enter path to save folder or file: "
) else (
    set "TARGET_PATH=%~1"
)

if "%TARGET_PATH%"=="" (
    echo Error: No target path specified.
    pause
    exit /b 1
)

python "%~dp0tdu2_save_tool.py" unpack "%TARGET_PATH%" --raw

echo.
echo Operation complete.
pause
