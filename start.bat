@echo off
title Barron License Manager
cd /d "%~dp0"

REM Check if JAR exists
if not exist "build\libs\Barron-Obfuscator-2.0.0.jar" (
    echo Building project...
    call gradlew.bat jar --no-daemon
    if %ERRORLEVEL% NEQ 0 (
        echo Build failed!
        pause
        exit /b
    )
)

REM Start with hidden console
start javaw -Xmx2G -jar build\libs\Barron-Obfuscator-2.0.0.jar
