@echo off
title Barron License Manager
cd /d "%~dp0"

REM Check if JAR exists
if not exist "build\libs\Barron-Obfuscator-2.0.0.jar" (
    echo Building project...
    call gradlew.bat jar --no-daemon
)

REM Start without CMD window using javaw
start "" javaw -jar build\libs\Barron-Obfuscator-2.0.0.jar
