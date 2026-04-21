#!/bin/bash
cd "$(dirname "$0")"

# Check if JAR exists
if [ ! -f "build/libs/Barron-Obfuscator-2.0.0.jar" ]; then
    echo "Building project..."
    # Ensure gradlew is executable
    chmod +x gradlew
    ./gradlew jar --no-daemon
fi

# CLI Mode if args provided
if [ $# -gt 0 ]; then
    java -jar build/libs/Barron-Obfuscator-2.0.0.jar "$@"
else
    # GUI Mode for Linux/RDP
    echo "Starting Barron Obfuscator (GUI)..."
    
    # Fix X11 Permissions
    [ -z "$XAUTHORITY" ] && export XAUTHORITY=$HOME/.Xauthority
    [ -z "$DISPLAY" ] && export DISPLAY=:0

    # Start with Software Rendering (fixes RDP crash) & logging to file
    nohup java -Dprism.order=sw -jar build/libs/Barron-Obfuscator-2.0.0.jar >> startup.log 2>&1 &
    
    echo "Started! Logs: startup.log (PID: $!)"
fi

