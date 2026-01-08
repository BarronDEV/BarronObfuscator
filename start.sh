#!/bin/bash
cd "$(dirname "$0")"

# Check if JAR exists
if [ ! -f "build/libs/Barron-Obfuscator-2.0.0.jar" ]; then
    echo "Building project..."
    ./gradlew jar --no-daemon
fi

# Start without terminal (nohup + background)
nohup java -jar build/libs/Barron-Obfuscator-2.0.0.jar > /dev/null 2>&1 &
disown
