@echo off
cd /d "C:\SentinelForge TrueForge hackathon\sentinelforge"
echo [%date% %time%] starting TrueForge >> state\tf-task.log
node scripts\run-trueforge.mjs >> state\tf-task.log 2>&1
echo [%date% %time%] TrueForge exited with %errorlevel% >> state\tf-task.log
