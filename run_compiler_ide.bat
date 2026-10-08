@echo off
title Password Policy Compiler & AI Assistant
echo =======================================================
echo  Starting Password Policy Compiler & AI Assistant IDE
echo =======================================================
cd /d "%~dp0CODE"
start http://localhost:3000
node server.js
pause
