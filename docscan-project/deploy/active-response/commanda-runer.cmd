@echo off
REM Wazuh Active Response entry point. The Wazuh agent (execd) runs this file from
REM   C:\Program Files (x86)\ossec-agent\active-response\bin\
REM and passes the AR request as JSON on stdin. We hand stdin straight to the
REM PowerShell helper next to this file, which does all the checks and the work.
REM The agent runs this as SYSTEM, so the helper must stay strict (see commanda-runer.ps1).
setlocal
PowerShell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0commanda-runer.ps1"
exit /b %ERRORLEVEL%
