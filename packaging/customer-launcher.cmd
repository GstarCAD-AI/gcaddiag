@echo off
setlocal DisableDelayedExpansion
set "GCADDIAG_ROOT=%~dp0gcaddiag"
set "GCADDIAG_CASE=%~1"
if not defined GCADDIAG_CASE set "GCADDIAG_CASE=%~dp0cases\customer-%RANDOM%-%RANDOM%"
echo Collecting local diagnostics. No product settings will be changed.
echo A report and redacted support ZIP will be prepared; nothing is uploaded.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -File "%GCADDIAG_ROOT%\scripts\gcaddiag.ps1" -Action Scan -Profile Crash -Symptom "Customer crash investigation" -Output "%GCADDIAG_CASE%"
if errorlevel 1 goto failed
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -File "%GCADDIAG_ROOT%\scripts\gcaddiag.ps1" -Action Export -Case "%GCADDIAG_CASE%" -Output "%GCADDIAG_CASE%-redacted.zip"
if errorlevel 1 goto failed
echo.
echo Report: "%GCADDIAG_CASE%\report.md"
echo Review before sharing: "%GCADDIAG_CASE%-redacted.zip"
echo Keep raw case.json, dumps, and originals local unless separately reviewed.
if "%~1"=="" pause
exit /b 0
:failed
echo.
echo Collection/export did not complete. Preserve the displayed policy or access error.
echo Do not bypass execution policy or enterprise controls to run this kit.
if "%~1"=="" pause
exit /b 2
