@echo off
REM PQNodium - dev.cmd
REM Auto-detect and run dev build.

if defined PQNODIUM_SHELL (
    goto :run
)

where pwsh >nul 2>&1
if %errorlevel%==0 (
    set "PQNODIUM_SHELL=pwsh"
) else (
    where bash >nul 2>&1
    if %errorlevel%==0 (
        set "PQNODIUM_SHELL=bash"
    ) else (
        echo Error: neither pwsh nor bash found in PATH
        exit /b 1
    )
)

:run
if "%PQNODIUM_SHELL%"=="pwsh" (
    pwsh -File "%~dp0win\dev.ps1" %*
) else (
    bash "%~dp0linux\dev.sh" %*
)
