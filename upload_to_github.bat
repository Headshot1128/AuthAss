@echo off
setlocal enabledelayedexpansion
title GitHub Uploader - AuthAss

:: Change directory to where this batch file is located
cd /d "%~dp0"

echo =======================================================
echo          AUTH-main - GitHub Auto-Sync Script
echo          Target: https://github.com/Headshot1128/AuthAss.git
echo =======================================================
echo.

:: 1. Ensure Git is in PATH
where git >nul 2>&1
if errorlevel 1 (
    echo [*] Git not found in PATH, searching common install locations...
    if exist "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd\git.exe" (
        set "PATH=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd;!PATH!"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd\git.exe" (
        set "PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd;!PATH!"
    ) else if exist "C:\Program Files\Git\cmd\git.exe" (
        set "PATH=C:\Program Files\Git\cmd;!PATH!"
    ) else if exist "C:\Program Files (x86)\Git\cmd\git.exe" (
        set "PATH=C:\Program Files (x86)\Git\cmd;!PATH!"
    ) else if exist "%LOCALAPPDATA%\Programs\Git\cmd\git.exe" (
        set "PATH=%LOCALAPPDATA%\Programs\Git\cmd;!PATH!"
    )
)

where git >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git could not be found! Please install Git from https://git-scm.com/
    pause
    exit /b 1
)

:: 2. Check and configure git user if missing
git config user.name >nul 2>&1
if errorlevel 1 (
    echo [*] Git user.name not configured. Setting default to Headshot1128...
    git config --global user.name "Headshot1128"
)

git config user.email >nul 2>&1
if errorlevel 1 (
    echo [*] Git user.email not configured. Setting default...
    git config --global user.email "Headshot1128@users.noreply.github.com"
)

:: 3. Initialize Git repository if not already initialized
if not exist ".git" (
    echo [*] Initializing new Git repository...
    git init
    git branch -M main
    git remote add origin https://github.com/Headshot1128/AuthAss.git
) else (
    :: Verify remote origin
    git remote get-url origin >nul 2>&1
    if errorlevel 1 (
        echo [*] Adding remote origin...
        git remote add origin https://github.com/Headshot1128/AuthAss.git
    ) else (
        git remote set-url origin https://github.com/Headshot1128/AuthAss.git
    )
    git branch -M main >nul 2>&1
)

:: 4. Prompt for custom commit message (optional)
echo.
set "COMMIT_MSG="
set /p "COMMIT_MSG=Enter commit message (Press Enter for default timestamp): "
if "!COMMIT_MSG!"=="" (
    set "COMMIT_MSG=Update: %date% %time%"
)

:: 5. Stage and Commit
echo.
echo [*] Staging all files...
git add -A

git diff --cached --quiet
if errorlevel 1 (
    echo [*] Committing changes...
    git commit -m "!COMMIT_MSG!"
) else (
    echo [*] No new changes to commit.
)

:: 6. Push to GitHub
echo.
echo [*] Pushing to GitHub (main branch)...
git push -u origin main

if errorlevel 1 (
    echo.
    echo [!] Push failed. Remote repository might contain commits not present locally.
    echo [*] Attempting to pull with rebase first...
    git pull --rebase origin main
    echo [*] Retrying push...
    git push -u origin main
)

if errorlevel 1 (
    echo.
    echo =======================================================
    echo [ERROR] Push failed. 
    echo Please make sure:
    echo 1. You have access rights to Headshot1128/AuthAss
    echo 2. You are logged into GitHub (Personal Access Token or Credential Manager)
    echo =======================================================
) else (
    echo.
    echo =======================================================
    echo [SUCCESS] Successfully uploaded to GitHub!
    echo =======================================================
)

echo.
pause
