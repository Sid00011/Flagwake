@echo off
rem Start the Flagwake page: set up a private Python environment the first time, then run
rem "flagwake ui", which opens the page in your browser. Double-click this file.
setlocal
cd /d "%~dp0"
set "VENV=.flagwake-venv"
set "CHECK=import sys, pathlib, importlib.metadata as m, tomllib; src = sys.argv[1]; v = pathlib.Path(src).name.split('-')[1] if src.endswith('.whl') else tomllib.load(open('pyproject.toml', 'rb'))['project']['version']; sys.exit(0 if m.version('flagwake') == v else 1)"

rem Python 3.11 or newer: the py launcher first, then python on PATH.
set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul && set "PY=python"
if not defined PY (
  echo.
  echo Flagwake needs Python 3.11 or newer, and it was not found on this computer.
  echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH"
  echo during the installation, then double-click this file again.
  echo.
  pause
  exit /b 1
)

rem From a copy of the source, install it; from a folder with the package file, install that.
set "SRC="
if exist pyproject.toml (set "SRC=.") else (for %%W in (dist\flagwake-*.whl) do set "SRC=%%W")
if not defined SRC (
  echo No Flagwake package was found next to this file.
  pause
  exit /b 1
)

if not exist "%VENV%\Scripts\python.exe" (
  echo Setting up Flagwake the first time, about a minute...
  %PY% -m venv "%VENV%" || goto failed
)
"%VENV%\Scripts\python.exe" -c "%CHECK%" "%SRC%" >nul 2>nul
if errorlevel 1 (
  echo Installing Flagwake...
  "%VENV%\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check "%SRC%" || goto failed
)
"%VENV%\Scripts\flagwake.exe" ui %*
exit /b %errorlevel%

:failed
echo.
echo The setup did not finish. Setting up from the source needs an internet connection once,
echo to fetch the build tool. If it keeps failing, delete the folder %VENV% and try again.
pause
exit /b 1
