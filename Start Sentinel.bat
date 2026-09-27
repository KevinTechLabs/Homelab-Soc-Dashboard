@echo off
rem Opens Sentinel in its own app window (no address bar) using Microsoft Edge, which ships with Windows.
set "APPDIR=%~dp0web"
start "" msedge --app="file:///%APPDIR:\=/%/index.html" --window-size=1280,860 --user-data-dir="%LOCALAPPDATA%\Sentinel\EdgeProfile"
