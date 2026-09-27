@echo off
rem Adds a Sentinel shortcut with its own icon to your Desktop and Start menu.
set "APPDIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$app = '%APPDIR%'.TrimEnd('\');" ^
  "$edge = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe' -ErrorAction SilentlyContinue).'(default)';" ^
  "if (-not $edge) { $edge = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe' -ErrorAction SilentlyContinue).'(default)' };" ^
  "if (-not $edge) { Write-Host 'Microsoft Edge was not found.'; exit 1 };" ^
  "$url = 'file:///' + ($app -replace '\\','/') + '/web/index.html';" ^
  "$profile = Join-Path $env:LOCALAPPDATA 'Sentinel\EdgeProfile';" ^
  "$ws = New-Object -ComObject WScript.Shell;" ^
  "foreach ($dir in @([Environment]::GetFolderPath('Desktop'), (Join-Path ([Environment]::GetFolderPath('Programs')) ''))) {" ^
  "  $s = $ws.CreateShortcut((Join-Path $dir 'Sentinel.lnk'));" ^
  "  $s.TargetPath = $edge;" ^
  "  $s.Arguments = '--app=\"' + $url + '\" --window-size=1280,860 --user-data-dir=\"' + $profile + '\"';" ^
  "  $s.IconLocation = (Join-Path $app 'web\icons\icon.ico');" ^
  "  $s.Description = 'Sentinel cyber command center';" ^
  "  $s.Save() };" ^
  "Write-Host 'Sentinel shortcuts added to your Desktop and Start menu.'"
pause
