
Start-Process notepad.exe
Start-Sleep -Seconds 15
Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 20

