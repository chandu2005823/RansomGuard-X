
for ($i=0; $i -lt 10; $i++) {
    Start-Process notepad.exe
    Start-Sleep -Seconds 2
    Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri "http://google.com" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 5
}

