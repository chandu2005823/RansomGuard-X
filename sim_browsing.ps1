while ($true) {
    Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15)
    Invoke-WebRequest -Uri "https://www.wikipedia.org" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 30)
}
