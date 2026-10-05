while ($true) {
    Start-Process -FilePath "wordpad.exe"
    Start-Sleep -Seconds 20
    Stop-Process -Name "wordpad" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 60)
}
