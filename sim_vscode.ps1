while ($true) {
    Start-Process -FilePath "notepad.exe" -ArgumentList "ransomguard_test_files\code.txt"
    Start-Sleep -Seconds 10
    Stop-Process -Name "notepad" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds (Get-Random -Minimum 15 -Maximum 45)
}
