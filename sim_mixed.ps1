while ($true) {
    # File
    $f = "ransomguard_test_files\mixed_$((Get-Date).Ticks).txt"
    echo "Mixed" > $f
    # Net
    Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
    # Proc
    Start-Process notepad.exe
    Start-Sleep -Seconds 5
    Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
    
    Start-Sleep -Seconds (Get-Random -Minimum 15 -Maximum 45)
}
