
$endtime = (Get-Date).AddMinutes(60)

while ((Get-Date) -lt $endtime) {
    # 1. Start some processes
    Start-Process notepad.exe
    $wordpad = Start-Process wordpad.exe -PassThru
    
    # 2. Network activity (Browser/Web requests)
    Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
    Invoke-WebRequest -Uri "https://www.microsoft.com" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
    
    # 3. File Operations
    $file1 = "ransomguard_test_files\benign_test_$((Get-Date).Ticks).txt"
    $file2 = "ransomguard_test_files\benign_renamed_$((Get-Date).Ticks).txt"
    echo "This is a harmless test file." > $file1
    Start-Sleep -Seconds 2
    Add-Content -Path $file1 -Value "Adding some more text to modify it."
    Start-Sleep -Seconds 1
    Rename-Item -Path $file1 -NewName $file2
    Start-Sleep -Seconds 1
    Remove-Item -Path $file2 -ErrorAction SilentlyContinue
    
    # 4. Wait
    Start-Sleep -Seconds 10
    
    # 5. Process termination
    Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
    if ($wordpad) {
        Stop-Process -Id $wordpad.Id -Force -ErrorAction SilentlyContinue
    }
    
    # 6. Wait before next loop
    Start-Sleep -Seconds 15
}
echo "Simulation complete."

