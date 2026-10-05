while ($true) {
    $f1 = "ransomguard_test_files\test_file_$((Get-Date).Ticks).txt"
    $f2 = "ransomguard_test_files\test_file_$((Get-Date).Ticks)_renamed.txt"
    echo "Harmless data" > $f1
    Start-Sleep -Seconds 2
    Add-Content -Path $f1 -Value "More harmless data"
    Start-Sleep -Seconds 5
    Rename-Item -Path $f1 -NewName $f2 -ErrorAction SilentlyContinue
    Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 30)
}
