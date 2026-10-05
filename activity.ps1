
for ($i=0; $i -lt 12; $i++) {
    Start-Process notepad.exe
    Start-Sleep -Seconds 2
    Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
    ping google.com -n 2
    echo "test" > "ransomguard_test_files\doc_$i.txt"
    Start-Sleep -Seconds 3
}
