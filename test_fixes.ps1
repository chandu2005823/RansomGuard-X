
Start-Sleep -Seconds 2
echo "Start testing"
# B & D. Process start, DLL load
Start-Process notepad.exe
Start-Sleep -Seconds 2

# A. Network (TCP connection)
# Using PowerShell to fetch a web page
Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing | Out-Null
Start-Sleep -Seconds 2

# C. File
echo "Harmless file" > ransomguard_test_files\harmless_fix.txt

# B. Process close
Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue

echo "Testing complete"

