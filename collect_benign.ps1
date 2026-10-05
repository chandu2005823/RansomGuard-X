param (
    [int]$DurationMinutes = 60
)

$Scenarios = @(
    "benign_vscode_01"
    "benign_browser_01"
    "benign_fileops_01"
    "benign_python_01"
    "benign_java_01"
    "benign_documents_01"
    "benign_git_01"
    "benign_mixed_01"
)

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "   RANSOMGUARD-X BENIGN COLLECTION    " -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Select a collection scenario:"
for ($i = 0; $i -lt $Scenarios.Length; $i++) {
    Write-Host "[$($i + 1)] $($Scenarios[$i])"
}
Write-Host "[0] Custom Session Name"
Write-Host ""

$selection = Read-Host "Enter your choice (0-$($Scenarios.Length))"

if ($selection -eq '0') {
    $SessionName = Read-Host "Enter custom session name"
} elseif ([int]$selection -gt 0 -and [int]$selection -le $Scenarios.Length) {
    $SessionName = $Scenarios[[int]$selection - 1]
} else {
    Write-Host "Invalid selection. Exiting." -ForegroundColor Red
    exit
}

Write-Host ""
$customDuration = Read-Host "Enter duration in minutes (Default: $DurationMinutes)"
if ([string]::IsNullOrWhiteSpace($customDuration) -eq $false) {
    $DurationMinutes = [int]$customDuration
}

Write-Host "`nStarting collection for '$SessionName' over $DurationMinutes minutes..." -ForegroundColor Green
Write-Host "Please perform the relevant activities now. Do not close this window." -ForegroundColor Yellow
Write-Host ""

python collect_benign_live.py $DurationMinutes $SessionName
