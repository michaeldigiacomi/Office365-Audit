# PowerShell Session Reset Script
# This script helps resolve function capacity overflow issues

Write-Host "PowerShell Session Reset for O365 Audit" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green

# Check current function count
$functionCount = (Get-ChildItem function:).Count
Write-Host "Current function count: $functionCount / 4096" -ForegroundColor Yellow

if ($functionCount -gt 3500) {
    Write-Host "Warning: Function count is approaching limit. Cleanup recommended." -ForegroundColor Red
} else {
    Write-Host "Function count is within safe limits." -ForegroundColor Green
}

# Remove problematic modules
Write-Host "`nRemoving potentially problematic modules..." -ForegroundColor Cyan
$modulesToRemove = @(
    "Microsoft.Graph*",
    "ExchangeOnlineManagement", 
    "AzureAD*",
    "MSOnline"
)

foreach ($modulePattern in $modulesToRemove) {
    $modules = Get-Module -Name $modulePattern
    if ($modules) {
        Write-Host "Removing modules matching: $modulePattern" -ForegroundColor Yellow
        $modules | Remove-Module -Force -ErrorAction SilentlyContinue
        Write-Host "Removed $($modules.Count) module(s)" -ForegroundColor Green
    }
}

# Clear variables
Write-Host "`nClearing O365-related variables..." -ForegroundColor Cyan
Get-Variable -Name "*graph*", "*exchange*", "*azure*", "*tenant*" -ErrorAction SilentlyContinue | Remove-Variable -Force -ErrorAction SilentlyContinue

# Force garbage collection
Write-Host "Running garbage collection..." -ForegroundColor Cyan
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

# Final function count
$newFunctionCount = (Get-ChildItem function:).Count
Write-Host "`nFunction count after cleanup: $newFunctionCount / 4096" -ForegroundColor Yellow
Write-Host "Functions freed: $($functionCount - $newFunctionCount)" -ForegroundColor Green

Write-Host "`nSession reset complete!" -ForegroundColor Green
Write-Host "You can now run the O365 audit scripts safely." -ForegroundColor Yellow
