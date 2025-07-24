# Office 365 Audit Suite Launcher
# Quick launcher for the unified audit script

Write-Host "Office 365 Security Audit Suite Launcher" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# Check if unified script exists
if (-not (Test-Path "O365-Unified-Audit.ps1")) {
    Write-Host "Error: O365-Unified-Audit.ps1 not found in current directory" -ForegroundColor Red
    exit 1
}

Write-Host "`nAvailable options:" -ForegroundColor Cyan
Write-Host "1. Run Unified Audit (Recommended)" -ForegroundColor White
Write-Host "2. Run with Tenant ID" -ForegroundColor White
Write-Host "3. Skip Connection (if already connected)" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Select option (1-3)"

switch ($choice) {
    "1" {
        Write-Host "Starting unified audit..." -ForegroundColor Yellow
        .\O365-Unified-Audit.ps1
    }
    "2" {
        $tenantId = Read-Host "Enter Tenant ID"
        Write-Host "Running unified audit with Tenant ID..." -ForegroundColor Yellow
        .\O365-Unified-Audit.ps1 -TenantId $tenantId
    }
    "3" {
        Write-Host "Running unified audit (skipping connection)..." -ForegroundColor Yellow
        .\O365-Unified-Audit.ps1 -SkipConnection
    }
    default {
        Write-Host "Invalid selection" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`nAudit launcher completed!" -ForegroundColor Green
