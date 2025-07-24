# O365 Security Audit - Simple Working Version
param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId
)

Write-Host "Office 365 Security Audit - Simple Version" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow

# Reset session first
Write-Host "`nStep 1: Resetting session..." -ForegroundColor Cyan
Get-Module Microsoft.Graph*, ExchangeOnlineManagement, AzureAD | Remove-Module -Force -ErrorAction SilentlyContinue

# Load modules
Write-Host "`nStep 2: Loading modules..." -ForegroundColor Cyan
Import-Module ExchangeOnlineManagement -Force
Import-Module Microsoft.Graph.Authentication -Force  
Import-Module AzureAD -Force
Write-Host "Modules loaded successfully" -ForegroundColor Green

# Connect to Exchange Online
Write-Host "`nStep 3: Connecting to Exchange Online..." -ForegroundColor Cyan
Write-Host "Please complete authentication when prompted..." -ForegroundColor Yellow
try {
    Connect-ExchangeOnline -ShowBanner:$false
    $org = Get-OrganizationConfig
    Write-Host "SUCCESS: Connected to $($org.DisplayName)" -ForegroundColor Green
    $exchangeOK = $true
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $exchangeOK = $false
}

# Connect to Microsoft Graph
Write-Host "`nStep 4: Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "Please complete authentication when prompted..." -ForegroundColor Yellow
try {
    Connect-MgGraph -Scopes "Directory.Read.All" -TenantId $TenantId -NoWelcome
    Write-Host "SUCCESS: Connected to Microsoft Graph" -ForegroundColor Green
    $graphOK = $true
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $graphOK = $false
}

# Connect to Azure AD
Write-Host "`nStep 5: Connecting to Azure AD..." -ForegroundColor Cyan
Write-Host "Please complete authentication when prompted..." -ForegroundColor Yellow
try {
    Connect-AzureAD -TenantId $TenantId | Out-Null
    $tenant = Get-AzureADTenantDetail
    Write-Host "SUCCESS: Connected to $($tenant.DisplayName)" -ForegroundColor Green
    $azureOK = $true
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $azureOK = $false
}

# Summary
Write-Host "`n========== CONNECTION SUMMARY ==========" -ForegroundColor Magenta
if ($exchangeOK) {
    Write-Host "Exchange Online: CONNECTED" -ForegroundColor Green
} else {
    Write-Host "Exchange Online: FAILED" -ForegroundColor Red
}

if ($graphOK) {
    Write-Host "Microsoft Graph: CONNECTED" -ForegroundColor Green  
} else {
    Write-Host "Microsoft Graph: FAILED" -ForegroundColor Red
}

if ($azureOK) {
    Write-Host "Azure AD: CONNECTED" -ForegroundColor Green
} else {
    Write-Host "Azure AD: FAILED" -ForegroundColor Red
}

if ($exchangeOK -and $graphOK -and $azureOK) {
    Write-Host "`nALL SERVICES CONNECTED! Ready for audit." -ForegroundColor Green
    Write-Host "You can now run specific audit commands." -ForegroundColor Yellow
} else {
    Write-Host "`nSome connections failed. Check authentication." -ForegroundColor Red
}

Write-Host "`nConnections remain active for further use." -ForegroundColor Cyan
Write-Host "To disconnect all services later, run:" -ForegroundColor Gray
Write-Host "  Disconnect-ExchangeOnline -Confirm:`$false" -ForegroundColor Gray
Write-Host "  Disconnect-MgGraph" -ForegroundColor Gray  
Write-Host "  Disconnect-AzureAD" -ForegroundColor Gray
