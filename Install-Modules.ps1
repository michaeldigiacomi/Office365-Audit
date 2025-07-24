Write-Host "Office 365 Security Audit - Module Installation" 
Write-Host "===============================================" 

# Set TLS 1.2 for PowerShell Gallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$modules = @(
    "ExchangeOnlineManagement",
    "Microsoft.Graph", 
    "AzureAD"
)

foreach ($moduleName in $modules) {
    Write-Host "`nInstalling $moduleName..."
        Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser
        Write-Host "Successfully installed $moduleName" 
    }
    catch {
        Write-Host "Failed to install $moduleName : $($_.Exception.Message)"
    }
}

Write-Host "`nVerifying installations..." 
foreach ($moduleName in $modules) {
    $module = Get-Module -ListAvailable -Name $moduleName
    if ($module) {
        Write-Host "✓ $moduleName is installed" 
    } else {
        Write-Host "✗ $moduleName is NOT installed"
}

Write-Host "`nModule installation complete!"