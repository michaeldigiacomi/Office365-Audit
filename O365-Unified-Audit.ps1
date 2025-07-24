# Office 365 Security Audit - Unified Efficient Script
# Single script that collects data once and performs all analyses
# Eliminates redundant API calls for maximum efficiency

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    [Parameter(Mandatory=$false)]
    [switch]$SkipConnection
)

# Global data collections - populated once
$Script:AllUsers = @()
$Script:AllGroups = @()
$Script:AllServicePrincipals = @()
$Script:AllApplications = @()
$Script:AllDirectoryRoles = @()
$Script:AllRoleAssignments = @()
$Script:AllDevices = @()
$Script:AllDomains = @()
$Script:AllTransportRules = @()
$Script:AllMailboxes = @()
$Script:DataCollected = $false
$Script:StartTime = Get-Date

function Show-Banner {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "      OFFICE 365 UNIFIED SECURITY AUDIT - EFFICIENT v3.0" -ForegroundColor Green
    Write-Host "           Single Data Collection + Multi-Analysis" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
}

function Reset-PowerShellSession {
    Write-Host "Optimizing PowerShell session..." -ForegroundColor Yellow
    
    $functionsBefore = (Get-ChildItem function:).Count
    
    # Remove modules that might cause function overflow
    $modulesToRemove = @("Microsoft.Graph", "ExchangeOnlineManagement", "AzureAD")
    foreach ($module in $modulesToRemove) {
        if (Get-Module -Name $module) {
            Remove-Module -Name $module -Force -ErrorAction SilentlyContinue
        }
    }
    
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    
    $functionsAfter = (Get-ChildItem function:).Count
    Write-Host "Session optimized. Functions: $functionsBefore -> $functionsAfter" -ForegroundColor Green
}

function Connect-AllServices {
    param([string]$TenantId)
    
    if (-not $TenantId) {
        $TenantId = Read-Host "Enter your Tenant ID"
    }
    
    Write-Host "`nConnecting to Office 365 Services..." -ForegroundColor Yellow
    Write-Host "Tenant ID: $TenantId" -ForegroundColor Cyan
    
    try {
        Reset-PowerShellSession
        
        # Load essential modules only
        Write-Host "Loading essential modules..." -ForegroundColor Yellow
        
        Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
        Import-Module AzureAD -Force -ErrorAction Stop
        Import-Module Microsoft.Graph.Authentication -Force -ErrorAction Stop
        
        # Connect to services
        Write-Host "Connecting to Exchange Online..." -ForegroundColor Gray
        Connect-ExchangeOnline -ShowBanner:$false
        
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Gray
        Connect-MgGraph -Scopes "Directory.Read.All,Application.Read.All,User.Read.All,Group.Read.All" -TenantId $TenantId
        
        Write-Host "Connecting to Azure AD..." -ForegroundColor Gray
        Connect-AzureAD -TenantId $TenantId
        
        Write-Host "All services connected successfully!" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "Connection error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Collect-AllData {
    if ($Script:DataCollected) {
        Write-Host "Data already collected. Using cached data." -ForegroundColor Green
        return
    }
    
    Write-Host "`n=== COLLECTING ALL DATA (ONE-TIME OPERATION) ===" -ForegroundColor Magenta
    $dataStartTime = Get-Date
    
    # Collect Users
    Write-Host "Collecting all users..." -ForegroundColor Yellow
    try {
        $Script:AllUsers = Get-AzureADUser -All $true
        Write-Host "  Collected $($Script:AllUsers.Count) users" -ForegroundColor Green
    } catch {
        Write-Host "  Error collecting users: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Collect Groups
    Write-Host "Collecting all groups..." -ForegroundColor Yellow
    try {
        $Script:AllGroups = Get-AzureADGroup -All $true
        Write-Host "  Collected $($Script:AllGroups.Count) groups" -ForegroundColor Green
    } catch {
        Write-Host "  Error collecting groups: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Collect Service Principals
    Write-Host "Collecting all service principals..." -ForegroundColor Yellow
    try {
        $Script:AllServicePrincipals = Get-AzureADServicePrincipal -All $true
        Write-Host "  Collected $($Script:AllServicePrincipals.Count) service principals" -ForegroundColor Green
    } catch {
        Write-Host "  Error collecting service principals: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Collect Applications
    Write-Host "Collecting all applications..." -ForegroundColor Yellow
    try {
        $Script:AllApplications = Get-AzureADApplication -All $true
        Write-Host "  Collected $($Script:AllApplications.Count) applications" -ForegroundColor Green
    } catch {
        Write-Host "  Error collecting applications: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Collect Directory Roles and Assignments
    Write-Host "Collecting directory roles and assignments..." -ForegroundColor Yellow
    try {
        $Script:AllDirectoryRoles = Get-AzureADDirectoryRole
        Write-Host "  Collected $($Script:AllDirectoryRoles.Count) directory roles" -ForegroundColor Green
        
        # Collect all role assignments
        foreach ($role in $Script:AllDirectoryRoles) {
            try {
                $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
                foreach ($member in $members) {
                    $Script:AllRoleAssignments += [PSCustomObject]@{
                        RoleName = $role.DisplayName
                        RoleId = $role.ObjectId
                        MemberName = $member.DisplayName
                        MemberType = $member.ObjectType
                        MemberObjectId = $member.ObjectId
                        MemberUPN = $member.UserPrincipalName
                        AccountEnabled = $member.AccountEnabled
                        MemberAppId = $member.AppId
                    }
                }
            } catch {
                Write-Host "    Warning: Could not get members for role $($role.DisplayName)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Collected $($Script:AllRoleAssignments.Count) role assignments" -ForegroundColor Green
    } catch {
        Write-Host "  Error collecting roles: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Collect Devices
    Write-Host "Collecting all devices..." -ForegroundColor Yellow
    try {
        $Script:AllDevices = Get-AzureADDevice -All $true
        Write-Host "  Collected $($Script:AllDevices.Count) devices" -ForegroundColor Green
    } catch {
        Write-Host "  Error collecting devices: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Collect Domains
    Write-Host "Collecting domain information..." -ForegroundColor Yellow
    try {
        $Script:AllDomains = Get-AzureADDomain
        Write-Host "  Collected $($Script:AllDomains.Count) domains" -ForegroundColor Green
    } catch {
        Write-Host "  Error collecting domains: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Collect Exchange Data
    Write-Host "Collecting Exchange transport rules..." -ForegroundColor Yellow
    try {
        $Script:AllTransportRules = Get-TransportRule
        Write-Host "  Collected $($Script:AllTransportRules.Count) transport rules" -ForegroundColor Green
    } catch {
        Write-Host "  Error collecting transport rules: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "Collecting mailbox information (first 100)..." -ForegroundColor Yellow
    try {
        $Script:AllMailboxes = Get-Mailbox -ResultSize 100
        Write-Host "  Collected $($Script:AllMailboxes.Count) mailboxes" -ForegroundColor Green
    } catch {
        Write-Host "  Error collecting mailboxes: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    $dataEndTime = Get-Date
    $dataCollectionTime = $dataEndTime - $dataStartTime
    
    $Script:DataCollected = $true
    Write-Host "`nData collection completed in $($dataCollectionTime.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Green
    Write-Host "Ready for analysis..." -ForegroundColor Cyan
}

function Analyze-Users {
    Write-Host "`n=== USER ANALYSIS ===" -ForegroundColor Blue
    
    $analysis = @{
        TotalUsers = $Script:AllUsers.Count
        EnabledUsers = ($Script:AllUsers | Where-Object { $_.AccountEnabled -eq $true }).Count
        DisabledUsers = ($Script:AllUsers | Where-Object { $_.AccountEnabled -eq $false }).Count
        GuestUsers = ($Script:AllUsers | Where-Object { $_.UserType -eq "Guest" }).Count
        ExternalUsers = ($Script:AllUsers | Where-Object { $_.UserPrincipalName -like "*#EXT#*" }).Count
        AdminUsers = ($Script:AllRoleAssignments | Where-Object { $_.MemberType -eq "User" } | Select-Object -Unique MemberObjectId).Count
        RecentUsers = @()
    }
    
    # Find recently created users (last 7 days)
    $recentDate = (Get-Date).AddDays(-7)
    foreach ($user in $Script:AllUsers) {
        try {
            if ($user.ExtensionProperty.createdDateTime) {
                $createdDate = [DateTime]$user.ExtensionProperty.createdDateTime
                if ($createdDate -ge $recentDate) {
                    $analysis.RecentUsers += $user
                }
            }
        } catch {}
    }
    
    # Display results
    Write-Host "Total Users: $($analysis.TotalUsers)" -ForegroundColor White
    Write-Host "  Enabled: $($analysis.EnabledUsers)" -ForegroundColor Green
    Write-Host "  Disabled: $($analysis.DisabledUsers)" -ForegroundColor Yellow
    Write-Host "  Guest Users: $($analysis.GuestUsers)" -ForegroundColor Cyan
    Write-Host "  External Users: $($analysis.ExternalUsers)" -ForegroundColor Cyan
    Write-Host "  Admin Users: $($analysis.AdminUsers)" -ForegroundColor Red
    Write-Host "  Recent Users (7 days): $($analysis.RecentUsers.Count)" -ForegroundColor Magenta
    
    return $analysis
}

function Analyze-Groups {
    Write-Host "`n=== GROUP ANALYSIS ===" -ForegroundColor Blue
    
    $analysis = @{
        TotalGroups = $Script:AllGroups.Count
        SecurityGroups = ($Script:AllGroups | Where-Object { $_.SecurityEnabled -eq $true }).Count
        MailEnabledGroups = ($Script:AllGroups | Where-Object { $_.MailEnabled -eq $true }).Count
        Office365Groups = ($Script:AllGroups | Where-Object { $_.GroupTypes -contains "Unified" }).Count
        PrivilegedGroups = ($Script:AllRoleAssignments | Where-Object { $_.MemberType -eq "Group" } | Select-Object -Unique MemberObjectId).Count
    }
    
    Write-Host "Total Groups: $($analysis.TotalGroups)" -ForegroundColor White
    Write-Host "  Security Groups: $($analysis.SecurityGroups)" -ForegroundColor Green
    Write-Host "  Mail Enabled: $($analysis.MailEnabledGroups)" -ForegroundColor Cyan
    Write-Host "  Office 365 Groups: $($analysis.Office365Groups)" -ForegroundColor Yellow
    Write-Host "  Privileged Groups: $($analysis.PrivilegedGroups)" -ForegroundColor Red
    
    return $analysis
}

function Analyze-ServicePrincipals {
    Write-Host "`n=== SERVICE PRINCIPAL ANALYSIS ===" -ForegroundColor Blue
    
    $analysis = @{
        TotalServicePrincipals = $Script:AllServicePrincipals.Count
        MicrosoftApps = ($Script:AllServicePrincipals | Where-Object { $_.PublisherName -eq "Microsoft Corporation" }).Count
        ThirdPartyApps = ($Script:AllServicePrincipals | Where-Object { $_.PublisherName -and $_.PublisherName -ne "Microsoft Corporation" }).Count
        NoPublisherApps = ($Script:AllServicePrincipals | Where-Object { -not $_.PublisherName }).Count
        PrivilegedSPs = ($Script:AllRoleAssignments | Where-Object { $_.MemberType -eq "ServicePrincipal" } | Select-Object -Unique MemberObjectId).Count
        HighRiskApps = @()
        SuspiciousApps = @()
    }
    
    # Identify high-risk and suspicious apps
    $suspiciousPatterns = @("hack", "test", "temp", "bypass", "admin", "root", "system", "backdoor")
    
    foreach ($sp in $Script:AllServicePrincipals) {
        $riskScore = 0
        $riskFactors = @()
        $suspicious = $false
        
        # Risk scoring
        if (-not $sp.PublisherName) { $riskScore += 10; $riskFactors += "No publisher" }
        if ($sp.PublisherName -and $sp.PublisherName -ne "Microsoft Corporation") { $riskScore += 5; $riskFactors += "Third-party" }
        
        # Check for suspicious patterns
        foreach ($pattern in $suspiciousPatterns) {
            if ($sp.DisplayName -like "*$pattern*") {
                $suspicious = $true
                $riskScore += 20
                $riskFactors += "Suspicious name: $pattern"
                break
            }
        }
        
        if ($riskScore -ge 15) {
            $analysis.HighRiskApps += [PSCustomObject]@{
                DisplayName = $sp.DisplayName
                AppId = $sp.AppId
                Publisher = $sp.PublisherName
                RiskScore = $riskScore
                RiskFactors = $riskFactors -join "; "
            }
        }
        
        if ($suspicious) {
            $analysis.SuspiciousApps += $sp
        }
    }
    
    Write-Host "Total Service Principals: $($analysis.TotalServicePrincipals)" -ForegroundColor White
    Write-Host "  Microsoft Apps: $($analysis.MicrosoftApps)" -ForegroundColor Green
    Write-Host "  Third-party Apps: $($analysis.ThirdPartyApps)" -ForegroundColor Yellow
    Write-Host "  No Publisher Info: $($analysis.NoPublisherApps)" -ForegroundColor Gray
    Write-Host "  Privileged SPs: $($analysis.PrivilegedSPs)" -ForegroundColor Red
    Write-Host "  High Risk Apps: $($analysis.HighRiskApps.Count)" -ForegroundColor Red
    Write-Host "  Suspicious Apps: $($analysis.SuspiciousApps.Count)" -ForegroundColor Red
    
    return $analysis
}

function Analyze-PrivilegedAccess {
    Write-Host "`n=== PRIVILEGED ACCESS ANALYSIS ===" -ForegroundColor Blue
    
    $analysis = @{
        TotalRoleAssignments = $Script:AllRoleAssignments.Count
        PrivilegedUsers = ($Script:AllRoleAssignments | Where-Object { $_.MemberType -eq "User" } | Group-Object MemberObjectId).Count
        PrivilegedGroups = ($Script:AllRoleAssignments | Where-Object { $_.MemberType -eq "Group" } | Group-Object MemberObjectId).Count
        PrivilegedSPs = ($Script:AllRoleAssignments | Where-Object { $_.MemberType -eq "ServicePrincipal" } | Group-Object MemberObjectId).Count
        GlobalAdmins = ($Script:AllRoleAssignments | Where-Object { $_.RoleName -eq "Global Administrator" }).Count
        CriticalRoles = @()
        SuspiciousAssignments = @()
    }
    
    # Critical roles to monitor
    $criticalRoleNames = @("Global Administrator", "Privileged Role Administrator", "Security Administrator", 
                          "Exchange Administrator", "SharePoint Administrator", "User Administrator",
                          "Application Administrator", "Cloud Application Administrator")
    
    foreach ($roleName in $criticalRoleNames) {
        $assignments = $Script:AllRoleAssignments | Where-Object { $_.RoleName -eq $roleName }
        if ($assignments.Count -gt 0) {
            $analysis.CriticalRoles += [PSCustomObject]@{
                RoleName = $roleName
                AssignmentCount = $assignments.Count
                Assignments = $assignments
            }
        }
    }
    
    # Check for suspicious admin patterns
    foreach ($assignment in $Script:AllRoleAssignments) {
        $issues = @()
        
        # Check for external admins
        if ($assignment.MemberUPN -like "*#EXT#*") {
            $issues += "External admin account"
        }
        
        # Check for disabled admin accounts
        if ($assignment.AccountEnabled -eq $false) {
            $issues += "Disabled account with admin role"
        }
        
        # Check for suspicious usernames
        $suspiciousNames = @("admin", "test", "temp", "service", "system", "root", "hack")
        foreach ($suspicious in $suspiciousNames) {
            if ($assignment.MemberUPN -like "*$suspicious*" -or $assignment.MemberName -like "*$suspicious*") {
                $issues += "Suspicious username pattern"
                break
            }
        }
        
        if ($issues.Count -gt 0) {
            $analysis.SuspiciousAssignments += [PSCustomObject]@{
                Assignment = $assignment
                Issues = $issues -join "; "
            }
        }
    }
    
    Write-Host "Total Role Assignments: $($analysis.TotalRoleAssignments)" -ForegroundColor White
    Write-Host "  Privileged Users: $($analysis.PrivilegedUsers)" -ForegroundColor Red
    Write-Host "  Privileged Groups: $($analysis.PrivilegedGroups)" -ForegroundColor Yellow
    Write-Host "  Privileged Service Principals: $($analysis.PrivilegedSPs)" -ForegroundColor Cyan
    Write-Host "  Global Administrators: $($analysis.GlobalAdmins)" -ForegroundColor Red
    Write-Host "  Critical Role Types: $($analysis.CriticalRoles.Count)" -ForegroundColor Yellow
    Write-Host "  Suspicious Assignments: $($analysis.SuspiciousAssignments.Count)" -ForegroundColor Red
    
    return $analysis
}

function Analyze-SecurityThreats {
    Write-Host "`n=== SECURITY THREAT ANALYSIS ===" -ForegroundColor Blue
    
    $analysis = @{
        MailboxForwarding = @()
        SuspiciousTransportRules = @()
        FederatedDomains = @()
        ExternalUsers = @()
        SecurityFindings = @()
    }
    
    # Check mailbox forwarding
    foreach ($mailbox in $Script:AllMailboxes) {
        if ($mailbox.ForwardingAddress -or $mailbox.ForwardingSmtpAddress) {
            $analysis.MailboxForwarding += [PSCustomObject]@{
                Mailbox = $mailbox.DisplayName
                UPN = $mailbox.UserPrincipalName
                ForwardingAddress = $mailbox.ForwardingAddress
                ForwardingSmtpAddress = $mailbox.ForwardingSmtpAddress
                DeliverToMailboxAndForward = $mailbox.DeliverToMailboxAndForward
            }
        }
    }
    
    # Check transport rules
    foreach ($rule in $Script:AllTransportRules) {
        $issues = @()
        
        if ($rule.RedirectMessageTo -or $rule.BlindCopyTo) {
            $issues += "External forwarding"
        }
        if ($rule.DeleteMessage -eq $true) {
            $issues += "Message deletion"
        }
        if ($rule.WhenCreated -gt (Get-Date).AddDays(-30)) {
            $issues += "Recently created"
        }
        
        if ($issues.Count -gt 0) {
            $analysis.SuspiciousTransportRules += [PSCustomObject]@{
                RuleName = $rule.Name
                Issues = $issues -join "; "
                Created = $rule.WhenCreated
                Enabled = $rule.State -eq "Enabled"
            }
        }
    }
    
    # Check federated domains
    $analysis.FederatedDomains = $Script:AllDomains | Where-Object { $_.AuthenticationType -eq "Federated" }
    
    # Check external users
    $analysis.ExternalUsers = $Script:AllUsers | Where-Object { $_.UserType -eq "Guest" -or $_.UserPrincipalName -like "*#EXT#*" }
    
    # Compile security findings
    if ($analysis.MailboxForwarding.Count -gt 0) {
        $analysis.SecurityFindings += "CRITICAL: $($analysis.MailboxForwarding.Count) mailboxes with forwarding enabled"
    }
    if ($analysis.SuspiciousTransportRules.Count -gt 0) {
        $analysis.SecurityFindings += "WARNING: $($analysis.SuspiciousTransportRules.Count) suspicious transport rules"
    }
    if ($analysis.FederatedDomains.Count -gt 0) {
        $analysis.SecurityFindings += "INFO: $($analysis.FederatedDomains.Count) federated domains detected"
    }
    if ($analysis.ExternalUsers.Count -gt 0) {
        $analysis.SecurityFindings += "INFO: $($analysis.ExternalUsers.Count) external/guest users"
    }
    
    Write-Host "Mailbox Forwarding: $($analysis.MailboxForwarding.Count)" -ForegroundColor $(if ($analysis.MailboxForwarding.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "Suspicious Transport Rules: $($analysis.SuspiciousTransportRules.Count)" -ForegroundColor $(if ($analysis.SuspiciousTransportRules.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "Federated Domains: $($analysis.FederatedDomains.Count)" -ForegroundColor Yellow
    Write-Host "External Users: $($analysis.ExternalUsers.Count)" -ForegroundColor Cyan
    Write-Host "Security Findings: $($analysis.SecurityFindings.Count)" -ForegroundColor $(if ($analysis.SecurityFindings.Count -gt 0) { "Red" } else { "Green" })
    
    return $analysis
}

function Analyze-RecentActivity {
    Write-Host "`n=== RECENT ACTIVITY ANALYSIS (7 DAYS) ===" -ForegroundColor Blue
    
    $recentDate = (Get-Date).AddDays(-7)
    $analysis = @{
        RecentUsers = @()
        RecentDevices = @()
        RecentActivity = @()
    }
    
    # Recent users
    foreach ($user in $Script:AllUsers) {
        try {
            if ($user.ExtensionProperty.createdDateTime) {
                $createdDate = [DateTime]$user.ExtensionProperty.createdDateTime
                if ($createdDate -ge $recentDate) {
                    $analysis.RecentUsers += $user
                }
            }
        } catch {}
    }
    
    # Recent devices
    foreach ($device in $Script:AllDevices) {
        try {
            if ($device.ApproximateLastLogonTimeStamp) {
                $lastLogon = [DateTime]$device.ApproximateLastLogonTimeStamp
                if ($lastLogon -ge $recentDate) {
                    $analysis.RecentDevices += $device
                }
            }
        } catch {}
    }
    
    Write-Host "Recent Users (7 days): $($analysis.RecentUsers.Count)" -ForegroundColor Cyan
    Write-Host "Recent Device Activity: $($analysis.RecentDevices.Count)" -ForegroundColor Cyan
    
    return $analysis
}

function Export-UnifiedResults {
    param($UserAnalysis, $GroupAnalysis, $SPAnalysis, $PrivilegedAnalysis, $ThreatAnalysis, $ActivityAnalysis)
    
    Write-Host "`n=== EXPORTING UNIFIED RESULTS ===" -ForegroundColor Green
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $exportDir = "O365-Unified-Audit-$timestamp"
    New-Item -Path $exportDir -ItemType Directory -Force | Out-Null
    
    # Export raw data collections
    $dataDir = Join-Path $exportDir "RawData"
    New-Item -Path $dataDir -ItemType Directory -Force | Out-Null
    
    if ($Script:AllUsers.Count -gt 0) {
        $Script:AllUsers | Export-Csv -Path (Join-Path $dataDir "AllUsers.csv") -NoTypeInformation
    }
    if ($Script:AllGroups.Count -gt 0) {
        $Script:AllGroups | Export-Csv -Path (Join-Path $dataDir "AllGroups.csv") -NoTypeInformation
    }
    if ($Script:AllServicePrincipals.Count -gt 0) {
        $Script:AllServicePrincipals | Export-Csv -Path (Join-Path $dataDir "AllServicePrincipals.csv") -NoTypeInformation
    }
    if ($Script:AllRoleAssignments.Count -gt 0) {
        $Script:AllRoleAssignments | Export-Csv -Path (Join-Path $dataDir "AllRoleAssignments.csv") -NoTypeInformation
    }
    
    # Export analysis results
    $analysisDir = Join-Path $exportDir "Analysis"
    New-Item -Path $analysisDir -ItemType Directory -Force | Out-Null
    
    # High-risk findings
    if ($SPAnalysis.HighRiskApps.Count -gt 0) {
        $SPAnalysis.HighRiskApps | Export-Csv -Path (Join-Path $analysisDir "HighRiskApps.csv") -NoTypeInformation
    }
    if ($PrivilegedAnalysis.SuspiciousAssignments.Count -gt 0) {
        $PrivilegedAnalysis.SuspiciousAssignments | Export-Csv -Path (Join-Path $analysisDir "SuspiciousRoleAssignments.csv") -NoTypeInformation
    }
    if ($ThreatAnalysis.MailboxForwarding.Count -gt 0) {
        $ThreatAnalysis.MailboxForwarding | Export-Csv -Path (Join-Path $analysisDir "MailboxForwarding.csv") -NoTypeInformation
    }
    
    # Create comprehensive summary
    $summary = @"
OFFICE 365 UNIFIED SECURITY AUDIT REPORT
=========================================
Generated: $(Get-Date)
Execution Time: $((Get-Date) - $Script:StartTime)
Data Collection Time: Single collection for all analyses

SUMMARY STATISTICS:
==================
Users: $($UserAnalysis.TotalUsers) (Enabled: $($UserAnalysis.EnabledUsers), Disabled: $($UserAnalysis.DisabledUsers))
Groups: $($GroupAnalysis.TotalGroups) (Security: $($GroupAnalysis.SecurityGroups), Mail: $($GroupAnalysis.MailEnabledGroups))
Service Principals: $($SPAnalysis.TotalServicePrincipals) (Microsoft: $($SPAnalysis.MicrosoftApps), Third-party: $($SPAnalysis.ThirdPartyApps))
Role Assignments: $($PrivilegedAnalysis.TotalRoleAssignments)
Devices: $($Script:AllDevices.Count)
Transport Rules: $($Script:AllTransportRules.Count)
Mailboxes Analyzed: $($Script:AllMailboxes.Count)

PRIVILEGED ACCESS:
==================
Global Administrators: $($PrivilegedAnalysis.GlobalAdmins)
Privileged Users: $($PrivilegedAnalysis.PrivilegedUsers)
Privileged Groups: $($PrivilegedAnalysis.PrivilegedGroups)
Privileged Service Principals: $($PrivilegedAnalysis.PrivilegedSPs)

SECURITY FINDINGS:
==================
High-Risk Applications: $($SPAnalysis.HighRiskApps.Count)
Suspicious Role Assignments: $($PrivilegedAnalysis.SuspiciousAssignments.Count)
Mailbox Forwarding: $($ThreatAnalysis.MailboxForwarding.Count)
Suspicious Transport Rules: $($ThreatAnalysis.SuspiciousTransportRules.Count)
External/Guest Users: $($ThreatAnalysis.ExternalUsers.Count)
Federated Domains: $($ThreatAnalysis.FederatedDomains.Count)

RECENT ACTIVITY (7 DAYS):
=========================
Recent Users: $($ActivityAnalysis.RecentUsers.Count)
Recent Device Activity: $($ActivityAnalysis.RecentDevices.Count)

SECURITY RECOMMENDATIONS:
=========================
$($ThreatAnalysis.SecurityFindings -join "`n")

DATA EXPORTED TO:
================
Raw Data: $dataDir
Analysis Results: $analysisDir
"@
    
    $summary | Out-File -FilePath (Join-Path $exportDir "UnifiedAuditSummary.txt") -Encoding UTF8
    
    Write-Host "Unified audit results exported to: $exportDir" -ForegroundColor Green
    return $exportDir
}

# Main execution
function Start-UnifiedAudit {
    Show-Banner
    
    if (-not $SkipConnection) {
        if (-not (Connect-AllServices -TenantId $TenantId)) {
            Write-Host "Failed to connect to services. Exiting." -ForegroundColor Red
            exit 1
        }
    }
    
    # Single data collection
    Collect-AllData
    
    # Multiple analyses using the same data
    Write-Host "`n=== PERFORMING ALL ANALYSES ===" -ForegroundColor Magenta
    
    $userAnalysis = Analyze-Users
    $groupAnalysis = Analyze-Groups
    $spAnalysis = Analyze-ServicePrincipals
    $privilegedAnalysis = Analyze-PrivilegedAccess
    $threatAnalysis = Analyze-SecurityThreats
    $activityAnalysis = Analyze-RecentActivity
    
    # Export everything
    $exportDir = Export-UnifiedResults -UserAnalysis $userAnalysis -GroupAnalysis $groupAnalysis -SPAnalysis $spAnalysis -PrivilegedAnalysis $privilegedAnalysis -ThreatAnalysis $threatAnalysis -ActivityAnalysis $activityAnalysis
    
    $totalTime = (Get-Date) - $Script:StartTime
    Write-Host "`n=== AUDIT COMPLETED ===" -ForegroundColor Green
    Write-Host "Total execution time: $($totalTime.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Yellow
    Write-Host "Results exported to: $exportDir" -ForegroundColor Cyan
    Write-Host "`nEfficiency gained: Single data collection + multiple analyses = Faster execution!" -ForegroundColor Green
}

# Start the unified audit
Start-UnifiedAudit
