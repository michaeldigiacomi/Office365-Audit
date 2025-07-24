# O365 Security Remediation Guide
# Based on audit findings

Write-Host "Office 365 Security Remediation Guide" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green

Write-Host "`nBased on your audit results, here are the recommended actions:" -ForegroundColor Yellow

Write-Host "`n=== HIGH PRIORITY ACTIONS ===" -ForegroundColor Red

Write-Host "`n1. STRENGTHEN MFA ENFORCEMENT" -ForegroundColor Cyan
Write-Host "   Current Status: Some users may not have MFA enforced"
Write-Host "   Action: Create comprehensive Conditional Access policies"
Write-Host "   Commands to run:"
Write-Host "   # Review current MFA status for all users" -ForegroundColor Gray
Write-Host "   Get-MsolUser -All | Select-Object DisplayName,StrongAuthenticationRequirements" -ForegroundColor Gray
Write-Host "   # Or use Graph API for modern approach" -ForegroundColor Gray

Write-Host "`n2. REVIEW ADMIN ACCOUNT SECURITY" -ForegroundColor Cyan
Write-Host "   Current Status: Multiple admin accounts detected"
Write-Host "   Action: Implement admin account best practices"
Write-Host "   Recommendations:"
Write-Host "   - Use dedicated admin accounts (not personal emails)"
Write-Host "   - Enable Privileged Identity Management (PIM)"
Write-Host "   - Require separate authentication for admin tasks"

Write-Host "`n3. APPLICATION PERMISSION REVIEW" -ForegroundColor Cyan
Write-Host "   Current Status: Applications with excessive permissions found"
Write-Host "   Action: Audit and reduce application permissions"
Write-Host "   Commands to run:"
Write-Host "   Get-AzureADServicePrincipal | Where-Object {`$_.AppRoles.Count -gt 5}" -ForegroundColor Gray

Write-Host "`n=== MEDIUM PRIORITY ACTIONS ===" -ForegroundColor Yellow

Write-Host "`n4. EXTEND AUDIT LOG RETENTION" -ForegroundColor Cyan
Write-Host "   Current Status: Audit logs may be retained less than 1 year"
Write-Host "   Action: Configure longer retention for compliance"
Write-Host "   Command:"
Write-Host "   Set-AdminAuditLogConfig -AdminAuditLogAgeLimit 365.00:00:00" -ForegroundColor Gray

Write-Host "`n=== IMMEDIATE SECURITY ACTIONS ===" -ForegroundColor Magenta

Write-Host "`n5. MAILBOX FORWARDING REVIEW" -ForegroundColor Cyan
Write-Host "   Action: Check for unauthorized forwarding rules"
Write-Host "   Commands:"
Write-Host "   Get-Mailbox | Where-Object {`$_.ForwardingSmtpAddress -ne `$null}" -ForegroundColor Gray
Write-Host "   Get-InboxRule -Mailbox * | Where-Object {`$_.ForwardTo -ne `$null}" -ForegroundColor Gray

Write-Host "`n6. LEGACY AUTHENTICATION BLOCKING" -ForegroundColor Cyan
Write-Host "   Action: Create policy to block legacy authentication"
Write-Host "   This should be done via Azure AD Conditional Access policies"

Write-Host "`n=== ONGOING MONITORING ===" -ForegroundColor Green

Write-Host "`n7. REGULAR SECURITY REVIEWS" -ForegroundColor Cyan
Write-Host "   Schedule:"
Write-Host "   - Weekly: Review admin activities"
Write-Host "   - Monthly: Full security audit"
Write-Host "   - Quarterly: Permission and access review"

Write-Host "`n8. AUTOMATION SETUP" -ForegroundColor Cyan
Write-Host "   Implement:"
Write-Host "   - Automated security alerts"
Write-Host "   - Regular audit script execution"
Write-Host "   - Compliance monitoring"

Write-Host "`n=== QUICK SECURITY HEALTH CHECK ===" -ForegroundColor Blue
Write-Host "Run these commands to verify improvements:"

$healthCheck = @"
# Quick Security Health Check Commands:

# 1. Check Global Admin count
(Get-AzureADDirectoryRole | Where-Object {`$_.DisplayName -eq "Global Administrator"} | Get-AzureADDirectoryRoleMember).Count

# 2. Check enabled Conditional Access policies  
(Get-AzureADMSConditionalAccessPolicy | Where-Object {`$_.State -eq "Enabled"}).Count

# 3. Check for external forwarding
Get-Mailbox | Where-Object {`$_.ForwardingSmtpAddress -like "*@*" -and `$_.ForwardingSmtpAddress -notlike "*edgegroupltd.com"}

# 4. Check audit log configuration
Get-AdminAuditLogConfig | Select-Object AdminAuditLogEnabled,AdminAuditLogAgeLimit

# 5. Check for high-risk applications
Get-AzureADServicePrincipal | Where-Object {`$_.AppRoles.Count -gt 10} | Select-Object DisplayName,AppId
"@

Write-Host $healthCheck -ForegroundColor Gray

Write-Host "`n=== NEXT STEPS ===" -ForegroundColor Green
Write-Host "1. Prioritize HIGH risk findings from the audit report"
Write-Host "2. Create an action plan with timelines"
Write-Host "3. Test changes in a pilot group first"
Write-Host "4. Document all security configurations"
Write-Host "5. Schedule regular audit runs using these scripts"

Write-Host "`n=== AUTOMATION TIP ===" -ForegroundColor Yellow
Write-Host "To automate regular audits, create a scheduled task that runs:"
Write-Host ".\Reset-PowerShellSession.ps1; .\O365-Connect-Simple.ps1 -TenantId 'fd1d1756-d45a-4fb8-9bd8-bbab1043eba4'; .\O365-Audit-Comprehensive.ps1" -ForegroundColor Gray

Write-Host "`nRemediation guide complete. Review the audit reports for detailed findings." -ForegroundColor Green
