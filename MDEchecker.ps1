#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Scans all Group Policy Objects in the current domain for MDE Auditing related settings.

.DESCRIPTION
    This script examines all GPOs in the domain and identifies settings that affect
    Microsoft Defender for Endpoint (MDE) auditing capabilities, including:
    - Advanced Audit Policy settings
    - Security Options related to auditing
    - Event Log settings
    - Process and object access auditing
    - Network access auditing

.NOTES
    Requires GroupPolicy PowerShell module and appropriate permissions to read GPOs.
    Run as an administrator with domain read permissions.
#>

# Import required module
Import-Module GroupPolicy -ErrorAction Stop

# Define MDE auditing related settings to search for
$AuditSettings = @{
    # Advanced Audit Policy Categories
    "Account Logon" = @(
        "Audit Credential Validation",
        "Audit Kerberos Authentication Service",
        "Audit Kerberos Service Ticket Operations",
        "Audit Other Account Logon Events"
    )
    "Account Management" = @(
        "Audit Application Group Management",
        "Audit Computer Account Management",
        "Audit Distribution Group Management",
        "Audit Other Account Management Events",
        "Audit Security Group Management",
        "Audit User Account Management"
    )
    "Detailed Tracking" = @(
        "Audit DPAPI Activity",
        "Audit Process Creation",
        "Audit Process Termination",
        "Audit RPC Events",
        "Audit Token Right Adjusted Events"
    )
    "DS Access" = @(
        "Audit Directory Service Access",
        "Audit Directory Service Changes",
        "Audit Directory Service Replication",
        "Audit Detailed Directory Service Replication"
    )
    "Logon/Logoff" = @(
        "Audit Account Lockout",
        "Audit Group Membership",
        "Audit Logoff",
        "Audit Logon",
        "Audit Network Policy Server",
        "Audit Other Logon/Logoff Events",
        "Audit Special Logon",
        "Audit User / Device Claims"
    )
    "Object Access" = @(
        "Audit Application Generated",
        "Audit Certification Services",
        "Audit Detailed File Share",
        "Audit File Share",
        "Audit File System",
        "Audit Filtering Platform Connection",
        "Audit Filtering Platform Packet Drop",
        "Audit Handle Manipulation",
        "Audit Kernel Object",
        "Audit Other Object Access Events",
        "Audit Registry",
        "Audit Removable Storage",
        "Audit SAM",
        "Audit Central Policy Staging"
    )
    "Policy Change" = @(
        "Audit Audit Policy Change",
        "Audit Authentication Policy Change",
        "Audit Authorization Policy Change",
        "Audit Filtering Platform Policy Change",
        "Audit MPSSVC Rule-Level Policy Change",
        "Audit Other Policy Change Events"
    )
    "Privilege Use" = @(
        "Audit Non Sensitive Privilege Use",
        "Audit Other Privilege Use Events",
        "Audit Sensitive Privilege Use"
    )
    "System" = @(
        "Audit IPsec Driver",
        "Audit Other System Events",
        "Audit Security State Change",
        "Audit Security System Extension",
        "Audit System Integrity"
    )
}

# Security Options related to auditing
$SecurityOptions = @(
    "Audit: Audit the access of global system objects",
    "Audit: Audit the use of Backup and Restore privilege",
    "Audit: Force audit policy subcategory settings",
    "Audit: Shut down system immediately if unable to log security audits"
)

# Event Log related settings
$EventLogSettings = @(
    "Maximum security log size",
    "Retain security log",
    "Security log retention method"
)

function Write-ColorOutput {
    param(
        [string]$Text,
        [string]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
}

function Search-GPOForAuditSettings {
    param(
        [Microsoft.GroupPolicy.Gpo]$GPO
    )
    
    $findings = @()
    
    try {
        # Get GPO report in XML format
        $gpoReport = Get-GPOReport -Guid $GPO.Id -ReportType Xml -ErrorAction Stop
        [xml]$xmlReport = $gpoReport
        
        # Search for Advanced Audit Policy settings
        $auditNodes = $xmlReport.SelectNodes("//q1:AdvancedAuditPolicyConfiguration/q1:AuditSetting", $xmlReport.DocumentElement.GetXmlNamespace())
        
        foreach ($node in $auditNodes) {
            $subcategory = $node.SubcategoryName
            $setting = $node.SettingValue
            
            # Check if this subcategory is relevant to MDE auditing
            foreach ($category in $AuditSettings.Keys) {
                if ($AuditSettings[$category] -contains $subcategory) {
                    $findings += [PSCustomObject]@{
                        Type = "Advanced Audit Policy"
                        Category = $category
                        Setting = $subcategory
                        Value = $setting
                        Path = "Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\$category"
                    }
                    break
                }
            }
        }
        
        # Search for Security Options
        $securityNodes = $xmlReport.SelectNodes("//q1:SecurityOptions/q1:Display/q1:DisplayFields", $xmlReport.DocumentElement.GetXmlNamespace())
        
        foreach ($node in $securityNodes) {
            $name = $node.Field1
            $value = $node.Field2
            
            if ($SecurityOptions -contains $name) {
                $findings += [PSCustomObject]@{
                    Type = "Security Option"
                    Category = "Security Options"
                    Setting = $name
                    Value = $value
                    Path = "Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options"
                }
            }
        }
        
        # Search for Event Log settings
        $eventLogNodes = $xmlReport.SelectNodes("//q1:EventLog/q1:*", $xmlReport.DocumentElement.GetXmlNamespace())
        
        foreach ($node in $eventLogNodes) {
            $settingName = $node.LocalName
            if ($EventLogSettings -contains $settingName) {
                $findings += [PSCustomObject]@{
                    Type = "Event Log Setting"
                    Category = "Event Log"
                    Setting = $settingName
                    Value = $node.InnerText
                    Path = "Computer Configuration\Policies\Windows Settings\Security Settings\Event Log"
                }
            }
        }
        
    }
    catch {
        Write-Warning "Error processing GPO '$($GPO.DisplayName)': $($_.Exception.Message)"
    }
    
    return $findings
}

# Main execution
Write-ColorOutput "=== MDE Auditing GPO Scanner ===" "Cyan"
Write-ColorOutput "Scanning all GPOs in domain for MDE auditing related settings..." "Yellow"
Write-Host ""

try {
    # Get all GPOs in the domain
    $allGPOs = Get-GPO -All
    Write-ColorOutput "Found $($allGPOs.Count) GPOs to scan" "Green"
    Write-Host ""
    
    $totalFindings = @()
    $processedCount = 0
    
    foreach ($gpo in $allGPOs) {
        $processedCount++
        Write-Progress -Activity "Scanning GPOs" -Status "Processing: $($gpo.DisplayName)" -PercentComplete (($processedCount / $allGPOs.Count) * 100)
        
        $findings = Search-GPOForAuditSettings -GPO $gpo
        
        if ($findings.Count -gt 0) {
            Write-ColorOutput "GPO: $($gpo.DisplayName)" "Cyan"
            Write-ColorOutput "  GUID: $($gpo.Id)" "Gray"
            Write-ColorOutput "  Domain: $($gpo.DomainName)" "Gray"
            Write-ColorOutput "  Created: $($gpo.CreationTime)" "Gray"
            Write-ColorOutput "  Modified: $($gpo.ModificationTime)" "Gray"
            Write-Host ""
            
            foreach ($finding in $findings) {
                Write-ColorOutput "  [$($finding.Type)] $($finding.Setting)" "White"
                Write-ColorOutput "    Value: $($finding.Value)" "Green"
                Write-ColorOutput "    Path: $($finding.Path)" "Gray"
                Write-Host ""
            }
            
            $totalFindings += $findings | ForEach-Object { 
                $_ | Add-Member -NotePropertyName "GPOName" -NotePropertyValue $gpo.DisplayName -PassThru |
                     Add-Member -NotePropertyName "GPOGUID" -NotePropertyValue $gpo.Id -PassThru
            }
            
            Write-Host ("-" * 80)
        }
    }
    
    Write-Progress -Activity "Scanning GPOs" -Completed
    
    # Summary
    Write-ColorOutput "`n=== SUMMARY ===" "Cyan"
    Write-ColorOutput "Total GPOs scanned: $($allGPOs.Count)" "Yellow"
    Write-ColorOutput "GPOs with MDE auditing settings: $(($totalFindings | Select-Object -Unique GPOName).Count)" "Yellow"
    Write-ColorOutput "Total MDE auditing settings found: $($totalFindings.Count)" "Yellow"
    
    if ($totalFindings.Count -gt 0) {
        Write-Host "`nBreakdown by setting type:"
        $totalFindings | Group-Object Type | ForEach-Object {
            Write-ColorOutput "  $($_.Name): $($_.Count) settings" "White"
        }
        
        # Export results to CSV
        $csvPath = "MDE_Audit_GPO_Findings_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $totalFindings | Export-Csv -Path $csvPath -NoTypeInformation
        Write-ColorOutput "`nResults exported to: $csvPath" "Green"
    }
    else {
        Write-ColorOutput "No MDE auditing related settings found in any GPO." "Yellow"
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}

Write-ColorOutput "`nScript completed successfully!" "Green"
