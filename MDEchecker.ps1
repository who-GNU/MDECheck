#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Scans all Group Policy Objects in the current domain for Microsoft Defender Antivirus settings.

.DESCRIPTION
    This script examines all GPOs in the domain and identifies Microsoft Defender Antivirus
    settings under Windows Components\Microsoft Defender Antivirus, including:
    - Real-time Protection settings
    - Scan configurations
    - Cloud protection (MpEngine) settings
    - Reporting and notification settings
    - Quarantine settings
    - Exclusions
    - MAPS settings
    - Network Inspection System settings
    - Threat detection settings

.NOTES
    Requires GroupPolicy PowerShell module and appropriate permissions to read GPOs.
    Run as an administrator with domain read permissions.
#>

# Import required module
Import-Module GroupPolicy -ErrorAction Stop

# Define Microsoft Defender Antivirus settings to search for
$DefenderSettings = @{
    "Real-time Protection" = @(
        "Turn on behavior monitoring",
        "Scan all downloaded files and attachments",
        "Monitor file and program activity on your computer",
        "Turn on real-time protection",
        "Turn on process scanning whenever real-time protection is enabled",
        "Turn on raw volume write notifications",
        "Configure monitoring for incoming and outgoing file and program activity"
    )
    "Scan" = @(
        "Specify the maximum depth to scan archive files",
        "Scan archive files",
        "Scan packed executables",
        "Scan removable drives",
        "Turn on e-mail scanning",
        "Scan mapped network drives",
        "Run scheduled scan only when computer is on but not in use",
        "Specify the day of the week to run a scheduled scan",
        "Specify the time of day to run a scheduled scan",
        "Specify the scan type to use for a scheduled scan",
        "Specify the interval to run quick scans per day"
    )
    "MpEngine" = @(
        "Configure extended cloud check",
        "Select cloud protection level",
        "Configure cloud protection level",
        "Configure timeout for cloud lookups",
        "Turn on Microsoft Defender Antivirus cloud-delivered protection"
    )
    "Reporting" = @(
        "Configure Watson events",
        "Turn off enhanced notifications",
        "Suppress all notifications",
        "Configure notification timeout"
    )
    "Quarantine" = @(
        "Configure removal of items from Quarantine folder",
        "Configure local setting override for the removal of items from Quarantine folder"
    )
    "Exclusions" = @(
        "Path Exclusions",
        "Extension Exclusions", 
        "Process Exclusions"
    )
    "MAPS" = @(
        "Join Microsoft MAPS",
        "Configure the 'Block at First Sight' feature",
        "Send file samples when further analysis is required",
        "Configure local setting override for reporting to Microsoft MAPS"
    )
    "Network Inspection System" = @(
        "Turn on definition retirement",
        "Turn on protocol recognition",
        "Specify additional definition sets for network traffic inspection"
    )
    "Threats" = @(
        "Configure detection for potentially unwanted applications",
        "Turn on e-mail scanning"
    )
}

# Remove the Security Options and Event Log settings arrays since we're focusing on Defender settings

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
        
        # Search for Microsoft Defender Antivirus settings under Windows Components
        $defenderNodes = $xmlReport.SelectNodes("//*[local-name()='Policy' and contains(@name,'Microsoft Defender Antivirus')]")
        
        foreach ($node in $defenderNodes) {
            $policyName = $node.name
            $policyState = $node.state
            $policyCategory = $node.category
            
            if ($policyName -and $policyState) {
                # Extract the subcategory from the policy name or category
                $subcategory = "General"
                
                # Determine which Defender category this setting belongs to
                foreach ($category in $DefenderSettings.Keys) {
                    if ($DefenderSettings[$category] -contains $policyName) {
                        $subcategory = $category
                        break
                    }
                }
                
                # Check if category contains keywords to categorize settings
                if ($policyCategory) {
                    switch -Wildcard ($policyCategory) {
                        "*Real-time Protection*" { $subcategory = "Real-time Protection" }
                        "*Scan*" { $subcategory = "Scan" }
                        "*MpEngine*" { $subcategory = "MpEngine" }
                        "*Reporting*" { $subcategory = "Reporting" }
                        "*Quarantine*" { $subcategory = "Quarantine" }
                        "*Exclusions*" { $subcategory = "Exclusions" }
                        "*MAPS*" { $subcategory = "MAPS" }
                        "*Network Inspection*" { $subcategory = "Network Inspection System" }
                        "*Threats*" { $subcategory = "Threats" }
                    }
                }
                
                # Get additional details like registry values
                $registryValues = @()
                $valueNodes = $node.SelectNodes(".//*[local-name()='RegistryValue']")
                foreach ($valueNode in $valueNodes) {
                    $regName = $valueNode.Name
                    $regValue = $valueNode.Value
                    $regType = $valueNode.Type
                    if ($regName -and $regValue) {
                        $registryValues += "$regName = $regValue ($regType)"
                    }
                }
                
                $findings += [PSCustomObject]@{
                    Type = "Microsoft Defender Antivirus Policy"
                    Category = $subcategory
                    Setting = $policyName
                    Value = $policyState
                    RegistryDetails = ($registryValues -join "; ")
                    Path = "Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\$subcategory"
                }
            }
        }
        
        # Alternative search for Administrative Templates policies
        $adminTemplateNodes = $xmlReport.SelectNodes("//*[local-name()='AdministrativeTemplate']")
        
        foreach ($templateNode in $adminTemplateNodes) {
            $policyNodes = $templateNode.SelectNodes(".//*[local-name()='Policy']")
            
            foreach ($policyNode in $policyNodes) {
                $policyName = $policyNode.Name
                $policyState = $policyNode.State
                $policyCategory = $policyNode.Category
                
                # Check if this is a Microsoft Defender Antivirus policy
                if ($policyCategory -and $policyCategory -match "Microsoft Defender Antivirus") {
                    
                    # Determine subcategory
                    $subcategory = "General"
                    foreach ($category in $DefenderSettings.Keys) {
                        if ($DefenderSettings[$category] -contains $policyName) {
                            $subcategory = $category
                            break
                        }
                    }
                    
                    # Extract category from path if available
                    if ($policyCategory -match "Microsoft Defender Antivirus\\(.+)") {
                        $subcategory = $matches[1]
                    }
                    
                    $findings += [PSCustomObject]@{
                        Type = "Microsoft Defender Antivirus Policy"
                        Category = $subcategory
                        Setting = $policyName
                        Value = $policyState
                        RegistryDetails = ""
                        Path = "Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\$subcategory"
                    }
                }
            }
        }
        
        # Search for any policy with "Defender" or "Antivirus" in the name
        $allPolicyNodes = $xmlReport.SelectNodes("//*[local-name()='Policy']")
        
        foreach ($node in $allPolicyNodes) {
            $policyName = $node.Name
            $policyState = $node.State
            $policyCategory = $node.Category
            
            if ($policyName -and ($policyName -match "Defender|Antivirus|Windows Security")) {
                
                # Skip if we already found this policy
                $alreadyFound = $findings | Where-Object { $_.Setting -eq $policyName }
                if ($alreadyFound) { continue }
                
                $subcategory = "General"
                if ($policyCategory) {
                    $subcategory = $policyCategory -replace ".*Microsoft Defender Antivirus\\?", ""
                    if (-not $subcategory) { $subcategory = "General" }
                }
                
                $findings += [PSCustomObject]@{
                    Type = "Microsoft Defender Antivirus Policy"
                    Category = $subcategory
                    Setting = $policyName
                    Value = $policyState
                    RegistryDetails = ""
                    Path = "Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\$subcategory"
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
Write-ColorOutput "=== Microsoft Defender Antivirus GPO Scanner ===" "Cyan"
Write-ColorOutput "Scanning all GPOs in domain for Microsoft Defender Antivirus settings..." "Yellow"
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
    Write-ColorOutput "GPOs with Microsoft Defender Antivirus settings: $(($totalFindings | Select-Object -Unique GPOName).Count)" "Yellow"
    Write-ColorOutput "Total Microsoft Defender Antivirus settings found: $($totalFindings.Count)" "Yellow"
    
    if ($totalFindings.Count -gt 0) {
        Write-Host "`nBreakdown by setting type:"
        $totalFindings | Group-Object Type | ForEach-Object {
            Write-ColorOutput "  $($_.Name): $($_.Count) settings" "White"
        }
        
        Write-Host "`nBreakdown by category:"
        $totalFindings | Group-Object Category | ForEach-Object {
            Write-ColorOutput "  $($_.Name): $($_.Count) settings" "White"
        }
        
        # Export results to CSV
        $csvPath = "Microsoft_Defender_GPO_Findings_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $totalFindings | Export-Csv -Path $csvPath -NoTypeInformation
        Write-ColorOutput "`nResults exported to: $csvPath" "Green"
    }
    else {
        Write-ColorOutput "No Microsoft Defender Antivirus settings found in any GPO." "Yellow"
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}

Write-ColorOutput "`nScript completed successfully!" "Green"
