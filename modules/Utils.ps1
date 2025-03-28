# Utility Functions Module

# Script configuration
$script:LogFile = $null
$script:VerboseLogging = $true
$script:ResultDirectory = $null
$script:ColorOutput = $true
$script:OutputFormat = "CSV"
$script:QuickMode = $false

function Initialize-Environment {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$LogPath,
        
        [Parameter()]
        [string]$ResultPath,
        
        [Parameter()]
        [bool]$Verbose = $true,
        
        [Parameter()]
        [bool]$ColoredOutput = $true,
        
        [Parameter()]
        [ValidateSet("CSV", "JSON", "TEXT")]
        [string]$Format = "CSV",
        
        [Parameter()]
        [bool]$QuickScan = $false
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    
    # Set up log file path
    if ([string]::IsNullOrEmpty($LogPath)) {
        $script:LogFile = Join-Path $env:TEMP "DotNetAnalysis_$timestamp.log"
    } else {
        $script:LogFile = $LogPath
    }
    
    # Set up results directory
    if ([string]::IsNullOrEmpty($ResultPath)) {
        $script:ResultDirectory = Join-Path $env:TEMP "DotNetAnalysis_$timestamp"
    } else {
        $script:ResultDirectory = $ResultPath
    }
    
    # Create the results directory
    if (-not (Test-Path $script:ResultDirectory)) {
        New-Item -ItemType Directory -Path $script:ResultDirectory -Force | Out-Null
    }
    
    # Configure settings
    $script:VerboseLogging = $Verbose
    $script:ColorOutput = $ColoredOutput
    $script:OutputFormat = $Format
    $script:QuickMode = $QuickScan
    
    # Initialize log file
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] .NET Analysis Script Started" | Out-File -FilePath $script:LogFile
    Write-Log "Environment initialized. Logging to: $script:LogFile" -Level INFO
    Write-Log "Results will be saved to: $script:ResultDirectory" -Level INFO
    
    # Validate permissions
    $isAdmin = IsAdministrator
    if (-not $isAdmin) {
        Write-Log "Warning: Script is not running with administrator privileges. Some functionality may be limited." -Level WARNING
    }
    
    return [PSCustomObject]@{
        LogFile = $script:LogFile
        ResultDirectory = $script:ResultDirectory
        IsAdmin = $isAdmin
        Timestamp = $timestamp
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DETAIL")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to log file if defined
    if ($script:LogFile) {
        $logMessage | Out-File -FilePath $script:LogFile -Append
    }
    
    # Write to console with color coding if enabled
    if ($script:ColorOutput) {
        switch ($Level) {
            "INFO"    { Write-Host $logMessage -ForegroundColor White }
            "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
            "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
            "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
            "DETAIL"  { 
                if ($script:VerboseLogging) {
                    Write-Host $logMessage -ForegroundColor Gray 
                }
            }
        }
    } else {
        # Plain output without colors
        if ($Level -ne "DETAIL" -or ($Level -eq "DETAIL" -and $script:VerboseLogging)) {
            Write-Host $logMessage
        }
    }
}

function Export-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Array]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$Filename,
        
        [Parameter()]
        [string]$Description = ""
    )
    
    if (-not $Data -or $Data.Count -eq 0) {
        Write-Log "No data to export for $Filename" -Level INFO
        return
    }
    
    try {
        $filePath = Join-Path $script:ResultDirectory $Filename
        
        switch ($script:OutputFormat) {
            "CSV" {
                $Data | Export-Csv -Path "$filePath.csv" -NoTypeInformation
                Write-Log "Exported $($Data.Count) items to $filePath.csv" -Level DETAIL
            }
            "JSON" {
                $jsonOutput = @{
                    Description = $Description
                    ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    ComputerName = $env:COMPUTERNAME
                    Data = $Data
                    Count = $Data.Count
                }
                $jsonOutput | ConvertTo-Json -Depth 5 | Out-File "$filePath.json"
                Write-Log "Exported $($Data.Count) items to $filePath.json" -Level DETAIL
            }
            "TEXT" {
                $textOutput = "# $Description`r`n"
                $textOutput += "# Export Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`r`n"
                $textOutput += "# Computer: $env:COMPUTERNAME`r`n"
                $textOutput += "# Items: $($Data.Count)`r`n`r`n"
                
                $columns = $Data[0].PSObject.Properties.Name
                $textOutput += $columns -join "`t" + "`r`n"
                $textOutput += "-" * 80 + "`r`n"
                
                foreach ($item in $Data) {
                    $line = foreach ($column in $columns) {
                        $item.$column
                    }
                    $textOutput += $line -join "`t" + "`r`n"
                }
                
                $textOutput | Out-File "$filePath.txt"
                Write-Log "Exported $($Data.Count) items to $filePath.txt" -Level DETAIL
            }
        }
        
        return $filePath
    } catch {
        Write-Log "Error exporting data to $Filename`: $($_.Exception.Message)" -Level ERROR
    }
}

function Get-FileDotNetVersion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    $dotNetVersion = "Not .NET"
    
    try {
        if (Test-Path $FilePath) {
            # Check for PE header with .NET CLI header
            try {
                $bytes = [System.IO.File]::ReadAllBytes($FilePath)
                
                if ($bytes.Length -gt 0x200) { # Minimum size for a valid PE file with .NET headers
                    # Check for PE header
                    if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) { # MZ header
                        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
                        
                        # Ensure PE header offset is valid
                        if ($peOffset -gt 0 -and $peOffset -lt ($bytes.Length - 0x40)) {
                            # Check for "PE\0\0"
                            if ($bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45 -and $bytes[$peOffset+2] -eq 0 -and $bytes[$peOffset+3] -eq 0) {
                                # Get optional header size and location
                                $optionalHeaderOffset = $peOffset + 0x18
                                
                                # Check if PE32 or PE32+
                                $peFormat = $bytes[$optionalHeaderOffset + 2]
                                $comDescriptorOffset = 0
                                
                                if ($peFormat -eq 0x10B) { # PE32
                                    $comDescriptorOffset = $optionalHeaderOffset + 0x60
                                } elseif ($peFormat -eq 0x20B) { # PE32+ (64-bit)
                                    $comDescriptorOffset = $optionalHeaderOffset + 0x70
                                }
                                
                                if ($comDescriptorOffset -gt 0 -and $comDescriptorOffset + 8 -lt $bytes.Length) {
                                    # Get COM descriptor RVA and size
                                    $comDescriptorRVA = [BitConverter]::ToInt32($bytes, $comDescriptorOffset)
                                    $comDescriptorSize = [BitConverter]::ToInt32($bytes, $comDescriptorOffset + 4)
                                    
                                    # If COM descriptor exists, it's a .NET assembly
                                    if ($comDescriptorRVA -gt 0 -and $comDescriptorSize -gt 0) {
                                        # It's a .NET file! Try to get the metadata version
                                        $dotNetVersion = "Detected .NET Assembly"
                                        
                                        # Now try to determine the version from metadata
                                        try {
                                            $assembly = [System.Reflection.Assembly]::LoadFile($FilePath)
                                            
                                            # Check for target framework attribute
                                            $targetFrameworkAttribute = $assembly.GetCustomAttributes([System.Runtime.Versioning.TargetFrameworkAttribute], $false)
                                            if ($targetFrameworkAttribute -and $targetFrameworkAttribute.Length -gt 0) {
                                                $tfm = $targetFrameworkAttribute[0].FrameworkName
                                                
                                                # Parse framework name
                                                if ($tfm -match "^\.NETCoreApp,Version=v(\d+\.\d+)") {
                                                    $dotNetVersion = ".NET Core $($matches[1])"
                                                } elseif ($tfm -match "^\.NETCore,Version=v(\d+\.\d+)") {
                                                    $dotNetVersion = ".NET Core $($matches[1])"
                                                } elseif ($tfm -match "^\.NETFramework,Version=v(\d+\.\d+)") {
                                                    $dotNetVersion = ".NET Framework $($matches[1])"
                                                } elseif ($tfm -match "^\.NETStandard,Version=v(\d+\.\d+)") {
                                                    $dotNetVersion = ".NET Standard $($matches[1]) Compatible"
                                                } elseif ($tfm -match "^\.NET,Version=v(\d+\.\d+)") {
                                                    $dotNetVersion = ".NET $($matches[1])"
                                                } else {
                                                    $dotNetVersion = "Unknown .NET ($tfm)"
                                                }
                                            } else {
                                                # Fallback to imageruntime version
                                                $runtimeInfo = $assembly.ImageRuntimeVersion
                                                if ($runtimeInfo -match "^v(\d+\.\d+)") {
                                                    $version = $matches[1]
                                                    if ($version -eq "4.0") {
                                                        $dotNetVersion = ".NET Framework 4.x"
                                                    } elseif ($version -eq "2.0") {
                                                        $dotNetVersion = ".NET Framework 2.0/3.5"
                                                    } else {
                                                        $dotNetVersion = ".NET Runtime v$version"
                                                    }
                                                }
                                            }
                                        } catch {
                                            # Failed to load assembly, but we know it's .NET
                                            $dotNetVersion = ".NET (could not determine version)"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-Log "Error analyzing file ${FilePath}: $($_.Exception.Message)" -Level ERROR
            }
        } else {
            $dotNetVersion = "File not found"
        }
    } catch {
        $dotNetVersion = "Error: $($_.Exception.Message)"
    }
    
    return $dotNetVersion
}

function IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ScanConfiguration {
    [CmdletBinding()]
    param()
    
    return [PSCustomObject]@{
        IsAdmin = IsAdministrator
        QuickScan = $script:QuickMode
        VerboseLogging = $script:VerboseLogging
        OutputFormat = $script:OutputFormat
        LogFile = $script:LogFile
        ResultDirectory = $script:ResultDirectory
        ColorOutput = $script:ColorOutput
        OperatingSystem = [Environment]::OSVersion.Version.ToString()
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        ComputerName = $env:COMPUTERNAME
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}

function Show-AnalysisResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Results
    )
    
    # Header
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "          .NET ANALYSIS RESULTS SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
    
    # System Info
    Write-Host "SYSTEM: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "DATE  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host ""
    
    # Framework versions
    Write-Host "INSTALLED .NET FRAMEWORK VERSIONS:" -ForegroundColor Green
    if ($Results.FrameworkVersions -and $Results.FrameworkVersions.Count -gt 0) {
        foreach ($version in $Results.FrameworkVersions) {
            $versionStr = $version.Version
            if ($version.ServicePack) { $versionStr += " SP$($version.ServicePack)" }
            if ($version.Release) { $versionStr += " (Release: $($version.Release))" }
            Write-Host "  - $versionStr" -ForegroundColor Gray
        }
    } else {
        Write-Host "  None detected" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Core versions
    Write-Host "INSTALLED .NET CORE/.NET VERSIONS:" -ForegroundColor Green
    if ($Results.CoreVersions -and $Results.CoreVersions.Count -gt 0) {
        $Results.CoreVersions | Group-Object -Property Type | ForEach-Object {
            Write-Host "  $($_.Name):" -ForegroundColor White
            $_.Group | Sort-Object Version -Descending | ForEach-Object {
                $versionInfo = $_.Version
                if ($_.IsPrerelease) { $versionInfo += " (Preview)" }
                Write-Host "    - $versionInfo" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "  None detected" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Processes
    Write-Host "RUNNING .NET PROCESSES:" -ForegroundColor Green
    if ($Results.Processes -and $Results.Processes.Count -gt 0) {
        Write-Host "  Found $($Results.Processes.Count) .NET processes (out of $($Results.ProcessCount) total)" -ForegroundColor White
        
        # Group by .NET type
        $processesByType = $Results.Processes | Group-Object -Property Runtime
        foreach ($type in $processesByType) {
            Write-Host "  $($type.Name) ($($type.Count) processes):" -ForegroundColor White
            # Show top 5 processes by memory usage
            $type.Group | Sort-Object -Property Memory_MB -Descending | Select-Object -First 5 | ForEach-Object {
                Write-Host "    - $($_.ProcessName) (PID: $($_.PID), Memory: $($_.Memory_MB) MB)" -ForegroundColor Gray
            }
            if ($type.Count -gt 5) {
                Write-Host "    - ... and $($type.Count - 5) more" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "  No .NET processes detected" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Services
    Write-Host "RUNNING .NET SERVICES:" -ForegroundColor Green
    if ($Results.Services -and $Results.Services.Count -gt 0) {
        Write-Host "  Found $($Results.Services.Count) .NET services (out of $($Results.ServiceCount) total)" -ForegroundColor White
        
        # Group by .NET type
        $servicesByType = $Results.Services | Group-Object -Property Runtime
        foreach ($type in $servicesByType) {
            Write-Host "  $($type.Name) ($($type.Count) services):" -ForegroundColor White
            $type.Group | Select-Object -First 5 | ForEach-Object {
                Write-Host "    - $($_.Name) ($($_.DisplayName))" -ForegroundColor Gray
            }
            if ($type.Count -gt 5) {
                Write-Host "    - ... and $($type.Count - 5) more" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "  No .NET services detected" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Tasks
    Write-Host "SCHEDULED .NET TASKS:" -ForegroundColor Green
    if ($Results.Tasks -and $Results.Tasks.Count -gt 0) {
        Write-Host "  Found $($Results.Tasks.Count) .NET tasks (out of $($Results.TaskCount) total)" -ForegroundColor White
        
        # Show top 5 tasks
        $Results.Tasks | Select-Object -First 5 | ForEach-Object {
            Write-Host "    - $($_.TaskName)" -ForegroundColor Gray
        }
        if ($Results.Tasks.Count -gt 5) {
            Write-Host "    - ... and $($Results.Tasks.Count - 5) more" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No .NET scheduled tasks detected" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Results location
    Write-Host "RESULTS SAVED TO:" -ForegroundColor Green
    Write-Host "  $($Results.ResultDirectory)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

Export-ModuleMember -Function Initialize-Environment, Write-Log, Export-Results, Get-FileDotNetVersion, IsAdministrator, Get-ScanConfiguration, Show-AnalysisResults