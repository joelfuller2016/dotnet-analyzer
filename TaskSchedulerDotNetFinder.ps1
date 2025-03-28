# TaskSchedulerDotNetFinder.ps1
# Specialized script for finding .NET applications in Windows Task Scheduler
# Version: 1.0

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSystemTasks,
    
    [Parameter(Mandatory=$false)]
    [switch]$Detailed
)

# Initialize
$Results = @()
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = "$env:TEMP\TaskDotNetFinder_$timestamp.log"

# Start logging
"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Task Scheduler .NET Finder Started" | Out-File -FilePath $LogFile

# Helper functions
function Write-Log {
    param($Message, $Level = "INFO")
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogFile -Append
    
    switch ($Level) {
        "ERROR"   { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default   { Write-Host $Message }
    }
}

function Get-FileDotNetVersion {
    param([string]$FilePath)
    
    $dotNetVersion = "Not .NET"
    
    try {
        if (Test-Path $FilePath) {
            # Check for PE header with .NET CLI header
            try {
                $bytes = [System.IO.File]::ReadAllBytes($FilePath)
                
                # Basic PE header check
                if ($bytes.Length -gt 64 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                    $peOffset = [BitConverter]::ToInt32($bytes, 60)
                    
                    if ($peOffset -gt 0 -and $peOffset -lt ($bytes.Length - 4)) {
                        if ($bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {
                            # Check for .NET metadata
                            $optionalHeaderOffset = $peOffset + 0x18
                            $peFormat = $bytes[$optionalHeaderOffset + 2]
                            $comDescriptorOffset = 0
                            
                            if ($peFormat -eq 0x10B) { # PE32
                                $comDescriptorOffset = $optionalHeaderOffset + 0x60
                            } elseif ($peFormat -eq 0x20B) { # PE32+ (64-bit)
                                $comDescriptorOffset = $optionalHeaderOffset + 0x70
                            }
                            
                            if ($comDescriptorOffset -gt 0 -and $comDescriptorOffset + 8 -lt $bytes.Length) {
                                $comDescriptorRVA = [BitConverter]::ToInt32($bytes, $comDescriptorOffset)
                                $comDescriptorSize = [BitConverter]::ToInt32($bytes, $comDescriptorOffset + 4)
                                
                                if ($comDescriptorRVA -gt 0 -and $comDescriptorSize -gt 0) {
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
                                                $dotNetVersion = ".NET Standard $($matches[1])"
                                            } elseif ($tfm -match "^\.NET,Version=v(\d+\.\d+)") {
                                                $dotNetVersion = ".NET $($matches[1])"
                                            } else {
                                                $dotNetVersion = ".NET (Unknown version: $tfm)"
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
                                            } else {
                                                $dotNetVersion = ".NET (Image runtime: $runtimeInfo)"
                                            }
                                        }
                                    } catch {
                                        $dotNetVersion = ".NET (could not determine specific version)"
                                    }
                                }
                            }
                        }
                    }
                }
            } catch {
                # Silently fail on binary parsing errors
            }
        }
    } catch {
        # Silently fail if file access is denied
    }
    
    return $dotNetVersion
}

function Get-FileArchitecture {
    param([string]$FilePath)
    
    $architecture = "Unknown"
    
    try {
        if (Test-Path $FilePath) {
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
            
            if ($bytes.Length -gt 64 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                $peOffset = [BitConverter]::ToInt32($bytes, 60)
                
                if ($peOffset -gt 0 -and $peOffset -lt ($bytes.Length - 4)) {
                    if ($bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {
                        $machineOffset = $peOffset + 4
                        $machineType = [BitConverter]::ToUInt16($bytes, $machineOffset)
                        
                        # Machine types from PE format spec
                        switch ($machineType) {
                            0x014c { $architecture = "32-bit (x86)" }
                            0x0200 { $architecture = "64-bit (IA64)" }
                            0x8664 { $architecture = "64-bit (x64)" }
                            0x01c4 { $architecture = "ARM" }
                            0xAA64 { $architecture = "ARM64" }
                            default { $architecture = "Unknown ($machineType)" }
                        }
                    }
                }
            }
        }
    } catch {
        # Silent fail
    }
    
    return $architecture
}

# Display banner
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "              TASK SCHEDULER .NET FINDER                     " -ForegroundColor Cyan
Write-Host "         Find .NET applications in scheduled tasks           " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host ""

# Start analysis
Write-Log "Scanning Windows Task Scheduler for .NET applications..." -Level SUCCESS
Write-Host "Scanning task scheduler for .NET applications..." -ForegroundColor Green

try {
    # Get all tasks based on filters
    $tasks = if ($IncludeDisabled) {
        Get-ScheduledTask
    } else {
        Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
    }
    
    # Filter system tasks if needed
    if (-not $IncludeSystemTasks) {
        $tasks = $tasks | Where-Object { $_.TaskPath -notlike "\Microsoft\Windows\*" }
    }
    
    $totalTasks = $tasks.Count
    $dotNetTasks = 0
    $taskCounter = 0
    $tasksByPath = @{}
    
    Write-Log "Found $totalTasks scheduled tasks to analyze" -Level INFO
    Write-Host "Found $totalTasks scheduled tasks to analyze"
    
    # Create progress bar
    $progressParams = @{
        Activity = "Analyzing scheduled tasks"
        Status = "Scanning task 0 of $totalTasks"
        PercentComplete = 0
    }
    Write-Progress @progressParams
    
    foreach ($task in $tasks) {
        $taskCounter++
        
        # Update progress
        if ($taskCounter % 5 -eq 0 -or $taskCounter -eq $totalTasks) {
            $progressParams.Status = "Scanning task $taskCounter of $totalTasks"
            $progressParams.PercentComplete = ($taskCounter / $totalTasks) * 100
            Write-Progress @progressParams
        }
        
        try {
            $actions = $task.Actions
            $taskPath = $task.TaskPath
            $taskName = $task.TaskName
            
            # Keep track of tasks by path
            if (-not $tasksByPath.ContainsKey($taskPath)) {
                $tasksByPath[$taskPath] = 0
            }
            
            foreach ($action in $actions) {
                if ($action.Execute) {
                    # Clean up executable path
                    $exePath = $action.Execute -replace '^"([^"]+)".*$', '$1'
                    $exePath = $exePath -replace "^'([^']+)'.*$", '$1'
                    
                    # Handle system environment variables
                    try {
                        $exePath = [System.Environment]::ExpandEnvironmentVariables($exePath)
                    } catch {
                        # Skip environment variable expansion if it fails
                    }
                    
                    if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                        $dotNetVersion = Get-FileDotNetVersion -FilePath $exePath
                        
                        if ($dotNetVersion -ne "Not .NET") {
                            $dotNetTasks++
                            $tasksByPath[$taskPath]++
                            
                            # Get more details
                            $architecture = Get-FileArchitecture -FilePath $exePath
                            
                            try {
                                $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
                                $lastRun = if ($taskInfo.LastRunTime -and $taskInfo.LastRunTime -gt [DateTime]::MinValue) { 
                                    $taskInfo.LastRunTime 
                                } else { 
                                    "Never" 
                                }
                                $lastResult = $taskInfo.LastTaskResult
                            } catch {
                                $lastRun = "Unknown"
                                $lastResult = "Unknown"
                            }
                            
                            # Get XML for more details
                            $taskXml = [xml]$task.XML
                            $author = $taskXml.Task.RegistrationInfo.Author
                            $description = $taskXml.Task.RegistrationInfo.Description
                            
                            # Principal (user account)
                            $principal = $taskXml.Task.Principals.Principal
                            $runAsUser = if ($principal) {
                                if ($principal.UserId) {
                                    $principal.UserId
                                } elseif ($principal.GroupId) {
                                    $principal.GroupId
                                } else {
                                    if ($principal.RunLevel -eq "HighestAvailable") {
                                        "Elevated Rights"
                                    } else {
                                        "Standard User"
                                    }
                                }
                            } else {
                                "Unknown"
                            }
                            
                            # Get trigger summary (just count types)
                            $triggerTypes = @()
                            $triggerNodes = $taskXml.Task.Triggers.ChildNodes
                            foreach ($node in $triggerNodes) {
                                if ($node.LocalName -and $node.LocalName -ne "#comment") {
                                    $triggerTypes += $node.LocalName
                                }
                            }
                            $triggerSummary = $triggerTypes -join ", "
                            if (-not $triggerSummary) { $triggerSummary = "None" }
                            
                            # Create result object
                            $resultObject = [PSCustomObject]@{
                                TaskName = $taskName
                                TaskPath = $taskPath
                                DotNetVersion = $dotNetVersion
                                ExecutablePath = $exePath
                                Architecture = $architecture
                                State = $task.State
                                LastRun = $lastRun
                                LastResult = $lastResult
                                Triggers = $triggerSummary
                                RunAs = $runAsUser
                            }
                            
                            # Add more details if requested
                            if ($Detailed) {
                                $resultObject | Add-Member -NotePropertyName Arguments -NotePropertyValue $action.Arguments
                                $resultObject | Add-Member -NotePropertyName WorkingDirectory -NotePropertyValue $action.WorkingDirectory
                                $resultObject | Add-Member -NotePropertyName Author -NotePropertyValue $author
                                $resultObject | Add-Member -NotePropertyName Description -NotePropertyValue $description
                            }
                            
                            # Add to results
                            $Results += $resultObject
                            
                            Write-Log "Found $dotNetVersion task: $taskPath$taskName at $exePath"
                        }
                    }
                    
                    break  # Only check first action with executable
                }
            }
        } catch {
            Write-Log "Error analyzing task $taskPath$taskName : $($_.Exception.Message)" -Level ERROR
        }
    }
    
    # Complete the progress bar
    Write-Progress -Activity "Analyzing scheduled tasks" -Completed
    
    # Display summary
    Write-Host ""
    Write-Host "Found $dotNetTasks .NET applications in scheduled tasks (out of $totalTasks total)" -ForegroundColor Green
    
    # Group by path
    Write-Host ""
    Write-Host "Distribution by Folder:" -ForegroundColor Yellow
    $tasksByPath.GetEnumerator() | Where-Object { $_.Value -gt 0 } | Sort-Object -Property Value -Descending | ForEach-Object {
        Write-Host "  $($_.Key): $($_.Value) .NET tasks" -ForegroundColor White
    }
    
    # Group by .NET version
    Write-Host ""
    Write-Host ".NET Versions Found:" -ForegroundColor Yellow
    $Results | Group-Object -Property DotNetVersion | Sort-Object -Property Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count) tasks" -ForegroundColor White
    }
    
    # Export results to file if specified
    if ($OutputFile -ne "") {
        try {
            $Results | Export-Csv -Path $OutputFile -NoTypeInformation
            Write-Host ""
            Write-Host "Results exported to $OutputFile" -ForegroundColor Green
        } catch {
            Write-Log "Error exporting results: $($_.Exception.Message)" -Level ERROR
            Write-Host "Error exporting results: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        # Default output in temp dir
        $defaultOutput = "$env:TEMP\TaskDotNetFinder_$timestamp.csv"
        $Results | Export-Csv -Path $defaultOutput -NoTypeInformation
        Write-Host ""
        Write-Host "Results exported to $defaultOutput" -ForegroundColor Green
    }
    
} catch {
    Write-Log "Error scanning scheduled tasks: $($_.Exception.Message)" -Level ERROR
    Write-Host "Error scanning scheduled tasks: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Analysis complete! Log file: $LogFile" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan