# PowerShell Script to identify running processes, services, scheduled tasks and their .NET versions

# Function to get .NET version of a process
function Get-DotNetVersion {
    param (
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Process]$Process
    )
    
    $dotNetVersion = "Not .NET"
    
    try {
        # Check for .NET Framework modules
        $netFrameworkModules = $Process.Modules | Where-Object { 
            $_.ModuleName -like "mscorlib.dll" -or 
            $_.ModuleName -like "clr.dll" -or 
            $_.ModuleName -like "System.dll" 
        }
        
        if ($netFrameworkModules) {
            # Try to determine version by looking at file version of mscorlib
            $mscorlibModule = $Process.Modules | Where-Object { $_.ModuleName -eq "mscorlib.dll" }
            if ($mscorlibModule) {
                $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($mscorlibModule.FileName)
                # Map major version to .NET Framework version
                switch ($fileVersion.FileMajorPart) {
                    2 { $dotNetVersion = ".NET Framework 2.0/3.0/3.5" }
                    4 { 
                        switch ($fileVersion.FileMinorPart) {
                            0 { $dotNetVersion = ".NET Framework 4.0/4.5" }
                            6 { $dotNetVersion = ".NET Framework 4.6/4.7" }
                            7 { $dotNetVersion = ".NET Framework 4.7/4.8" }
                            8 { $dotNetVersion = ".NET Framework 4.8" }
                            default { $dotNetVersion = ".NET Framework 4.x" }
                        }
                    }
                    default { $dotNetVersion = ".NET Framework (Unknown version)" }
                }
            }
            
            # Check for .NET Core/5+
            $netCoreModules = $Process.Modules | Where-Object { 
                $_.ModuleName -like "coreclr.dll" -or 
                $_.ModuleName -like "hostpolicy.dll"
            }
            
            if ($netCoreModules) {
                $coreclrModule = $Process.Modules | Where-Object { $_.ModuleName -eq "coreclr.dll" }
                if ($coreclrModule) {
                    $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($coreclrModule.FileName)
                    if ($fileVersion.FileMajorPart -ge 5) {
                        $dotNetVersion = ".NET 5.0+"
                    } else {
                        $dotNetVersion = ".NET Core"
                    }
                } else {
                    $dotNetVersion = ".NET Core/5+"
                }
            }
        }
    } catch {
        $dotNetVersion = "Error determining .NET version"
    }
    
    return $dotNetVersion
}

# Function to get .NET version from executable path
function Get-ExecutableDotNetVersion {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ExePath
    )
    
    $dotNetVersion = "Unknown"
    
    try {
        if (Test-Path $ExePath) {
            # Check if it's a .NET executable
            $bytes = [System.IO.File]::ReadAllBytes($ExePath)
            $isDotNet = $false
            
            # Check for PE header and CLI header
            if ($bytes.Length -gt 64) {
                if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {  # MZ header
                    $peOffset = [BitConverter]::ToInt32($bytes, 60)
                    if ($peOffset -lt $bytes.Length - 4) {
                        if ($bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {  # PE header
                            # Look for CLI header which indicates .NET
                            $isDotNet = $true
                        }
                    }
                }
            }
            
            if ($isDotNet) {
                # Try to determine framework version
                try {
                    $assembly = [System.Reflection.Assembly]::LoadFile($ExePath)
                    $targetFramework = $assembly.GetCustomAttributes([System.Runtime.Versioning.TargetFrameworkAttribute], $false)
                    if ($targetFramework -and $targetFramework.Length -gt 0) {
                        $dotNetVersion = $targetFramework[0].FrameworkName
                    } else {
                        $dotNetVersion = ".NET (version not determined)"
                    }
                } catch {
                    $dotNetVersion = ".NET (could not load assembly)"
                }
            } else {
                $dotNetVersion = "Not a .NET executable"
            }
        } else {
            $dotNetVersion = "File not found"
        }
    } catch {
        $dotNetVersion = "Error: $($_.Exception.Message)"
    }
    
    return $dotNetVersion
}

# Function to analyze a scheduled task
function Get-ScheduledTaskInfo {
    param (
        [Parameter(Mandatory=$true)]
        $Task
    )
    
    try {
        $actions = $Task.Actions
        $exePath = ""
        
        # Try to extract executable path from task action
        foreach ($action in $actions) {
            if ($action.Execute) {
                $exePath = $action.Execute
                break
            }
        }
        
        if ($exePath) {
            # Clean up the path if it contains arguments
            $exePath = $exePath -replace '^"([^"]+)".*$', '$1'
            $dotNetVersion = Get-ExecutableDotNetVersion -ExePath $exePath
        } else {
            $dotNetVersion = "No executable found"
        }
        
        return [PSCustomObject]@{
            TaskName = $Task.TaskName
            TaskPath = $Task.TaskPath
            Executable = $exePath
            DotNetVersion = $dotNetVersion
        }
    } catch {
        return [PSCustomObject]@{
            TaskName = $Task.TaskName
            TaskPath = $Task.TaskPath
            Executable = "Error"
            DotNetVersion = "Error: $($_.Exception.Message)"
        }
    }
}

# Main script execution
Write-Host "========== .NET Version Analysis Script ==========" -ForegroundColor Green
Write-Host "Starting analysis... This may take a while." -ForegroundColor Yellow

# Check installed .NET versions on the system
Write-Host "`n[1] Installed .NET Versions" -ForegroundColor Cyan
Write-Host "------------------------------" -ForegroundColor Cyan

# Check .NET Framework from registry
$netFrameworkVersions = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse | 
    Get-ItemProperty -Name Version, Install, Release -ErrorAction SilentlyContinue

if ($netFrameworkVersions) {
    Write-Host "Installed .NET Framework versions:" -ForegroundColor White
    $netFrameworkVersions | ForEach-Object {
        if ($_.Install -eq 1) {
            Write-Host "  - $($_.Version)" -ForegroundColor White
        }
    }
} else {
    Write-Host "  No .NET Framework versions detected" -ForegroundColor Gray
}

# Check .NET Core/.NET 5+ from program files
$dotnetRootPaths = @(
    "${env:ProgramFiles}\dotnet\shared\Microsoft.NETCore.App",
    "${env:ProgramFiles(x86)}\dotnet\shared\Microsoft.NETCore.App"
)

$coreVersions = @()
foreach ($path in $dotnetRootPaths) {
    if (Test-Path $path) {
        $coreVersions += Get-ChildItem -Path $path -Directory | Select-Object -ExpandProperty Name
    }
}

if ($coreVersions) {
    Write-Host "Installed .NET Core/.NET versions:" -ForegroundColor White
    $coreVersions | ForEach-Object {
        Write-Host "  - $_" -ForegroundColor White
    }
} else {
    Write-Host "  No .NET Core/.NET 5+ versions detected" -ForegroundColor Gray
}

# Analyze running processes
Write-Host "`n[2] Running Processes" -ForegroundColor Cyan
Write-Host "-------------------" -ForegroundColor Cyan
$runningProcesses = @()

Get-Process | ForEach-Object {
    try {
        $process = $_
        $dotNetVersion = Get-DotNetVersion -Process $process
        
        $runningProcesses += [PSCustomObject]@{
            ProcessName = $process.ProcessName
            PID = $process.Id
            DotNetVersion = $dotNetVersion
        }
    } catch {
        Write-Host "Error analyzing process $($_.ProcessName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

$runningProcesses | Where-Object { $_.DotNetVersion -ne "Not .NET" } | 
    Format-Table -AutoSize -Property ProcessName, PID, DotNetVersion

# Analyze running services
Write-Host "`n[3] Running Services" -ForegroundColor Cyan
Write-Host "------------------" -ForegroundColor Cyan
$runningServices = @()

Get-Service | Where-Object { $_.Status -eq 'Running' } | ForEach-Object {
    try {
        $service = $_
        $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'"
        
        if ($serviceInfo -and $serviceInfo.PathName) {
            # Extract actual path from the service path
            $exePath = $serviceInfo.PathName -replace '^"([^"]+)".*$', '$1'
            $exePath = $exePath -replace "^'([^']+)'.*$", '$1'
            
            $dotNetVersion = "Unknown"
            
            # Try to find process associated with service
            $serviceProcess = Get-Process -Id $serviceInfo.ProcessId -ErrorAction SilentlyContinue
            if ($serviceProcess) {
                $dotNetVersion = Get-DotNetVersion -Process $serviceProcess
            } else {
                $dotNetVersion = Get-ExecutableDotNetVersion -ExePath $exePath
            }
            
            $runningServices += [PSCustomObject]@{
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                PID = $serviceInfo.ProcessId
                ExecutablePath = $exePath
                DotNetVersion = $dotNetVersion
            }
        }
    } catch {
        Write-Host "Error analyzing service $($_.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}

$runningServices | Where-Object { $_.DotNetVersion -ne "Not .NET" -and $_.DotNetVersion -ne "Unknown" } | 
    Format-Table -AutoSize -Property ServiceName, DisplayName, PID, DotNetVersion

# Analyze scheduled tasks
Write-Host "`n[4] Scheduled Tasks" -ForegroundColor Cyan
Write-Host "----------------" -ForegroundColor Cyan
$scheduledTasks = @()

Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
    try {
        $taskInfo = Get-ScheduledTaskInfo -Task $_
        $scheduledTasks += $taskInfo
    } catch {
        Write-Host "Error analyzing task $($_.TaskName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

$scheduledTasks | Where-Object { $_.DotNetVersion -ne "Not a .NET executable" -and $_.DotNetVersion -ne "File not found" } |
    Format-Table -AutoSize -Property TaskName, Executable, DotNetVersion

Write-Host "`nAnalysis complete!" -ForegroundColor Green