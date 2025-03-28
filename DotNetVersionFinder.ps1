# DotNetVersionFinder.ps1
# All-in-one script to detect .NET versions on Windows systems
# Identifies .NET Framework, .NET Core, and .NET 5+ across processes, services, and tasks

param(
    [Parameter(Mandatory=$false)]
    [switch]$Quick,            # Quick scan with less detail
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipProcesses,    # Skip process scanning
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipServices,     # Skip service scanning
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTasks,        # Skip scheduled tasks scanning
    
    [Parameter(Mandatory=$false)]
    [switch]$NoSystemItems,    # Skip system processes/services/tasks
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ""   # Custom output path
)

# Set up log file and results directory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if ([string]::IsNullOrEmpty($OutputPath)) {
    $resultsDir = Join-Path $env:TEMP "DotNetScan_$timestamp"
} else {
    $resultsDir = $OutputPath
}

if (-not (Test-Path $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
}

$logFile = Join-Path $resultsDir "DotNetScan.log"
"[$timestamp] .NET Version Finder Started" | Out-File -FilePath $logFile

# Logging function
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    $logMessage | Out-File -FilePath $logFile -Append
    
    # Write to console with color
    switch ($Level) {
        "INFO"    { Write-Host $logMessage -ForegroundColor White }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "DETAIL"  { Write-Host $logMessage -ForegroundColor Gray }
    }
}

function Export-Results {
    param (
        [Array]$Data,
        [string]$FileName
    )
    
    if (-not $Data -or $Data.Count -eq 0) {
        return
    }
    
    $filePath = Join-Path $resultsDir "$FileName.csv"
    $Data | Export-Csv -Path $filePath -NoTypeInformation
    Write-Log "Exported $($Data.Count) items to $filePath" -Level "SUCCESS"
}

function IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Display header
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "                .NET VERSION FINDER                    " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "System: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Date  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "Output: $resultsDir" -ForegroundColor White
Write-Host "Admin : $(if(IsAdministrator) { 'Yes' } else { 'No (limited functionality)' })" -ForegroundColor White
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# ==== PART 1: Check .NET CLI information ====
# Similar to "dotnet --version" but more comprehensive
Write-Host "Checking .NET CLI versions..." -ForegroundColor Green

$dotnetSdks = @()
$dotnetRuntimes = @()

# Try directly using dotnet command
try {
    # Check if dotnet CLI is available
    $dotnetPath = Get-Command dotnet -ErrorAction SilentlyContinue
    
    if ($dotnetPath) {
        Write-Log "Found dotnet CLI at: $($dotnetPath.Source)"
        
        # Get SDK versions
        $sdkOutput = dotnet --list-sdks 2>$null
        if ($sdkOutput) {
            foreach ($line in $sdkOutput) {
                if ($line -match '(\d+\.\d+\.\d+[^ ]*) \[(.*)\]') {
                    $version = $matches[1]
                    $path = $matches[2]
                    
                    $dotnetSdks += [PSCustomObject]@{
                        Version = $version
                        InstallPath = $path
                        Type = ".NET SDK"
                    }
                    
                    Write-Log "Found .NET SDK $version at $path" -Level "DETAIL"
                }
            }
        } else {
            Write-Log "No .NET SDKs found using dotnet CLI" -Level "WARNING"
        }
        
        # Get runtime versions
        $runtimeOutput = dotnet --list-runtimes 2>$null
        if ($runtimeOutput) {
            foreach ($line in $runtimeOutput) {
                if ($line -match '([^ ]+) (\d+\.\d+\.\d+[^ ]*) \[(.*)\]') {
                    $type = $matches[1]
                    $version = $matches[2]
                    $path = $matches[3]
                    
                    $dotnetRuntimes += [PSCustomObject]@{
                        Type = $type
                        Version = $version
                        InstallPath = $path
                    }
                    
                    Write-Log "Found .NET Runtime $type $version at $path" -Level "DETAIL"
                }
            }
        } else {
            Write-Log "No .NET Runtimes found using dotnet CLI" -Level "WARNING"
        }
    } else {
        Write-Log "dotnet CLI not found in PATH" -Level "WARNING"
    }
} catch {
    Write-Log "Error using dotnet CLI: $($_.Exception.Message)" -Level "ERROR"
}

# ==== PART 2: Check .NET Framework from registry ====
Write-Host "Checking .NET Framework versions from registry..." -ForegroundColor Green

$dotnetFrameworks = @()

# Check for .NET Framework 1.0 and 1.1
$netFx10 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\Policy\v1.0" -ErrorAction SilentlyContinue
if ($netFx10) {
    $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v1.0.3705"
    
    $dotnetFrameworks += [PSCustomObject]@{
        Version = ".NET Framework 1.0"
        ServicePack = $null
        InstallPath = $installPath
        Release = $null
    }
    
    Write-Log "Found .NET Framework 1.0 at $installPath"
}

$netFx11 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v1.1.4322" -ErrorAction SilentlyContinue
if ($netFx11) {
    $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v1.1.4322"
    
    $dotnetFrameworks += [PSCustomObject]@{
        Version = ".NET Framework 1.1"
        ServicePack = $netFx11.SP
        InstallPath = $installPath
        Release = $null
    }
    
    Write-Log "Found .NET Framework 1.1 SP$($netFx11.SP) at $installPath"
}

# .NET Framework 2.0 to 4.x
$ndpKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP"
if (Test-Path $ndpKey) {
    # .NET Framework 2.0, 3.0, 3.5
    foreach ($versionKey in Get-ChildItem $ndpKey | Where-Object { $_.PSChildName -match "^v[23]" }) {
        if ($versionKey.PSChildName -eq "v3.0" -or $versionKey.PSChildName -eq "v3.5") {
            $installPaths = @{
                "v3.0" = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v2.0.50727"
                "v3.5" = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v2.0.50727"
            }
            
            $installed = (Get-ItemProperty -Path $versionKey.PSPath -Name Install -ErrorAction SilentlyContinue).Install
            $sp = (Get-ItemProperty -Path $versionKey.PSPath -Name SP -ErrorAction SilentlyContinue).SP
            
            if ($installed -eq 1) {
                $dotnetFrameworks += [PSCustomObject]@{
                    Version = ".NET Framework $($versionKey.PSChildName.Substring(1))"
                    ServicePack = $sp
                    InstallPath = $installPaths[$versionKey.PSChildName]
                    Release = $null
                }
                
                Write-Log "Found .NET Framework $($versionKey.PSChildName.Substring(1)) SP$sp at $($installPaths[$versionKey.PSChildName])"
            }
        } else {
            # Check for v2.0 specifically
            foreach ($subkey in Get-ChildItem $versionKey.PSPath) {
                $installed = (Get-ItemProperty -Path $subkey.PSPath -Name Install -ErrorAction SilentlyContinue).Install
                
                if ($installed -eq 1) {
                    $version = (Get-ItemProperty -Path $subkey.PSPath -Name Version -ErrorAction SilentlyContinue).Version
                    $sp = (Get-ItemProperty -Path $subkey.PSPath -Name SP -ErrorAction SilentlyContinue).SP
                    $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v2.0.50727"
                    
                    $dotnetFrameworks += [PSCustomObject]@{
                        Version = if ($version) { ".NET Framework $version" } else { ".NET Framework $($versionKey.PSChildName.Substring(1))" }
                        ServicePack = $sp
                        InstallPath = $installPath
                        Release = $null
                    }
                    
                    Write-Log "Found .NET Framework $version SP$sp at $installPath"
                }
            }
        }
    }
    
    # .NET Framework 4.0 and newer
    $v4Key = Get-ChildItem $ndpKey | Where-Object { $_.PSChildName -eq "v4" -or $_.PSChildName -eq "v4.0" }
    if ($v4Key) {
        foreach ($subkey in Get-ChildItem $v4Key.PSPath) {
            $profile = $subkey.PSChildName
            $release = (Get-ItemProperty -Path $subkey.PSPath -Name Release -ErrorAction SilentlyContinue).Release
            $version = (Get-ItemProperty -Path $subkey.PSPath -Name Version -ErrorAction SilentlyContinue).Version
            $sp = (Get-ItemProperty -Path $subkey.PSPath -Name SP -ErrorAction SilentlyContinue).SP
            $installed = (Get-ItemProperty -Path $subkey.PSPath -Name Install -ErrorAction SilentlyContinue).Install
            
            if ($installed -eq 1) {
                # Map release number to detailed version
                $dotNetVersion = switch ($release) {
                    378389 { ".NET Framework 4.5" }
                    378675 { ".NET Framework 4.5.1" }
                    378758 { ".NET Framework 4.5.1" }
                    379893 { ".NET Framework 4.5.2" }
                    393295 { ".NET Framework 4.6" }
                    393297 { ".NET Framework 4.6" }
                    394254 { ".NET Framework 4.6.1" }
                    394271 { ".NET Framework 4.6.1" }
                    394802 { ".NET Framework 4.6.2" }
                    394806 { ".NET Framework 4.6.2" }
                    460798 { ".NET Framework 4.7" }
                    460805 { ".NET Framework 4.7" }
                    461308 { ".NET Framework 4.7.1" }
                    461310 { ".NET Framework 4.7.1" }
                    461808 { ".NET Framework 4.7.2" }
                    461814 { ".NET Framework 4.7.2" }
                    528040 { ".NET Framework 4.8" }
                    528049 { ".NET Framework 4.8" }
                    528209 { ".NET Framework 4.8.1" }
                    528372 { ".NET Framework 4.8.1" }
                    528449 { ".NET Framework 4.8.1" }
                    533320 { ".NET Framework 4.8.1" }
                    533325 { ".NET Framework 4.8.1" }
                    default { ".NET Framework 4.x (Release: $release)" }
                }
                
                $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
                
                $dotnetFrameworks += [PSCustomObject]@{
                    Version = $dotNetVersion
                    ServicePack = $sp
                    InstallPath = $installPath
                    Release = $release
                }
                
                Write-Log "Found $dotNetVersion Release $release at $installPath"
            }
        }
    }
}

# ==== PART 3: Check .NET Core installed versions ====
Write-Host "Checking .NET Core/.NET 5+ installed versions..." -ForegroundColor Green

$dotnetCoreInstalled = @()

# If we didn't already get them from CLI, check installation folders
if ($dotnetRuntimes.Count -eq 0) {
    # .NET Core Runtime paths
    $runtimePaths = @(
        (Join-Path $env:ProgramFiles "dotnet\shared\Microsoft.NETCore.App"),
        (Join-Path ${env:ProgramFiles(x86)} "dotnet\shared\Microsoft.NETCore.App"),
        (Join-Path $env:ProgramFiles "dotnet\shared\Microsoft.AspNetCore.App"),
        (Join-Path ${env:ProgramFiles(x86)} "dotnet\shared\Microsoft.AspNetCore.App"),
        (Join-Path $env:ProgramFiles "dotnet\shared\Microsoft.WindowsDesktop.App"),
        (Join-Path ${env:ProgramFiles(x86)} "dotnet\shared\Microsoft.WindowsDesktop.App")
    )
    
    foreach ($runtimePath in $runtimePaths) {
        if (Test-Path $runtimePath) {
            $type = switch -Wildcard ($runtimePath) {
                "*Microsoft.AspNetCore.App*" { "ASP.NET Core Runtime" }
                "*Microsoft.WindowsDesktop.App*" { "Windows Desktop Runtime" }
                default { ".NET Core/.NET Runtime" }
            }
            
            Get-ChildItem -Path $runtimePath -Directory | ForEach-Object {
                $dotnetCoreInstalled += [PSCustomObject]@{
                    Type = $type
                    Version = $_.Name
                    InstallPath = $_.FullName
                }
                
                Write-Log "Found $type version $($_.Name) at $($_.FullName)"
            }
        }
    }
}

# ==== PART 4: Check .NET in running processes ====
$dotnetProcesses = @()
if (-not $SkipProcesses) {
    Write-Host "Checking .NET usage in running processes..." -ForegroundColor Green
    
    # Function to detect .NET in a process
    function Get-ProcessDotNetInfo {
        param (
            [System.Diagnostics.Process]$Process
        )
        
        $dotNetDetected = $false
        $dotNetVersion = "Unknown"
        $dotNetType = "Unknown"
        
        try {
            # Check for .NET modules
            $netModules = @(
                # .NET Framework
                "mscorlib.dll", 
                "clr.dll", 
                "System.dll",
                
                # .NET Core/5+
                "coreclr.dll",
                "hostpolicy.dll",
                "System.Private.CoreLib.dll"
            )
            
            foreach ($module in $Process.Modules) {
                if ($netModules -contains $module.ModuleName) {
                    $dotNetDetected = $true
                    $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($module.FileName)
                    
                    # Determine version type
                    if ($module.ModuleName -eq "mscorlib.dll" -or $module.ModuleName -eq "clr.dll") {
                        $dotNetType = ".NET Framework"
                        
                        # Determine Framework version
                        switch ($fileVersion.FileMajorPart) {
                            2 { $dotNetVersion = ".NET Framework 2.0/3.0/3.5" }
                            4 { 
                                $dotNetVersion = switch ($fileVersion.FileMinorPart) {
                                    0 { 
                                        if ($fileVersion.FileBuildPart -eq 30319) {
                                            if ($fileVersion.FilePrivatePart -le 1008) {
                                                ".NET Framework 4.0 RTM"
                                            } elseif ($fileVersion.FilePrivatePart -le 34209) {
                                                ".NET Framework 4.5/4.5.1"
                                            } elseif ($fileVersion.FilePrivatePart -le 36213) {
                                                ".NET Framework 4.5.2"
                                            } elseif ($fileVersion.FilePrivatePart -le 42259) {
                                                ".NET Framework 4.6/4.6.2"
                                            } elseif ($fileVersion.FilePrivatePart -le 43634) {
                                                ".NET Framework 4.7/4.7.2" 
                                            } else {
                                                ".NET Framework 4.8+" 
                                            }
                                        } else {
                                            ".NET Framework 4.x"
                                        }
                                    }
                                    default { ".NET Framework 4.x" }
                                }
                            }
                            default { ".NET Framework (version unknown)" }
                        }
                    } elseif ($module.ModuleName -eq "coreclr.dll" -or $module.ModuleName -eq "hostpolicy.dll" -or $module.ModuleName -eq "System.Private.CoreLib.dll") {
                        $dotNetType = ".NET Core/.NET"
                        
                        if ($fileVersion.FileMajorPart -ge 5) {
                            $dotNetVersion = ".NET $($fileVersion.FileMajorPart).x"
                        } else {
                            $dotNetVersion = ".NET Core $($fileVersion.FileMajorPart).$($fileVersion.FileMinorPart)"
                        }
                    }
                    
                    break
                }
            }
        } catch {
            # Access denied or other error
            Write-Log "Error checking process $($Process.ProcessName) (PID: $($Process.Id)): $($_.Exception.Message)" -Level "ERROR"
        }
        
        return [PSCustomObject]@{
            Detected = $dotNetDetected
            Version = $dotNetVersion
            Type = $dotNetType
        }
    }
    
    $allProcesses = Get-Process
    
    # Filter system processes if requested
    if ($NoSystemItems) {
        $systemPaths = @(
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64",
            "$env:SystemRoot\Microsoft.NET"
        )
        
        $allProcesses = $allProcesses | Where-Object {
            if ($_.Path) {
                $inSystemDir = $false
                foreach ($path in $systemPaths) {
                    if ($_.Path -like "$path\*") {
                        $inSystemDir = $true
                        break
                    }
                }
                -not $inSystemDir
            } else {
                # If we can't determine path (needs admin), keep the process
                $true
            }
        }
    }
    
    $processCount = 0
    $totalCount = $allProcesses.Count
    
    foreach ($process in $allProcesses) {
        $processCount++
        
        # Show progress
        if ($processCount % 10 -eq 0) {
            Write-Progress -Activity "Analyzing Processes" -Status "Progress: $processCount of $totalCount" -PercentComplete (($processCount / $totalCount) * 100)
        }
        
        try {
            $dotNetInfo = Get-ProcessDotNetInfo -Process $process
            
            if ($dotNetInfo.Detected) {
                $dotnetProcesses += [PSCustomObject]@{
                    Name = $process.ProcessName
                    PID = $process.Id
                    Path = if ($process.MainModule) { $process.MainModule.FileName } else { "Access denied" }
                    DotNetVersion = $dotNetInfo.Version
                    DotNetType = $dotNetInfo.Type
                    Memory_MB = [math]::Round($process.WorkingSet / 1MB, 2)
                }
                
                Write-Log "Found .NET process: $($process.ProcessName) (PID: $($process.Id)) - $($dotNetInfo.Version)"
            }
        } catch {
            Write-Log "Error analyzing process $($process.ProcessName): $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    Write-Progress -Activity "Analyzing Processes" -Completed
}

# ==== PART 5: Check .NET in Services ====
$dotnetServices = @()
if (-not $SkipServices) {
    Write-Host "Checking .NET usage in Windows services..." -ForegroundColor Green
    
    function Get-FileDotNetVersion {
        param (
            [string]$FilePath
        )
        
        try {
            if (Test-Path $FilePath) {
                # Check for .NET assembly
                try {
                    $assembly = [System.Reflection.Assembly]::LoadFile($FilePath)
                    
                    # Get target framework
                    $targetFramework = $assembly.GetCustomAttributes([System.Runtime.Versioning.TargetFrameworkAttribute], $false)
                    if ($targetFramework -and $targetFramework.Length -gt 0) {
                        $frameworkName = $targetFramework[0].FrameworkName
                        
                        if ($frameworkName -match "^\.NETCoreApp,Version=v(\d+\.\d+)") {
                            return ".NET Core $($matches[1])"
                        } elseif ($frameworkName -match "^\.NETFramework,Version=v(\d+\.\d+)") {
                            return ".NET Framework $($matches[1])"
                        } elseif ($frameworkName -match "^\.NET,Version=v(\d+\.\d+)") {
                            return ".NET $($matches[1])"
                        } else {
                            return "Unknown .NET ($frameworkName)"
                        }
                    } else {
                        # Try to infer from runtime version
                        $runtimeVersion = $assembly.ImageRuntimeVersion
                        if ($runtimeVersion -match "^v(\d+)\.(\d+)") {
                            $major = [int]$matches[1]
                            $minor = [int]$matches[2]
                            
                            if ($major -eq 4) {
                                return ".NET Framework 4.x"
                            } elseif ($major -eq 2) {
                                return ".NET Framework 2.0/3.5"
                            } else {
                                return ".NET Runtime v$major.$minor"
                            }
                        }
                    }
                    
                    return ".NET (detected)"
                } catch {
                    # Not a .NET assembly or couldn't load
                    return "Not .NET"
                }
            }
        } catch {
            # File not found or access denied
            return "Error: $($_.Exception.Message)"
        }
        
        return "Not .NET"
    }
    
    $allServices = Get-Service | Where-Object { $_.Status -eq 'Running' }
    
    # Filter system services if requested
    if ($NoSystemItems) {
        $systemServiceNames = @(
            "wuauserv", "WSearch", "WinDefend", "Dhcp", "Dnscache", 
            "LanmanServer", "LanmanWorkstation", "MSDTC", "PlugPlay", 
            "SamSs", "Schedule", "SENS", "Spooler", "W32Time", "winmgmt"
        )
        
        $allServices = $allServices | Where-Object { $systemServiceNames -notcontains $_.Name }
    }
    
    $serviceCount = 0
    $totalCount = $allServices.Count
    
    foreach ($service in $allServices) {
        $serviceCount++
        
        # Show progress
        if ($serviceCount % 5 -eq 0) {
            Write-Progress -Activity "Analyzing Services" -Status "Progress: $serviceCount of $totalCount" -PercentComplete (($serviceCount / $totalCount) * 100)
        }
        
        try {
            $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            
            if ($wmiService -and $wmiService.PathName) {
                $exePath = $wmiService.PathName -replace '^"([^"]+)".*$', '$1'
                $exePath = $exePath -replace "^'([^']+)'.*$", '$1'
                
                $dotNetVersion = "Unknown"
                
                # Try to find process associated with service
                $serviceProcess = Get-Process -Id $wmiService.ProcessId -ErrorAction SilentlyContinue
                if ($serviceProcess) {
                    # Check .NET in process
                    $dotNetInfo = Get-ProcessDotNetInfo -Process $serviceProcess
                    if ($dotNetInfo.Detected) {
                        $dotNetVersion = $dotNetInfo.Version
                    }
                } else {
                    # Check executable file directly
                    $dotNetVersion = Get-FileDotNetVersion -FilePath $exePath
                }
                
                # If we found .NET usage
                if ($dotNetVersion -ne "Unknown" -and $dotNetVersion -ne "Not .NET") {
                    $dotnetServices += [PSCustomObject]@{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        ExecutablePath = $exePath
                        DotNetVersion = $dotNetVersion
                        ProcessId = $wmiService.ProcessId
                        StartMode = $wmiService.StartMode
                        Account = $wmiService.StartName
                    }
                    
                    Write-Log "Found .NET service: $($service.Name) ($($service.DisplayName)) - $dotNetVersion"
                }
            }
        } catch {
            Write-Log "Error analyzing service $($service.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    Write-Progress -Activity "Analyzing Services" -Completed
}

# ==== PART 6: Check .NET in Task Scheduler ====
$dotnetTasks = @()
if (-not $SkipTasks) {
    Write-Host "Checking .NET usage in scheduled tasks..." -ForegroundColor Green
    
    $allTasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
    
    # Filter system tasks if requested
    if ($NoSystemItems) {
        $allTasks = $allTasks | Where-Object { $_.TaskPath -notlike "\Microsoft\Windows\*" }
    }
    
    $taskCount = 0
    $totalCount = $allTasks.Count
    
    foreach ($task in $allTasks) {
        $taskCount++
        
        # Show progress
        if ($taskCount % 10 -eq 0) {
            Write-Progress -Activity "Analyzing Scheduled Tasks" -Status "Progress: $taskCount of $totalCount" -PercentComplete (($taskCount / $totalCount) * 100)
        }
        
        try {
            $actions = $task.Actions
            
            foreach ($action in $actions) {
                if ($action.Execute) {
                    # Clean up executable path
                    $exePath = $action.Execute -replace '^"([^"]+)".*$', '$1'
                    $exePath = $exePath -replace "^'([^']+)'.*$", '$1'
                    
                    # Handle system environment variables
                    try {
                        $exePath = [System.Environment]::ExpandEnvironmentVariables($exePath)
                    } catch {
                        Write-Log "Error expanding environment variables in path: $exePath" -Level "ERROR"
                    }
                    
                    if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                        $dotNetVersion = Get-FileDotNetVersion -FilePath $exePath
                        
                        if ($dotNetVersion -ne "Not .NET") {
                            # Get RunAs information
                            $runAsUser = "Unknown"
                            try {
                                $taskXml = [xml]$task.XML
                                $principal = $taskXml.Task.Principals.Principal
                                if ($principal) {
                                    $runAsUser = $principal.UserId
                                    if (-not $runAsUser) {
                                        if ($principal.GroupId) {
                                            $runAsUser = $principal.GroupId
                                        } else {
                                            $runAsUser = if ($principal.RunLevel -eq "HighestAvailable") { "Elevated Rights" } else { "Standard User" }
                                        }
                                    }
                                }
                            } catch {
                                Write-Log "Error getting task details for $($task.TaskName): $($_.Exception.Message)" -Level "ERROR"
                            }
                            
                            $dotnetTasks += [PSCustomObject]@{
                                TaskName = $task.TaskName
                                TaskPath = $task.TaskPath
                                ExecutablePath = $exePath
                                DotNetVersion = $dotNetVersion
                                RunAsUser = $runAsUser
                                State = $task.State
                                Arguments = $action.Arguments
                            }
                            
                            Write-Log "Found .NET task: $($task.TaskName) - $dotNetVersion"
                        }
                    }
                    
                    break  # Only process the first action with an executable
                }
            }
        } catch {
            Write-Log "Error analyzing task $($task.TaskName): $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    Write-Progress -Activity "Analyzing Scheduled Tasks" -Completed
}

# ==== PART 7: Export Results ====
Write-Host "`nExporting results to CSV files..." -ForegroundColor Green

# Combine Core and Standard installations to a complete picture
$allDotNetCore = $dotnetRuntimes
if ($dotnetCoreInstalled.Count -gt 0) {
    foreach ($core in $dotnetCoreInstalled) {
        # Only add if not already in the list
        if (-not ($allDotNetCore | Where-Object { $_.Version -eq $core.Version -and $_.Type -eq $core.Type })) {
            $allDotNetCore += $core
        }
    }
}

Export-Results -Data $dotnetSdks -FileName "DotNet_SDKs"
Export-Results -Data $allDotNetCore -FileName "DotNet_Core_Runtimes"
Export-Results -Data $dotnetFrameworks -FileName "DotNet_Framework_Versions"
Export-Results -Data $dotnetProcesses -FileName "DotNet_Processes"
Export-Results -Data $dotnetServices -FileName "DotNet_Services"
Export-Results -Data $dotnetTasks -FileName "DotNet_Tasks"

# ==== PART 8: Display Summary ====
Write-Host "`n=======================================================" -ForegroundColor Cyan
Write-Host "               SUMMARY REPORT                         " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# Framework summary
Write-Host "INSTALLED .NET FRAMEWORK VERSIONS:" -ForegroundColor Green
if ($dotnetFrameworks.Count -gt 0) {
    $dotnetFrameworks | ForEach-Object {
        $versionDesc = $_.Version
        if ($_.ServicePack) { $versionDesc += " SP$($_.ServicePack)" }
        
        Write-Host "  - $versionDesc" -ForegroundColor White
        Write-Host "    Path: $($_.InstallPath)" -ForegroundColor Gray
    }
} else {
    Write-Host "  No .NET Framework installations detected" -ForegroundColor Yellow
}
Write-Host ""

# Core summary
Write-Host "INSTALLED .NET CORE/.NET VERSIONS:" -ForegroundColor Green
if ($allDotNetCore.Count -gt 0) {
    $runtimeTypeGroups = $allDotNetCore | Group-Object -Property Type
    foreach ($group in $runtimeTypeGroups) {
        Write-Host "  $($group.Name):" -ForegroundColor White
        $sortedVersions = $group.Group | Sort-Object Version -Descending
        foreach ($version in $sortedVersions) {
            Write-Host "    - $($version.Version)" -ForegroundColor White
            Write-Host "      Path: $($version.InstallPath)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "  No .NET Core/.NET installations detected" -ForegroundColor Yellow
}
Write-Host ""

# SDK summary
Write-Host ".NET SDK VERSIONS:" -ForegroundColor Green
if ($dotnetSdks.Count -gt 0) {
    $sortedSdks = $dotnetSdks | Sort-Object Version -Descending
    foreach ($sdk in $sortedSdks) {
        Write-Host "  - $($sdk.Version)" -ForegroundColor White
        Write-Host "    Path: $($sdk.InstallPath)" -ForegroundColor Gray
    }
} else {
    Write-Host "  No .NET SDKs detected" -ForegroundColor Yellow
}
Write-Host ""

# Process summary
if (-not $SkipProcesses) {
    Write-Host ".NET PROCESSES:" -ForegroundColor Green
    if ($dotnetProcesses.Count -gt 0) {
        $runtimeTypeGroups = $dotnetProcesses | Group-Object -Property DotNetType
        foreach ($group in $runtimeTypeGroups) {
            Write-Host "  $($group.Name) ($($group.Group.Count) processes):" -ForegroundColor White
            
            # Show top memory consumers first
            $topProcesses = $group.Group | Sort-Object Memory_MB -Descending | Select-Object -First 5
            foreach ($process in $topProcesses) {
                Write-Host "    - $($process.Name) (PID: $($process.PID))" -ForegroundColor White
                Write-Host "      Version: $($process.DotNetVersion)" -ForegroundColor Gray
                Write-Host "      Memory: $($process.Memory_MB) MB" -ForegroundColor Gray
            }
            
            if ($group.Group.Count -gt 5) {
                Write-Host "    - ... and $($group.Group.Count - 5) more" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "  No .NET processes detected" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Service summary
if (-not $SkipServices) {
    Write-Host ".NET SERVICES:" -ForegroundColor Green
    if ($dotnetServices.Count -gt 0) {
        foreach ($service in $dotnetServices) {
            Write-Host "  - $($service.Name) ($($service.DisplayName))" -ForegroundColor White
            Write-Host "    Version: $($service.DotNetVersion)" -ForegroundColor Gray
            Write-Host "    Path: $($service.ExecutablePath)" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No .NET services detected" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Task summary
if (-not $SkipTasks) {
    Write-Host ".NET SCHEDULED TASKS:" -ForegroundColor Green
    if ($dotnetTasks.Count -gt 0) {
        foreach ($task in $dotnetTasks) {
            Write-Host "  - $($task.TaskName)" -ForegroundColor White
            Write-Host "    Version: $($task.DotNetVersion)" -ForegroundColor Gray
            Write-Host "    Path: $($task.ExecutablePath)" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No .NET scheduled tasks detected" -ForegroundColor Yellow
    }
    Write-Host ""
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "Results have been saved to: $resultsDir" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Cyan
