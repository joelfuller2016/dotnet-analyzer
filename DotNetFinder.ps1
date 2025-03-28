# DotNetFinder.ps1
# Comprehensive .NET Detection Script - Finds all .NET versions and locations on a system
# Version: 1.0

param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipProcesses,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipServices,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTasks,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$QuickScan
)

# Initialize
$Results = @()
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = "$env:TEMP\DotNetFinder_$timestamp.log"

# Start logging
"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] .NET Finder Started" | Out-File -FilePath $LogFile

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

# Display banner
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "                  .NET FINDER SCRIPT                      " -ForegroundColor Cyan
Write-Host "      Locates all .NET versions across your system        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# Check for dotnet CLI
$dotnetPath = Get-Command dotnet -ErrorAction SilentlyContinue
$hasDotNetCLI = ($null -ne $dotnetPath)

if ($hasDotNetCLI) {
    Write-Log "Detected dotnet CLI. Checking SDK versions..." -Level SUCCESS
    
    try {
        $dotnetInfo = dotnet --info
        $sdkSection = $dotnetInfo | Select-String -Pattern ".NET SDKs installed:" -Context 0,10
        $runtimeSection = $dotnetInfo | Select-String -Pattern ".NET runtimes installed:" -Context 0,20
        
        # Parse SDK versions
        foreach ($line in $sdkSection) {
            if ($line -match '\s+(\d+\.\d+\.\d+)\s+\[(.+)\]') {
                $version = $matches[1]
                $path = $matches[2]
                
                $Results += [PSCustomObject]@{
                    Type = ".NET SDK"
                    Version = $version
                    Location = $path
                    Source = "dotnet CLI"
                    Component = "SDK"
                }
                
                Write-Log "Found .NET SDK $version at $path"
            }
        }
        
        # Parse runtime versions
        foreach ($line in $runtimeSection) {
            if ($line -match '\s+Microsoft\.(\w+)\.App\s+(\d+\.\d+\.\d+)\s+\[(.+)\]') {
                $type = $matches[1]
                $version = $matches[2]
                $path = $matches[3]
                
                $Results += [PSCustomObject]@{
                    Type = ".$type Runtime"
                    Version = $version
                    Location = $path
                    Source = "dotnet CLI"
                    Component = "Runtime"
                }
                
                Write-Log "Found .$type Runtime $version at $path"
            }
        }
    } catch {
        Write-Log "Error retrieving dotnet CLI information: $($_.Exception.Message)" -Level ERROR
    }
} else {
    Write-Log "dotnet CLI not found. Skipping SDK detection." -Level WARNING
}

# Get .NET Framework versions from registry
Write-Log "Scanning for .NET Framework from registry..." -Level SUCCESS

$ndpKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP"
if (Test-Path $ndpKey) {
    # Get .NET Framework 1.0 and 1.1
    $netFx10 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\Policy\v1.0" -ErrorAction SilentlyContinue
    if ($netFx10) {
        $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v1.0.3705"
        
        $Results += [PSCustomObject]@{
            Type = ".NET Framework"
            Version = "1.0"
            Location = $installPath
            Source = "Registry"
            Component = "Runtime"
        }
        
        Write-Log "Found .NET Framework 1.0 at $installPath"
    }
    
    $netFx11 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v1.1.4322" -ErrorAction SilentlyContinue
    if ($netFx11) {
        $sp = if ($netFx11.SP) { " SP$($netFx11.SP)" } else { "" }
        $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v1.1.4322"
        
        $Results += [PSCustomObject]@{
            Type = ".NET Framework"
            Version = "1.1$sp"
            Location = $installPath
            Source = "Registry"
            Component = "Runtime"
        }
        
        Write-Log "Found .NET Framework 1.1$sp at $installPath"
    }
    
    # Get .NET Framework 2.0, 3.0, 3.5
    $v2To35 = Get-ChildItem $ndpKey | Where-Object { $_.PSChildName -match "^v[23]" }
    foreach ($versionKey in $v2To35) {
        $version = $versionKey.PSChildName.Substring(1)
        
        # Check if installed
        $installed = (Get-ItemProperty -Path $versionKey.PSPath -Name Install -ErrorAction SilentlyContinue).Install
        if ($installed -eq 1) {
            $sp = (Get-ItemProperty -Path $versionKey.PSPath -Name SP -ErrorAction SilentlyContinue).SP
            $spText = if ($sp) { " SP$sp" } else { "" }
            $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v2.0.50727"
            
            $Results += [PSCustomObject]@{
                Type = ".NET Framework"
                Version = "$version$spText"
                Location = $installPath
                Source = "Registry"
                Component = "Runtime"
            }
            
            Write-Log "Found .NET Framework $version$spText at $installPath"
        }
        
        # Check subversions
        $subkeys = Get-ChildItem $versionKey.PSPath -ErrorAction SilentlyContinue
        foreach ($subkey in $subkeys) {
            $installed = (Get-ItemProperty -Path $subkey.PSPath -Name Install -ErrorAction SilentlyContinue).Install
            if ($installed -eq 1) {
                $sp = (Get-ItemProperty -Path $subkey.PSPath -Name SP -ErrorAction SilentlyContinue).SP
                $spText = if ($sp) { " SP$sp" } else { "" }
                $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v2.0.50727"
                
                $Results += [PSCustomObject]@{
                    Type = ".NET Framework"
                    Version = "$version$spText (Profile: $($subkey.PSChildName))"
                    Location = $installPath
                    Source = "Registry"
                    Component = "Runtime"
                }
                
                Write-Log "Found .NET Framework $version$spText (Profile: $($subkey.PSChildName)) at $installPath"
            }
        }
    }
    
    # Get .NET Framework 4.0+
    $v4Key = Get-ChildItem $ndpKey | Where-Object { $_.PSChildName -eq "v4" -or $_.PSChildName -eq "v4.0" }
    if ($v4Key) {
        foreach ($subkey in Get-ChildItem $v4Key.PSPath) {
            $installed = (Get-ItemProperty -Path $subkey.PSPath -Name Install -ErrorAction SilentlyContinue).Install
            if ($installed -eq 1) {
                $release = (Get-ItemProperty -Path $subkey.PSPath -Name Release -ErrorAction SilentlyContinue).Release
                $sp = (Get-ItemProperty -Path $subkey.PSPath -Name SP -ErrorAction SilentlyContinue).SP
                $spText = if ($sp) { " SP$sp" } else { "" }
                $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
                
                # Translate release number to version
                $version = "4.0$spText"
                if ($release) {
                    $version = switch ($release) {
                        378389 { "4.5" }
                        378675 { "4.5.1" }
                        378758 { "4.5.1" }
                        379893 { "4.5.2" }
                        393295 { "4.6" }
                        393297 { "4.6" }
                        394254 { "4.6.1" }
                        394271 { "4.6.1" }
                        394802 { "4.6.2" }
                        394806 { "4.6.2" }
                        460798 { "4.7" }
                        460805 { "4.7" }
                        461308 { "4.7.1" }
                        461310 { "4.7.1" }
                        461808 { "4.7.2" }
                        461814 { "4.7.2" }
                        528040 { "4.8" }
                        528049 { "4.8" }
                        528209 { "4.8.1" }
                        528372 { "4.8.1" }
                        528449 { "4.8.1" }
                        533320 { "4.8.1" }
                        default { "4.x (Release $release)" }
                    }
                }
                
                $Results += [PSCustomObject]@{
                    Type = ".NET Framework"
                    Version = $version
                    Location = $installPath
                    Source = "Registry"
                    Component = "Runtime"
                }
                
                Write-Log "Found .NET Framework $version at $installPath"
            }
        }
    }
}

# Get .NET Core/.NET 5+ versions from file system
Write-Log "Scanning for .NET Core/.NET from file system..." -Level SUCCESS

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
        Get-ChildItem -Path $runtimePath -Directory | ForEach-Object {
            $type = switch -Wildcard ($runtimePath) {
                "*Microsoft.AspNetCore.App*" { "ASP.NET Core" }
                "*Microsoft.WindowsDesktop.App*" { ".NET Desktop" }
                default { ".NET Core/.NET" }
            }
            
            $Results += [PSCustomObject]@{
                Type = $type
                Version = $_.Name
                Location = $_.FullName
                Source = "FileSystem"
                Component = "Runtime"
            }
            
            Write-Log "Found $type runtime $($_.Name) at $($_.FullName)"
        }
    }
}

# Find .NET Core SDK versions
$sdkPaths = @(
    (Join-Path $env:ProgramFiles "dotnet\sdk"),
    (Join-Path ${env:ProgramFiles(x86)} "dotnet\sdk")
)

foreach ($sdkPath in $sdkPaths) {
    if (Test-Path $sdkPath) {
        Get-ChildItem -Path $sdkPath -Directory | ForEach-Object {
            $Results += [PSCustomObject]@{
                Type = ".NET SDK"
                Version = $_.Name
                Location = $_.FullName
                Source = "FileSystem"
                Component = "SDK"
            }
            
            Write-Log "Found .NET SDK $($_.Name) at $($_.FullName)"
        }
    }
}

# Analyze running processes (if not skipped)
if (-not $SkipProcesses) {
    Write-Log "Scanning running processes for .NET components..." -Level SUCCESS
    
    $processes = Get-Process
    $dotNetProcesses = 0
    
    foreach ($process in $processes) {
        try {
            # Skip if we can't access the process modules
            if (-not $process.Modules) {
                continue
            }
            
            $isDotNet = $false
            $netFramework = $false
            $netCore = $false
            $version = "Unknown"
            
            # Check common .NET modules
            foreach ($module in $process.Modules) {
                $moduleName = $module.ModuleName.ToLower()
                
                if ($moduleName -eq "mscorlib.dll" -or $moduleName -eq "clr.dll" -or $moduleName -eq "system.dll") {
                    $isDotNet = $true
                    $netFramework = $true
                    
                    # Try to get version info
                    try {
                        if ($moduleName -eq "mscorlib.dll" -or $moduleName -eq "clr.dll") {
                            $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($module.FileName)
                            
                            # Match version to .NET Framework
                            if ($fileVersion.FileMajorPart -eq 2) {
                                $version = ".NET Framework 2.0/3.5"
                            } elseif ($fileVersion.FileMajorPart -eq 4) {
                                $version = ".NET Framework 4.x"
                            }
                        }
                    } catch {
                        # Just use generic framework version
                        $version = ".NET Framework"
                    }
                } elseif ($moduleName -eq "coreclr.dll" -or $moduleName -eq "hostpolicy.dll" -or 
                          $moduleName -eq "system.private.corelib.dll") {
                    $isDotNet = $true
                    $netCore = $true
                    
                    # Try to get version info
                    try {
                        $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($module.FileName)
                        
                        if ($fileVersion.FileMajorPart -ge 5) {
                            $version = ".NET $($fileVersion.FileMajorPart).x"
                        } else {
                            $version = ".NET Core $($fileVersion.FileMajorPart).$($fileVersion.FileMinorPart)"
                        }
                    } catch {
                        # Just use generic core version
                        $version = ".NET Core/.NET"
                    }
                }
                
                if ($isDotNet) {
                    break
                }
            }
            
            if ($isDotNet) {
                $dotNetProcesses++
                
                # Get main module path
                $location = if ($process.MainModule) {
                    $process.MainModule.FileName
                } else {
                    "Unknown (access denied)"
                }
                
                $Results += [PSCustomObject]@{
                    Type = if ($netCore) { ".NET Core/.NET" } else { ".NET Framework" }
                    Version = $version
                    Location = $location
                    Source = "Process"
                    Component = "$($process.ProcessName) (PID: $($process.Id))"
                }
                
                Write-Log "Found $version process: $($process.ProcessName) (PID: $($process.Id))"
            }
        } catch {
            # Skip processes we can't access (requires admin privileges)
        }
        
        # Limit to first 100 for QuickScan
        if ($QuickScan -and $dotNetProcesses -gt 100) {
            Write-Log "Quick scan limit reached. Stopping process scan after 100 .NET processes." -Level WARNING
            break
        }
    }
}

# Analyze services (if not skipped)
if (-not $SkipServices) {
    Write-Log "Scanning services for .NET components..." -Level SUCCESS
    
    $services = Get-Service | Where-Object { $_.Status -eq 'Running' }
    $dotNetServices = 0
    
    foreach ($service in $services) {
        try {
            $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            
            if ($serviceInfo -and $serviceInfo.PathName) {
                # Extract executable path
                $exePath = $serviceInfo.PathName -replace '^"([^"]+)".*$', '$1'
                $exePath = $exePath -replace "^'([^']+)'.*$", '$1'
                
                # If it's svchost, check for DLL
                if ($exePath -like "*\svchost.exe*") {
                    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)\Parameters"
                    
                    if (Test-Path $registryPath) {
                        $serviceDll = (Get-ItemProperty -Path $registryPath -Name "ServiceDll" -ErrorAction SilentlyContinue).ServiceDll
                        
                        if ($serviceDll) {
                            $dotNetVersion = Get-FileDotNetVersion -FilePath $serviceDll
                            
                            if ($dotNetVersion -ne "Not .NET") {
                                $dotNetServices++
                                
                                $Results += [PSCustomObject]@{
                                    Type = $dotNetVersion -replace ' .*$'
                                    Version = $dotNetVersion -replace '^[^0-9]*'
                                    Location = $serviceDll
                                    Source = "Service (DLL)"
                                    Component = "$($service.Name) ($($service.DisplayName))"
                                }
                                
                                Write-Log "Found $dotNetVersion service DLL: $($service.Name) at $serviceDll"
                            }
                        }
                    }
                } else {
                    # Try to analyze executable directly
                    $dotNetVersion = Get-FileDotNetVersion -FilePath $exePath
                    
                    if ($dotNetVersion -ne "Not .NET") {
                        $dotNetServices++
                        
                        $Results += [PSCustomObject]@{
                            Type = $dotNetVersion -replace ' .*$'
                            Version = $dotNetVersion -replace '^[^0-9]*'
                            Location = $exePath
                            Source = "Service (EXE)"
                            Component = "$($service.Name) ($($service.DisplayName))"
                        }
                        
                        Write-Log "Found $dotNetVersion service: $($service.Name) at $exePath"
                    }
                }
            }
        } catch {
            # Skip services we can't access (requires admin privileges)
        }
        
        # Limit for QuickScan
        if ($QuickScan -and $dotNetServices -gt 50) {
            Write-Log "Quick scan limit reached. Stopping service scan after 50 .NET services." -Level WARNING
            break
        }
    }
}

# Analyze tasks (if not skipped)
if (-not $SkipTasks) {
    Write-Log "Scanning scheduled tasks for .NET components..." -Level SUCCESS
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
        $dotNetTasks = 0
        
        foreach ($task in $tasks) {
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
                            # Skip environment variable expansion if it fails
                        }
                        
                        if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                            $dotNetVersion = Get-FileDotNetVersion -FilePath $exePath
                            
                            if ($dotNetVersion -ne "Not .NET") {
                                $dotNetTasks++
                                
                                $Results += [PSCustomObject]@{
                                    Type = $dotNetVersion -replace ' .*$'
                                    Version = $dotNetVersion -replace '^[^0-9]*'
                                    Location = $exePath
                                    Source = "Scheduled Task"
                                    Component = "$($task.TaskName)"
                                }
                                
                                Write-Log "Found $dotNetVersion scheduled task: $($task.TaskName) at $exePath"
                            }
                        }
                        
                        break  # Only check first action with executable
                    }
                }
            } catch {
                # Skip tasks we can't access
            }
            
            # Limit for QuickScan
            if ($QuickScan -and $dotNetTasks -gt 50) {
                Write-Log "Quick scan limit reached. Stopping task scan after 50 .NET tasks." -Level WARNING
                break
            }
        }
    } catch {
        Write-Log "Error scanning scheduled tasks: $($_.Exception.Message)" -Level ERROR
    }
}

# Display results
Write-Host ""
Write-Host "=========== .NET COMPONENT SUMMARY ===========" -ForegroundColor Green
Write-Host "Found $($Results.Count) .NET components on this system" -ForegroundColor Green
Write-Host ""

# Group by Type
$Results | Group-Object -Property Type | ForEach-Object {
    Write-Host "$($_.Name) ($($_.Count) components)" -ForegroundColor Yellow
    
    # Sort and display versions
    $uniqueVersions = $_.Group | Select-Object -Property Version -Unique
    foreach ($version in $uniqueVersions) {
        Write-Host "  - $($version.Version)" -ForegroundColor White
    }
    Write-Host ""
}

# Export results to file if specified
if ($OutputFile -ne "") {
    try {
        $Results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Log "Results exported to $OutputFile" -Level SUCCESS
    } catch {
        Write-Log "Error exporting results: $($_.Exception.Message)" -Level ERROR
    }
} else {
    # Default output in temp dir
    $defaultOutput = "$env:TEMP\DotNetFinder_$timestamp.csv"
    $Results | Export-Csv -Path $defaultOutput -NoTypeInformation
    Write-Log "Results exported to $defaultOutput" -Level SUCCESS
}

Write-Host "Full details saved to log file: $LogFile" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan