# DotNetVersionFinder.ps1
# Scans the system for all .NET versions and lists files organized by version
# Provides a clear outline to identify applications that need updating

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportAsHTML,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSystemComponents,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeServerComponents,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeASPNET
)

# Initialize
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = "$env:TEMP\DotNetVersionFinder_$timestamp.log"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$dotNetComponents = @{}
$systemPaths = @("$env:windir\Microsoft.NET", "$env:windir\assembly", "$env:windir\System32", "$env:windir\SysWOW64")

# Start logging
"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] .NET Version Finder Started" | Out-File -FilePath $LogFile

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
    
    $dotNetVersion = $null
    
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
                                    # It's a .NET assembly!
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
                                                $dotNetVersion = "$tfm"
                                            }
                                        } else {
                                            # Fallback to imageruntime version
                                            $runtimeInfo = $assembly.ImageRuntimeVersion
                                            if ($runtimeInfo -match "^v(\d+\.\d+)") {
                                                $version = $matches[1]
                                                if ($version -eq "4.0") {
                                                    $dotNetVersion = ".NET Framework 4.0"
                                                } elseif ($version -eq "2.0") {
                                                    $dotNetVersion = ".NET Framework 2.0"
                                                } else {
                                                    $dotNetVersion = ".NET Runtime v$version"
                                                }
                                            } else {
                                                $dotNetVersion = "$runtimeInfo"
                                            }
                                        }
                                    } catch {
                                        # Still a .NET assembly but can't get details
                                        $dotNetVersion = ".NET (Unknown Version)"
                                    }
                                }
                            }
                        }
                    }
                }
            } catch {
                # File access error, silently continue
            }
        }
    } catch {
        # General error, silently continue
    }
    
    return $dotNetVersion
}

function Is-SystemComponent {
    param([string]$Path)
    
    # Check if the path is in one of the system folders
    foreach ($systemPath in $systemPaths) {
        if ($Path -like "$systemPath*") {
            return $true
        }
    }
    
    # Check common system DLLs and executables
    $systemFiles = @("mscorlib.dll", "System.dll", "System.*.dll", "Microsoft.*.dll")
    $fileName = Split-Path -Leaf $Path
    
    foreach ($pattern in $systemFiles) {
        if ($fileName -like $pattern) {
            # Make exception for specific user apps that use Microsoft.* naming
            if ($Path -like "*\Program Files*" -and -not ($Path -like "*\Windows\*")) {
                return $false
            }
            return $true
        }
    }
    
    return $false
}

function Add-DotNetComponent {
    param(
        [string]$Version,
        [string]$FilePath,
        [string]$ComponentType,
        [string]$Context = ""
    )
    
    # Skip if we should exclude system components
    if ($SkipSystemComponents -and (Is-SystemComponent -Path $FilePath)) {
        return
    }
    
    # Skip ASP.NET unless specifically included
    if (-not $IncludeASPNET -and ($Version -like "*ASP.NET*")) {
        return
    }
    
    # Skip server components unless specifically included
    $isServerComponent = $FilePath -like "*\Windows\Microsoft.NET\Framework*\ASP.NET*" -or 
                         $FilePath -like "*\inetpub\*" -or 
                         $FilePath -like "*\Windows\System32\inetsrv\*"
    
    if (-not $IncludeServerComponents -and $isServerComponent) {
        return
    }
    
    # Create the key if it doesn't exist
    if (-not $dotNetComponents.ContainsKey($Version)) {
        $dotNetComponents[$Version] = @()
    }
    
    # Add the component
    $component = [PSCustomObject]@{
        Path = $FilePath
        Type = $ComponentType
        Context = $Context
    }
    
    # Check if this is a duplicate
    $exists = $false
    foreach ($item in $dotNetComponents[$Version]) {
        if ($item.Path -eq $FilePath -and $item.Type -eq $ComponentType) {
            $exists = $true
            break
        }
    }
    
    if (-not $exists) {
        $dotNetComponents[$Version] += $component
    }
}

# Display banner
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                .NET VERSION FINDER                          " -ForegroundColor Cyan
Write-Host "      Lists all .NET versions and associated files           " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $isAdmin) {
    Write-Host "Note: Running without admin privileges. Some results may be limited." -ForegroundColor Yellow
    Write-Host ""
}

# Find installed .NET Framework versions
Write-Host "Checking installed .NET Framework versions..." -ForegroundColor Green

# From registry
$ndpKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP"
if (Test-Path $ndpKey) {
    # .NET Framework 4.5 and later
    $v4RegKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
    if (Test-Path $v4RegKey) {
        $release = (Get-ItemProperty $v4RegKey).Release
        
        $version = switch ($release) {
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
            default { ".NET Framework 4.x (Release $release)" }
        }
        
        $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
        Add-DotNetComponent -Version $version -FilePath $installPath -ComponentType "Runtime" -Context "System Installed"
        Write-Log "Found $version at $installPath"
    }
    
    # Check for .NET 3.5
    $v35RegKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5"
    if (Test-Path $v35RegKey) {
        $installed = (Get-ItemProperty $v35RegKey).Install
        if ($installed -eq 1) {
            $sp = (Get-ItemProperty $v35RegKey).SP
            $version = ".NET Framework 3.5"
            if ($sp -gt 0) { $version += " SP$sp" }
            
            $installPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v2.0.50727"
            Add-DotNetComponent -Version $version -FilePath $installPath -ComponentType "Runtime" -Context "System Installed"
            Write-Log "Found $version at $installPath"
        }
    }
}

# Check for .NET Core and .NET 5+
Write-Host "Checking installed .NET Core and .NET 5+ versions..." -ForegroundColor Green

# First use dotnet --info if available
$dotnetExe = Get-Command dotnet -ErrorAction SilentlyContinue
if ($dotnetExe) {
    try {
        $dotnetInfo = dotnet --info
        
        # Parse SDK versions
        $sdkMatch = $dotnetInfo | Select-String -Pattern ".NET SDKs installed:" -Context 0,20
        if ($sdkMatch) {
            foreach ($line in $sdkMatch.Context.PostContext) {
                if ($line -match '\s+(\d+\.\d+\.\d+)\s+\[(.+)\]') {
                    $sdkVersion = $matches[1]
                    $sdkPath = $matches[2]
                    
                    # Determine .NET version from SDK version
                    $majorMinor = $sdkVersion -replace '(\d+\.\d+).*', '$1'
                    $dotNetVersion = if ([double]$majorMinor -ge 5.0) {
                        ".NET $majorMinor"
                    } else {
                        ".NET Core $majorMinor"
                    }
                    
                    Add-DotNetComponent -Version $dotNetVersion -FilePath $sdkPath -ComponentType "SDK" -Context "System Installed"
                    Write-Log "Found $dotNetVersion SDK $sdkVersion at $sdkPath"
                }
            }
        }
        
        # Parse runtime versions
        $runtimeMatch = $dotnetInfo | Select-String -Pattern ".NET runtimes installed:" -Context 0,30
        if ($runtimeMatch) {
            foreach ($line in $runtimeMatch.Context.PostContext) {
                if ($line -match '\s+Microsoft\.(\w+)\.App\s+(\d+\.\d+\.\d+).*\[(.+)\]') {
                    $runtimeType = $matches[1]
                    $runtimeVersion = $matches[2]
                    $runtimePath = $matches[3]
                    
                    # Format runtime version
                    $majorMinor = $runtimeVersion -replace '(\d+\.\d+).*', '$1'
                    $dotNetVersion = if ([double]$majorMinor -ge 5.0) {
                        ".NET $majorMinor"
                    } else {
                        ".NET Core $majorMinor"
                    }
                    
                    # Add context for special runtimes
                    $context = "System Installed"
                    if ($runtimeType -eq "AspNetCore") {
                        $dotNetVersion = "ASP.NET Core $majorMinor"
                        $context = "ASP.NET Core Runtime"
                    } elseif ($runtimeType -eq "WindowsDesktop") {
                        $context = "Windows Desktop Runtime"
                    }
                    
                    Add-DotNetComponent -Version $dotNetVersion -FilePath $runtimePath -ComponentType "Runtime" -Context $context
                    Write-Log "Found $dotNetVersion Runtime $runtimeVersion at $runtimePath"
                }
            }
        }
    } catch {
        Write-Log "Error getting dotnet CLI info: $($_.Exception.Message)" -Level ERROR
    }
}

# Also check file system for .NET Core
$runtimePaths = @(
    "$env:ProgramFiles\dotnet\shared\Microsoft.NETCore.App",
    "${env:ProgramFiles(x86)}\dotnet\shared\Microsoft.NETCore.App"
)

foreach ($path in $runtimePaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Directory | ForEach-Object {
            $version = $_.Name
            $majorMinor = $version -replace '(\d+\.\d+).*', '$1'
            $dotNetVersion = if ([double]$majorMinor -ge 5.0) {
                ".NET $majorMinor"
            } else {
                ".NET Core $majorMinor"
            }
            
            Add-DotNetComponent -Version $dotNetVersion -FilePath $_.FullName -ComponentType "Runtime" -Context "System Installed"
            Write-Log "Found $dotNetVersion Runtime $version at $($_.FullName)"
        }
    }
}

# Scan running processes
Write-Host "Scanning running processes for .NET components..." -ForegroundColor Green

$processes = Get-Process
$processCount = 0

foreach ($process in $processes) {
    try {
        # Skip if we can't access the process modules
        if (-not $process.Modules) {
            continue
        }
        
        # Check for .NET modules
        $isDotNet = $false
        $dotNetVersion = $null
        
        # Use MainModule path if available
        if ($process.MainModule) {
            $mainModulePath = $process.MainModule.FileName
            $dotNetVersion = Get-FileDotNetVersion -FilePath $mainModulePath
            
            if ($dotNetVersion) {
                $isDotNet = $true
                $context = "$($process.ProcessName) (PID: $($process.Id))"
                Add-DotNetComponent -Version $dotNetVersion -FilePath $mainModulePath -ComponentType "Process" -Context $context
                Write-Log "Found $dotNetVersion process: $($process.ProcessName) at $mainModulePath"
                $processCount++
            }
        }
        
        # If main module doesn't have version, check others
        if (-not $isDotNet) {
            foreach ($module in $process.Modules) {
                if ($module.ModuleName -eq "mscorlib.dll" -or 
                    $module.ModuleName -eq "coreclr.dll" -or 
                    $module.ModuleName -eq "System.Private.CoreLib.dll") {
                    
                    $dotNetVersion = Get-FileDotNetVersion -FilePath $module.FileName
                    if ($dotNetVersion) {
                        $context = "$($process.ProcessName) (PID: $($process.Id))"
                        $modulePath = if ($process.MainModule) { $process.MainModule.FileName } else { $module.FileName }
                        Add-DotNetComponent -Version $dotNetVersion -FilePath $modulePath -ComponentType "Process" -Context $context
                        Write-Log "Found $dotNetVersion process (via module): $($process.ProcessName) at $modulePath"
                        $processCount++
                        break
                    }
                }
            }
        }
    } catch {
        # Skip processes we can't access
    }
}

Write-Host "Found $processCount .NET processes" -ForegroundColor Gray

# Scan services
Write-Host "Scanning Windows services for .NET components..." -ForegroundColor Green

$services = Get-Service | Where-Object { $_.Status -eq 'Running' }
$serviceCount = 0

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
                        
                        if ($dotNetVersion) {
                            $context = "$($service.Name) ($($service.DisplayName))"
                            Add-DotNetComponent -Version $dotNetVersion -FilePath $serviceDll -ComponentType "Service" -Context $context
                            Write-Log "Found $dotNetVersion service DLL: $($service.Name) at $serviceDll"
                            $serviceCount++
                        }
                    }
                }
            } else {
                $dotNetVersion = Get-FileDotNetVersion -FilePath $exePath
                
                if ($dotNetVersion) {
                    $context = "$($service.Name) ($($service.DisplayName))"
                    Add-DotNetComponent -Version $dotNetVersion -FilePath $exePath -ComponentType "Service" -Context $context
                    Write-Log "Found $dotNetVersion service: $($service.Name) at $exePath"
                    $serviceCount++
                }
            }
        }
    } catch {
        # Skip services we can't access
    }
}

Write-Host "Found $serviceCount .NET services" -ForegroundColor Gray

# Scan scheduled tasks
Write-Host "Scanning scheduled tasks for .NET components..." -ForegroundColor Green

try {
    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
    $taskCount = 0
    
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
                        
                        if ($dotNetVersion) {
                            $context = "$($task.TaskPath)$($task.TaskName)"
                            Add-DotNetComponent -Version $dotNetVersion -FilePath $exePath -ComponentType "Scheduled Task" -Context $context
                            Write-Log "Found $dotNetVersion scheduled task: $($task.TaskName) at $exePath"
                            $taskCount++
                        }
                    }
                    
                    break  # Only check first action with executable
                }
            }
        } catch {
            # Skip tasks we can't access
        }
    }
    
    Write-Host "Found $taskCount .NET scheduled tasks" -ForegroundColor Gray
} catch {
    Write-Log "Error scanning scheduled tasks: $($_.Exception.Message)" -Level ERROR
}

# Scan installed applications 
Write-Host "Scanning installed applications for .NET components..." -ForegroundColor Green

$appPaths = @(
    "${env:ProgramFiles}\",
    "${env:ProgramFiles(x86)}\"
)

$appCount = 0
$scannedFiles = @{}

foreach ($basePath in $appPaths) {
    if (Test-Path $basePath) {
        # Get top-level directories first
        $appDirs = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue
        
        foreach ($appDir in $appDirs) {
            # Skip certain system directories to avoid long scans
            if ($appDir.Name -in @("Windows", "WindowsApps", "Microsoft", "Common Files")) {
                continue
            }
            
            # Get executable files
            $exeFiles = Get-ChildItem -Path $appDir.FullName -Include "*.exe", "*.dll" -Recurse -ErrorAction SilentlyContinue -Depth 2
            
            foreach ($file in $exeFiles) {
                # Skip if we've already scanned this file
                if ($scannedFiles.ContainsKey($file.FullName)) {
                    continue
                }
                
                $scannedFiles[$file.FullName] = $true
                
                $dotNetVersion = Get-FileDotNetVersion -FilePath $file.FullName
                
                if ($dotNetVersion) {
                    $context = "Installed App: $($appDir.Name)"
                    Add-DotNetComponent -Version $dotNetVersion -FilePath $file.FullName -ComponentType "Application" -Context $context
                    Write-Log "Found $dotNetVersion application: $($file.Name) at $($file.FullName)"
                    $appCount++
                }
            }
        }
    }
}

Write-Host "Found $appCount .NET applications" -ForegroundColor Gray

# Sort and organize results
Write-Host ""
Write-Host "Organizing results..." -ForegroundColor Green

# Sort versions by framework type and version number
$sortedVersions = $dotNetComponents.Keys | ForEach-Object {
    $framework = $_
    $versionStr = if ($framework -match '([\d\.]+)') { $matches[1] } else { "0.0" }
    
    $priority = switch -Wildcard ($framework) {
        ".NET 6*"              { 1 }
        ".NET 5*"              { 2 }
        ".NET Core 3*"         { 3 }
        ".NET Core 2*"         { 4 }
        ".NET Core*"           { 5 }
        ".NET Framework 4.8*"  { 6 }
        ".NET Framework 4.7*"  { 7 }
        ".NET Framework 4.6*"  { 8 }
        ".NET Framework 4.5*"  { 9 }
        ".NET Framework 4*"    { 10 }
        ".NET Framework 3.5*"  { 11 }
        ".NET Framework*"      { 12 }
        "ASP.NET Core*"        { 13 }
        ".NET Standard*"       { 14 }
        default                { 99 }
    }
    
    [PSCustomObject]@{
        Version = $framework
        SortKey = $priority
        VersionNum = $versionStr
    }
} | Sort-Object -Property SortKey, VersionNum

# Display results
Write-Host ""
Write-Host "============ .NET VERSIONS SUMMARY ============" -ForegroundColor Cyan
Write-Host "Found $($dotNetComponents.Count) .NET versions" -ForegroundColor Cyan
Write-Host ""

foreach ($versionInfo in $sortedVersions) {
    $version = $versionInfo.Version
    $components = $dotNetComponents[$version]
    
    # Skip if no components (shouldn't happen, but just in case)
    if ($components.Count -eq 0) {
        continue
    }
    
    # Get icon based on framework
    $icon = switch -Wildcard ($version) {
        ".NET 6*"             { "🔷" }
        ".NET 5*"             { "🔷" }
        ".NET Core*"          { "🔶" }
        ".NET Framework 4.8*" { "🔴" }
        ".NET Framework*"     { "🔴" }
        "ASP.NET Core*"       { "🔶" }
        ".NET Standard*"      { "⚪" }
        default               { "📦" }
    }
    
    # Determine color
    $color = switch -Wildcard ($version) {
        ".NET 6*"             { "Green" }
        ".NET 5*"             { "Green" }
        ".NET Core*"          { "Yellow" }
        ".NET Framework 4.8*" { "White" }
        ".NET Framework*"     { "Red" }
        "ASP.NET Core*"       { "Yellow" }
        ".NET Standard*"      { "Gray" }
        default               { "Cyan" }
    }
    
    # Display framework version
    Write-Host "$icon $version ($($components.Count) components)" -ForegroundColor $color
    
    # Group components by type for better organization
    $groupedComponents = $components | Group-Object -Property Type
    
    foreach ($group in $groupedComponents) {
        Write-Host "  $($group.Name):" -ForegroundColor White
        
        # Sort by context and path
        $sortedComponents = $group.Group | Sort-Object -Property Context, Path
        
        foreach ($component in $sortedComponents) {
            Write-Host "    - $($component.Path)" -ForegroundColor Gray
            Write-Host "      $($component.Context)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host ""
}

# Export results
if ($OutputFile -ne "") {
    try {
        # Prepare output data
        $exportData = @()
        
        foreach ($version in $dotNetComponents.Keys) {
            foreach ($component in $dotNetComponents[$version]) {
                $exportData += [PSCustomObject]@{
                    DotNetVersion = $version
                    FilePath = $component.Path
                    ComponentType = $component.Type
                    Context = $component.Context
                }
            }
        }
        
        # Determine export format and file
        if ($ExportAsHTML) {
            $htmlFile = if ($OutputFile -like "*.html") { $OutputFile } else { "$OutputFile.html" }
            
            # Create HTML content
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>.NET Version Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        h2 { color: #0066cc; margin-top: 20px; }
        .version-group { margin-bottom: 20px; }
        .component-type { margin-left: 20px; margin-top: 10px; font-weight: bold; }
        .component-item { margin-left: 40px; margin-bottom: 5px; }
        .component-path { color: #333; }
        .component-context { color: #666; font-size: 0.9em; margin-left: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th { background-color: #0066cc; color: white; padding: 8px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>.NET Version Report</h1>
    <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p>Found $($dotNetComponents.Count) .NET versions on system: $env:COMPUTERNAME</p>
    
    <h2>Summary Table</h2>
    <table>
        <tr>
            <th>.NET Version</th>
            <th>Component Count</th>
        </tr>
"@
            
            foreach ($versionInfo in $sortedVersions) {
                $version = $versionInfo.Version
                $components = $dotNetComponents[$version]
                $htmlContent += "        <tr><td>$version</td><td>$($components.Count)</td></tr>`n"
            }
            
            $htmlContent += "    </table>`n`n    <h2>Detailed Component List</h2>`n"
            
            foreach ($versionInfo in $sortedVersions) {
                $version = $versionInfo.Version
                $components = $dotNetComponents[$version]
                
                $htmlContent += "    <div class='version-group'>`n"
                $htmlContent += "        <h3>$version ($($components.Count) components)</h3>`n"
                
                $groupedComponents = $components | Group-Object -Property Type
                
                foreach ($group in $groupedComponents) {
                    $htmlContent += "        <div class='component-type'>$($group.Name):</div>`n"
                    
                    $sortedComponents = $group.Group | Sort-Object -Property Context, Path
                    
                    foreach ($component in $sortedComponents) {
                        $htmlContent += "        <div class='component-item'>`n"
                        $htmlContent += "            <div class='component-path'>$($component.Path)</div>`n"
                        $htmlContent += "            <div class='component-context'>$($component.Context)</div>`n"
                        $htmlContent += "        </div>`n"
                    }
                }
                
                $htmlContent += "    </div>`n"
            }
            
            $htmlContent += @"
</body>
</html>
"@
            
            $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
            Write-Host "Results exported to HTML: $htmlFile" -ForegroundColor Green
            
        } else {
            # CSV export
            $csvFile = if ($OutputFile -like "*.csv") { $OutputFile } else { "$OutputFile.csv" }
            $exportData | Export-Csv -Path $csvFile -NoTypeInformation
            Write-Host "Results exported to CSV: $csvFile" -ForegroundColor Green
        }
    } catch {
        Write-Log "Error exporting results: $($_.Exception.Message)" -Level ERROR
    }
} else {
    # Default output in temp dir
    $defaultOutput = "$env:TEMP\DotNetVersions_$timestamp.csv"
    
    # Prepare output data
    $exportData = @()
    
    foreach ($version in $dotNetComponents.Keys) {
        foreach ($component in $dotNetComponents[$version]) {
            $exportData += [PSCustomObject]@{
                DotNetVersion = $version
                FilePath = $component.Path
                ComponentType = $component.Type
                Context = $component.Context
            }
        }
    }
    
    $exportData | Export-Csv -Path $defaultOutput -NoTypeInformation
    Write-Host "Results exported to CSV: $defaultOutput" -ForegroundColor Green
}

Write-Host ""
Write-Host "Analysis complete! Log file: $LogFile" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan