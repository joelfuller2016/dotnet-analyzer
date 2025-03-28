# Advanced PowerShell Script for Deep .NET Analysis
# This script identifies processes, services, scheduled tasks and provides detailed .NET version information

# Script configuration
$LogFile = Join-Path $env:TEMP "DotNetAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$VerboseLogging = $true  # Set to $true for maximum detail

# Initialize log file
"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] .NET Deep Analysis Script Started" | Out-File -FilePath $LogFile

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DETAIL")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    $logMessage | Out-File -FilePath $LogFile -Append
    
    # Write to console with color coding
    switch ($Level) {
        "INFO"    { Write-Host $logMessage -ForegroundColor White }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "DETAIL"  { 
            if ($VerboseLogging) {
                Write-Host $logMessage -ForegroundColor Gray 
            }
        }
    }
}

function Get-DotNetFrameworkVersionFromRegistry {
    Write-Log "Retrieving .NET Framework versions from registry..." -Level INFO
    
    $results = @()
    
    # Check for .NET Framework 1.0 and 1.1
    $netFx10 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\Policy\v1.0" -ErrorAction SilentlyContinue
    if ($netFx10) {
        $results += [PSCustomObject]@{
            Version = "1.0"
            ServicePack = $null
            InstallPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v1.0.3705"
            Profile = "N/A"
            Release = $null
        }
        Write-Log "Found .NET Framework 1.0" -Level DETAIL
    }
    
    $netFx11 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v1.1.4322" -ErrorAction SilentlyContinue
    if ($netFx11) {
        $results += [PSCustomObject]@{
            Version = "1.1"
            ServicePack = $netFx11.SP
            InstallPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v1.1.4322"
            Profile = "N/A"
            Release = $null
        }
        Write-Log "Found .NET Framework 1.1 SP$($netFx11.SP)" -Level DETAIL
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
                    $results += [PSCustomObject]@{
                        Version = $versionKey.PSChildName.Substring(1)
                        ServicePack = $sp
                        InstallPath = $installPaths[$versionKey.PSChildName]
                        Profile = "N/A"
                        Release = $null
                    }
                    Write-Log "Found .NET Framework $($versionKey.PSChildName.Substring(1)) SP$sp" -Level DETAIL
                }
            } else {
                # Check for v2.0 specifically
                foreach ($subkey in Get-ChildItem $versionKey.PSPath) {
                    $installed = (Get-ItemProperty -Path $subkey.PSPath -Name Install -ErrorAction SilentlyContinue).Install
                    
                    if ($installed -eq 1) {
                        $version = (Get-ItemProperty -Path $subkey.PSPath -Name Version -ErrorAction SilentlyContinue).Version
                        $sp = (Get-ItemProperty -Path $subkey.PSPath -Name SP -ErrorAction SilentlyContinue).SP
                        
                        $results += [PSCustomObject]@{
                            Version = if ($version) { $version } else { $versionKey.PSChildName.Substring(1) }
                            ServicePack = $sp
                            InstallPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() -replace "v4.0.30319", "v2.0.50727"
                            Profile = (Get-ItemProperty -Path $subkey.PSPath -Name "MSCorEE" -ErrorAction SilentlyContinue).Profile
                            Release = $null
                        }
                        Write-Log "Found .NET Framework $version SP$sp" -Level DETAIL
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
                        528449 { ".NET Framework 4.8.1" }
                        533320 { ".NET Framework 4.8.1" }
                        default { "4.x (Release: $release)" }
                    }
                    
                    $results += [PSCustomObject]@{
                        Version = $dotNetVersion
                        ServicePack = $sp
                        InstallPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
                        Profile = $profile
                        Release = $release
                    }
                    Write-Log "Found $dotNetVersion Release $release" -Level DETAIL
                }
            }
        }
    }
    
    return $results
}

function Get-DotNetCoreVersions {
    Write-Log "Retrieving .NET Core/.NET 5+ versions..." -Level INFO
    
    $results = @()
    
    # .NET Core Runtime
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
                $type = if ($runtimePath -like "*Microsoft.AspNetCore.App*") {
                    "ASP.NET Core Runtime"
                } elseif ($runtimePath -like "*Microsoft.WindowsDesktop.App*") {
                    "Windows Desktop Runtime"
                } else {
                    ".NET Core/.NET Runtime"
                }
                
                $results += [PSCustomObject]@{
                    Version = $_.Name
                    Type = $type
                    InstallPath = $_.FullName
                    SDKs = "N/A"
                }
                Write-Log "Found $type version $($_.Name) at $($_.FullName)" -Level DETAIL
            }
        }
    }
    
    # .NET Core SDK
    $sdkPaths = @(
        (Join-Path $env:ProgramFiles "dotnet\sdk"),
        (Join-Path ${env:ProgramFiles(x86)} "dotnet\sdk")
    )
    
    foreach ($sdkPath in $sdkPaths) {
        if (Test-Path $sdkPath) {
            Get-ChildItem -Path $sdkPath -Directory | ForEach-Object {
                $results += [PSCustomObject]@{
                    Version = $_.Name
                    Type = ".NET Core/.NET SDK"
                    InstallPath = $_.FullName
                    SDKs = "N/A"
                }
                Write-Log "Found .NET Core/.NET SDK version $($_.Name) at $($_.FullName)" -Level DETAIL
            }
        }
    }
    
    return $results
}

function Analyze-ProcessModules {
    param (
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Process]$Process,
        
        [Parameter(Mandatory=$false)]
        [string]$ProcessName = "Unknown"
    )
    
    $processInfo = [PSCustomObject]@{
        DotNetVersion = "Not .NET"
        BitVersion = "N/A"
        CoreCLR = $false
        FrameworkCLR = $false
        NETNative = $false
        ModuleDetails = @()
        AppDomains = @()
        GCType = "N/A"
        JITType = "N/A"
        MLModules = $false
    }
    
    try {
        Write-Log "Analyzing modules for process $ProcessName (PID: $($Process.Id))..." -Level DETAIL
        $modules = $Process.Modules
        
        # Check for .NET modules
        $netModules = @(
            # .NET Framework
            "mscorlib.dll", 
            "clr.dll", 
            "clrjit.dll",
            "System.dll",
            "System.Core.dll",
            
            # .NET Core/5+
            "coreclr.dll",
            "hostpolicy.dll",
            "System.Private.CoreLib.dll",
            "netstandard.dll",
            
            # .NET Native
            "mrt100_app.dll",
            "mrt100.dll",
            
            # ML.NET
            "Microsoft.ML.dll"
        )
        
        foreach ($module in $modules) {
            try {
                $moduleInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($module.FileName)
                
                if ($netModules -contains $module.ModuleName) {
                    # Record detailed module information for .NET related modules
                    $processInfo.ModuleDetails += [PSCustomObject]@{
                        Name = $module.ModuleName
                        Path = $module.FileName
                        Version = "$($moduleInfo.FileMajorPart).$($moduleInfo.FileMinorPart).$($moduleInfo.FileBuildPart).$($moduleInfo.FilePrivatePart)"
                        Company = $moduleInfo.CompanyName
                        Description = $moduleInfo.FileDescription
                    }
                    
                    Write-Log "Found .NET module $($module.ModuleName) version $($moduleInfo.FileMajorPart).$($moduleInfo.FileMinorPart).$($moduleInfo.FileBuildPart).$($moduleInfo.FilePrivatePart)" -Level DETAIL
                    
                    # Determine .NET Framework version
                    if ($module.ModuleName -eq "mscorlib.dll" -or $module.ModuleName -eq "clr.dll") {
                        $processInfo.FrameworkCLR = $true
                        
                        switch ($moduleInfo.FileMajorPart) {
                            2 { 
                                $processInfo.DotNetVersion = ".NET Framework 2.0/3.0/3.5"
                                if ($moduleInfo.FileMinorPart -eq 0) {
                                    if ($moduleInfo.FileBuildPart -eq 50727) {
                                        if ($moduleInfo.FilePrivatePart -le 1434) {
                                            $processInfo.DotNetVersion = ".NET Framework 2.0 RTM"
                                        } elseif ($moduleInfo.FilePrivatePart -le 3053) {
                                            $processInfo.DotNetVersion = ".NET Framework 2.0 SP1"
                                        } elseif ($moduleInfo.FilePrivatePart -le 4927) {
                                            $processInfo.DotNetVersion = ".NET Framework 2.0 SP2"
                                        }
                                    }
                                }
                            }
                            4 { 
                                $processInfo.DotNetVersion = ".NET Framework 4.0+"
                                if ($moduleInfo.FileMinorPart -eq 0) {
                                    if ($moduleInfo.FileBuildPart -eq 30319) {
                                        if ($moduleInfo.FilePrivatePart -le 1008) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.0 RTM"
                                        } elseif ($moduleInfo.FilePrivatePart -le 17929) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.0 Update" 
                                        } elseif ($moduleInfo.FilePrivatePart -le 18408) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.5 Developer Preview"
                                        } elseif ($moduleInfo.FilePrivatePart -le 34209) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.5/4.5.1"
                                        } elseif ($moduleInfo.FilePrivatePart -le 36213) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.5.2"
                                        } elseif ($moduleInfo.FilePrivatePart -le 42000) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.6/4.6.1"
                                        } elseif ($moduleInfo.FilePrivatePart -le 42259) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.6.2"
                                        } elseif ($moduleInfo.FilePrivatePart -le 42847) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.7"
                                        } elseif ($moduleInfo.FilePrivatePart -le 43634) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.7.2" 
                                        } elseif ($moduleInfo.FilePrivatePart -le 53535) {
                                            $processInfo.DotNetVersion = ".NET Framework 4.8/4.8.1"
                                        } else {
                                            $processInfo.DotNetVersion = ".NET Framework 4.8+" 
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    # Check for .NET Core/5+
                    if ($module.ModuleName -eq "coreclr.dll" -or $module.ModuleName -eq "hostpolicy.dll" -or $module.ModuleName -eq "System.Private.CoreLib.dll") {
                        $processInfo.CoreCLR = $true
                        
                        if ($moduleInfo.FileMajorPart -ge 5) {
                            $processInfo.DotNetVersion = ".NET $($moduleInfo.FileMajorPart).x"
                        } elseif ($moduleInfo.FileMajorPart -ge 3) {
                            $processInfo.DotNetVersion = ".NET Core $($moduleInfo.FileMajorPart).$($moduleInfo.FileMinorPart)"
                        } else {
                            $processInfo.DotNetVersion = ".NET Core $($moduleInfo.FileMajorPart).$($moduleInfo.FileMinorPart)"
                        }
                    }
                    
                    # Check for .NET Native
                    if ($module.ModuleName -eq "mrt100_app.dll" -or $module.ModuleName -eq "mrt100.dll") {
                        $processInfo.NETNative = $true
                        $processInfo.DotNetVersion = ".NET Native"
                    }
                    
                    # Check for ML.NET
                    if ($module.ModuleName -eq "Microsoft.ML.dll") {
                        $processInfo.MLModules = $true
                    }
                }
            } catch {
                Write-Log "Error analyzing module $($module.ModuleName): $($_.Exception.Message)" -Level ERROR
            }
        }
        
        # Determine bitness
        if ($Process.MainModule) {
            if ((Get-Command $Process.MainModule.FileName -ErrorAction SilentlyContinue).BitVersion -eq 32) {
                $processInfo.BitVersion = "32-bit"
            } else {
                $processInfo.BitVersion = "64-bit"
            }
        } else {
            # Fall back to process platform
            if ([Environment]::Is64BitProcess -eq [Environment]::Is64BitOperatingSystem) {
                $processInfo.BitVersion = "64-bit"
            } else {
                $processInfo.BitVersion = "32-bit"
            }
        }
        
        # Try to get AppDomain information using reflection (may fail with access denied)
        if ($processInfo.DotNetVersion -ne "Not .NET") {
            try {
                $AppDomains = [System.AppDomain]::GetCurrentDomain().GetData("ProcessID")
                if ($AppDomains) {
                    $processInfo.AppDomains = $AppDomains
                }
            } catch {
                # This often fails for processes not in the current user context
                $processInfo.AppDomains = @("Unable to access AppDomain information")
            }
        }
        
        # Try to determine GC and JIT mode through heuristics based on modules
        if ($processInfo.DotNetVersion -ne "Not .NET") {
            # Look for server GC modules
            $serverGCModules = @("clrgc.dll", "GCHeapServer.dll")
            $hasServerGCModules = $Process.Modules | Where-Object { $serverGCModules -contains $_.ModuleName }
            if ($hasServerGCModules) {
                $processInfo.GCType = "Server GC"
            } else {
                $processInfo.GCType = "Workstation GC"
            }
            
            # Look for JIT related modules
            $JITModules = $Process.Modules | Where-Object { $_.ModuleName -like "*jit*" }
            if ($JITModules) {
                if ($JITModules.ModuleName -contains "clrjit.dll") {
                    $processInfo.JITType = "JIT"
                } elseif ($JITModules.ModuleName -contains "mscoreejit.dll") {
                    $processInfo.JITType = "EconoJIT"
                } elseif ($JITModules.ModuleName -contains "ngen.dll") {
                    $processInfo.JITType = "NGEN"
                } else {
                    $processInfo.JITType = "Unknown JIT"
                }
            }
        }
    } catch {
        Write-Log "Error analyzing process $ProcessName (PID: $($Process.Id)): $($_.Exception.Message)" -Level ERROR
    }
    
    return $processInfo
}

function Get-ServiceDotNetInfo {
    param (
        [Parameter(Mandatory=$true)]
        $Service
    )
    
    $serviceInfo = [PSCustomObject]@{
        Name = $Service.Name
        DisplayName = $Service.DisplayName
        ProcessId = 0
        ExecutablePath = "Unknown"
        Account = "Unknown"
        StartType = "Unknown"
        Description = "Unknown"
        Dependencies = @()
        DotNetVersion = "Unknown"
        Runtime = "Unknown"
        Architecture = "Unknown"
        InstallLocation = "Unknown"
    }
    
    try {
        Write-Log "Analyzing service $($Service.Name)..." -Level DETAIL
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($Service.Name)'"
        
        if ($wmiService) {
            $serviceInfo.ProcessId = $wmiService.ProcessId
            $serviceInfo.ExecutablePath = $wmiService.PathName
            $serviceInfo.Account = $wmiService.StartName
            $serviceInfo.StartType = $wmiService.StartMode
            $serviceInfo.Description = $wmiService.Description
            $serviceInfo.InstallLocation = Split-Path -Parent $wmiService.PathName.Replace('"', '')
            
            # Get dependencies
            $dependencies = $Service.DependentServices | Select-Object -ExpandProperty Name
            if ($dependencies) {
                $serviceInfo.Dependencies = $dependencies
            }
            
            # Extract executable path from service path
            $exePath = $wmiService.PathName -replace '^"([^"]+)".*$', '$1'
            $exePath = $exePath -replace "^'([^']+)'.*$", '$1'
            
            # If it's a svchost service, we need to look differently
            if ($exePath -like "*\svchost.exe*") {
                Write-Log "Service $($Service.Name) runs in svchost.exe" -Level DETAIL
                $serviceInfo.ExecutablePath = "svchost.exe"
                
                # For svchost services, we need to look at DLLs registered for this service
                $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Service.Name)\Parameters"
                
                if (Test-Path $registryPath) {
                    $serviceDll = (Get-ItemProperty -Path $registryPath -Name "ServiceDll" -ErrorAction SilentlyContinue).ServiceDll
                    
                    if ($serviceDll) {
                        Write-Log "Found service DLL: $serviceDll" -Level DETAIL
                        $serviceInfo.ExecutablePath = $serviceDll
                        
                        # Try to analyze the DLL
                        try {
                            $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($serviceDll)
                            $serviceInfo.DotNetVersion = Get-FileDotNetVersion -FilePath $serviceDll
                            
                            # Get architecture
                            try {
                                $peHeader = New-Object System.Reflection.PortableExecutable.PEReader([System.IO.File]::OpenRead($serviceDll))
                                $serviceInfo.Architecture = if ($peHeader.PEHeaders.PEHeader.Magic -eq 0x20B) { "64-bit" } else { "32-bit" }
                            } catch {
                                $serviceInfo.Architecture = "Unknown"
                            }
                        } catch {
                            Write-Log "Error analyzing service DLL ${serviceDll}: $($_.Exception.Message)" -Level ERROR
                        }
                    }
                }
            } else {
                # For normal services with executables
                $serviceInfo.ExecutablePath = $exePath
                
                # Try to find process associated with service
                $serviceProcess = Get-Process -Id $wmiService.ProcessId -ErrorAction SilentlyContinue
                if ($serviceProcess) {
                    Write-Log "Found process for service $($Service.Name): PID $($serviceProcess.Id)" -Level DETAIL
                    
                    # Analyze process for .NET
                    $processAnalysis = Analyze-ProcessModules -Process $serviceProcess -ProcessName $Service.Name
                    $serviceInfo.DotNetVersion = $processAnalysis.DotNetVersion
                    $serviceInfo.Runtime = if ($processAnalysis.CoreCLR) { ".NET Core/5+" } elseif ($processAnalysis.FrameworkCLR) { ".NET Framework" } else { "N/A" }
                    $serviceInfo.Architecture = $processAnalysis.BitVersion
                } else {
                    # If process not found (e.g., service not running), analyze the executable directly
                    $serviceInfo.DotNetVersion = Get-FileDotNetVersion -FilePath $exePath
                    
                    # Get architecture
                    try {
                        $peHeader = New-Object System.Reflection.PortableExecutable.PEReader([System.IO.File]::OpenRead($exePath))
                        $serviceInfo.Architecture = if ($peHeader.PEHeaders.PEHeader.Magic -eq 0x20B) { "64-bit" } else { "32-bit" }
                    } catch {
                        $serviceInfo.Architecture = "Unknown"
                    }
                }
            }
        }
    } catch {
        Write-Log "Error analyzing service $($Service.Name): $($_.Exception.Message)" -Level ERROR
    }
    
    return $serviceInfo
}

function Get-FileDotNetVersion {
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

function Get-ScheduledTaskDotNetInfo {
    param (
        [Parameter(Mandatory=$true)]
        $Task
    )
    
    try {
        Write-Log "Analyzing scheduled task $($Task.TaskName)..." -Level DETAIL
        
        $taskInfo = [PSCustomObject]@{
            TaskName = $Task.TaskName
            TaskPath = $Task.TaskPath
            State = $Task.State
            LastRunTime = "Unknown"
            NextRunTime = "Unknown"
            LastTaskResult = "Unknown"
            Author = "Unknown"
            Description = "Unknown"
            SecurityDescriptor = "Unknown"
            Principal = "Unknown"
            Executable = "Unknown"
            Arguments = "Unknown"
            WorkingDirectory = "Unknown"
            DotNetVersion = "Unknown"
            Architecture = "Unknown"
            RunAsUser = "Unknown"
            Triggers = @()
        }
        
        # Get detailed task information
        $taskDetails = Get-ScheduledTask $Task.TaskPath.TrimEnd("\") + "\" + $Task.TaskName -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo
        
        if ($taskDetails) {
            $taskInfo.LastRunTime = $taskDetails.LastRunTime
            $taskInfo.NextRunTime = $taskDetails.NextRunTime
            $taskInfo.LastTaskResult = $taskDetails.LastTaskResult
        }
        
        # Get action details
        $actions = $Task.Actions
        
        foreach ($action in $actions) {
            if ($action.Execute) {
                $taskInfo.Executable = $action.Execute
                $taskInfo.Arguments = $action.Arguments
                $taskInfo.WorkingDirectory = $action.WorkingDirectory
                
                # Clean up executable path
                $exePath = $action.Execute -replace '^"([^"]+)".*$', '$1'
                $exePath = $exePath -replace "^'([^']+)'.*$", '$1'
                
                # Handle system environment variables
                $exePath = [System.Environment]::ExpandEnvironmentVariables($exePath)
                
                if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                    $taskInfo.DotNetVersion = Get-FileDotNetVersion -FilePath $exePath
                    
                    # Get architecture
                    try {
                        $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exePath)
                        if ($fileInfo.FileDescription -match "64-bit") {
                            $taskInfo.Architecture = "64-bit"
                        } elseif ($fileInfo.FileDescription -match "32-bit") {
                            $taskInfo.Architecture = "32-bit"
                        } else {
                            try {
                                $peHeader = New-Object System.Reflection.PortableExecutable.PEReader([System.IO.File]::OpenRead($exePath))
                                $taskInfo.Architecture = if ($peHeader.PEHeaders.PEHeader.Magic -eq 0x20B) { "64-bit" } else { "32-bit" }
                            } catch {
                                $taskInfo.Architecture = "Unknown"
                            }
                        }
                    } catch {
                        $taskInfo.Architecture = "Unknown"
                    }
                } else {
                    $taskInfo.DotNetVersion = "Executable not found at path"
                }
                
                break  # Only process the first action with an executable
            }
        }
        
        # Get XML task details for more information
        $taskXml = [xml]$Task.XML
        
        # Get principal (user account)
        $principal = $taskXml.Task.Principals.Principal
        if ($principal) {
            $taskInfo.RunAsUser = $principal.UserId
            if (-not $taskInfo.RunAsUser) {
                if ($principal.GroupId) {
                    $taskInfo.RunAsUser = $principal.GroupId
                } else {
                    if ($principal.RunLevel -eq "HighestAvailable") {
                        $taskInfo.RunAsUser = "Elevated Rights"
                    } else {
                        $taskInfo.RunAsUser = "Standard User"
                    }
                }
            }
        }
        
        # Get author and description
        $registrationInfo = $taskXml.Task.RegistrationInfo
        if ($registrationInfo) {
            $taskInfo.Author = $registrationInfo.Author
            $taskInfo.Description = $registrationInfo.Description
        }
        
        # Get triggers
        $triggers = $taskXml.Task.Triggers
        if ($triggers) {
            $triggerTypes = @("BootTrigger", "CalendarTrigger", "DailyTrigger", "EventTrigger", "IdleTrigger", "LogonTrigger", "MonthlyDOWTrigger", "MonthlyTrigger", "RegistrationTrigger", "SessionStateChangeTrigger", "TimeTrigger", "WeeklyTrigger")
            
            foreach ($triggerType in $triggerTypes) {
                $triggerNodes = $triggers.SelectNodes(".//$triggerType")
                foreach ($node in $triggerNodes) {
                    $triggerDetails = "Type: $triggerType"
                    
                    # Get specific details based on trigger type
                    switch ($triggerType) {
                        "CalendarTrigger" {
                            $schedule = $node.ScheduleByDay -or $node.ScheduleByWeek -or $node.ScheduleByMonth -or $node.ScheduleByMonthDayOfWeek
                            $triggerDetails += " (Schedule: $schedule)"
                        }
                        "DailyTrigger" {
                            $triggerDetails += " (Every $($node.DaysInterval) days at $($node.StartBoundary))"
                        }
                        "TimeTrigger" {
                            $triggerDetails += " (At $($node.StartBoundary))"
                        }
                        "LogonTrigger" {
                            $triggerDetails += if ($node.UserId) { " (User: $($node.UserId))" } else { " (Any User)" }
                        }
                        "EventTrigger" {
                            $subscription = $node.Subscription
                            $triggerDetails += " (Event: $subscription)"
                        }
                    }
                    
                    # Add enabled state
                    if ($node.Enabled -eq "false") {
                        $triggerDetails += " [DISABLED]"
                    }
                    
                    $taskInfo.Triggers += $triggerDetails
                }
            }
        }
        
        return $taskInfo
    } catch {
        Write-Log "Error analyzing task $($Task.TaskName): $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

# Main script execution
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$resultDirectory = Join-Path $env:TEMP "DotNetAnalysis_$timestamp"
New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null

Write-Log "============== .NET Deep Analysis Report ==============" -Level SUCCESS
Write-Log "System: $env:COMPUTERNAME" -Level INFO
Write-Log "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO
Write-Log "Output Directory: $resultDirectory" -Level INFO
Write-Log "====================================================" -Level SUCCESS

#
# Section 1: .NET Framework Versions Installed
#
Write-Log "" -Level INFO
Write-Log "[1] Installed .NET Framework Versions" -Level SUCCESS
Write-Log "------------------------------" -Level INFO

$frameworkVersions = Get-DotNetFrameworkVersionFromRegistry
if ($frameworkVersions) {
    # Create organized dataframe for output
    $frameworkVersions | ForEach-Object {
        $versionStr = $_.Version
        if ($_.ServicePack) { $versionStr += " SP$($_.ServicePack)" }
        if ($_.Release) { $versionStr += " (Release: $($_.Release))" }
        
        Write-Log "Found $versionStr" -Level INFO
        Write-Log "   Install Path: $($_.InstallPath)" -Level INFO
        Write-Log "   Profile: $($_.Profile)" -Level INFO
        Write-Log "   " -Level INFO
    }
} else {
    Write-Log "No .NET Framework installations detected." -Level WARNING
}

# Export framework versions to CSV
$frameworkVersions | Export-Csv -Path (Join-Path $resultDirectory "DotNet_Framework_Versions.csv") -NoTypeInformation
Write-Log "Exported .NET Framework versions to DotNet_Framework_Versions.csv" -Level DETAIL

#
# Section 2: .NET Core/.NET 5+ Versions Installed
#
Write-Log "" -Level INFO
Write-Log "[2] Installed .NET Core/.NET 5+ Versions" -Level SUCCESS
Write-Log "------------------------------" -Level INFO

$coreVersions = Get-DotNetCoreVersions
if ($coreVersions) {
    # Organize by type first
    $coreVersions | Group-Object -Property Type | ForEach-Object {
        Write-Log "$($_.Name) Versions:" -Level INFO
        $_.Group | ForEach-Object {
            Write-Log "   $($_.Version)" -Level INFO
            Write-Log "      Install Path: $($_.InstallPath)" -Level INFO
            Write-Log "      " -Level INFO
        }
    }
} else {
    Write-Log "No .NET Core/.NET 5+ installations detected." -Level WARNING
}

# Export core versions to CSV
$coreVersions | Export-Csv -Path (Join-Path $resultDirectory "DotNet_Core_Versions.csv") -NoTypeInformation
Write-Log "Exported .NET Core versions to DotNet_Core_Versions.csv" -Level DETAIL

#
# Section 3: Running Processes
#
Write-Log "" -Level INFO
Write-Log "[3] Running Processes" -Level SUCCESS
Write-Log "------------------------------" -Level INFO

$runningProcesses = @()
$processCount = 0
$dotNetProcessCount = 0

Write-Log "Scanning running processes..." -Level INFO
$allProcesses = Get-Process

Write-Log "Found $($allProcesses.Count) running processes to analyze." -Level INFO
foreach ($process in $allProcesses) {
    $processCount++
    try {
        $processAnalysis = Analyze-ProcessModules -Process $process -ProcessName $process.ProcessName
        
        if ($processAnalysis.DotNetVersion -ne "Not .NET") {
            $dotNetProcessCount++
            
            $runningProcesses += [PSCustomObject]@{
                ProcessName = $process.ProcessName
                PID = $process.Id
                CPU = if ($process.CPU) { [math]::Round($process.CPU, 2) } else { "N/A" }
                Memory_MB = [math]::Round($process.WorkingSet / 1MB, 2)
                StartTime = if ($process.StartTime) { $process.StartTime } else { "N/A" }
                DotNetVersion = $processAnalysis.DotNetVersion
                Runtime = if ($processAnalysis.CoreCLR) { ".NET Core/5+" } elseif ($processAnalysis.FrameworkCLR) { ".NET Framework" } else { "N/A" }
                Architecture = $processAnalysis.BitVersion
                NETNative = $processAnalysis.NETNative
                GCMode = $processAnalysis.GCType
                JITMode = $processAnalysis.JITType
                ModuleCount = $processAnalysis.ModuleDetails.Count
                ML_NET = $processAnalysis.MLModules
                Path = if ($process.MainModule) { $process.MainModule.FileName } else { "Access Denied" }
            }
            
            # Log detailed modules to file
            $moduleLogFile = Join-Path $resultDirectory "Process_$($process.Id)_$($process.ProcessName)_Modules.csv"
            $processAnalysis.ModuleDetails | Export-Csv -Path $moduleLogFile -NoTypeInformation
            
            # Write short summary to console
            Write-Log "Process: $($process.ProcessName) (PID: $($process.Id))" -Level INFO
            Write-Log "   .NET Version: $($processAnalysis.DotNetVersion)" -Level INFO
            Write-Log "   Runtime: $(if ($processAnalysis.CoreCLR) { '.NET Core/5+' } elseif ($processAnalysis.FrameworkCLR) { '.NET Framework' } else { 'Unknown' })" -Level INFO
            Write-Log "   Architecture: $($processAnalysis.BitVersion)" -Level INFO
            Write-Log "   Path: $(if ($process.MainModule) { $process.MainModule.FileName } else { 'Access Denied' })" -Level INFO
            Write-Log "   Detailed modules exported to: Process_$($process.Id)_$($process.ProcessName)_Modules.csv" -Level DETAIL
            Write-Log "   " -Level INFO
        }
    } catch {
        Write-Log "Error analyzing process $($process.ProcessName) (PID: $($process.Id)): $($_.Exception.Message)" -Level ERROR
    }
    
    # Show progress
    if ($processCount % 20 -eq 0) {
        Write-Log "Processed $processCount/$($allProcesses.Count) processes..." -Level DETAIL
    }
}

# Export process summary to CSV
$runningProcesses | Export-Csv -Path (Join-Path $resultDirectory "DotNet_Processes.csv") -NoTypeInformation
Write-Log "Found $dotNetProcessCount .NET processes out of $processCount total processes." -Level INFO
Write-Log "Exported .NET processes to DotNet_Processes.csv" -Level DETAIL

#
# Section 4: Running Services
#
Write-Log "" -Level INFO
Write-Log "[4] Running Services" -Level SUCCESS
Write-Log "------------------------------" -Level INFO

$runningServices = @()
$serviceCount = 0
$dotNetServiceCount = 0

Write-Log "Scanning running services..." -Level INFO
$allServices = Get-Service | Where-Object { $_.Status -eq 'Running' }

Write-Log "Found $($allServices.Count) running services to analyze." -Level INFO
foreach ($service in $allServices) {
    $serviceCount++
    try {
        $serviceAnalysis = Get-ServiceDotNetInfo -Service $service
        
        if ($serviceAnalysis.DotNetVersion -ne "Unknown" -and $serviceAnalysis.DotNetVersion -ne "Not .NET") {
            $dotNetServiceCount++
            
            $runningServices += $serviceAnalysis
            
            # Write short summary to console
            Write-Log "Service: $($service.Name) ($($service.DisplayName))" -Level INFO
            Write-Log "   .NET Version: $($serviceAnalysis.DotNetVersion)" -Level INFO
            Write-Log "   Runtime: $($serviceAnalysis.Runtime)" -Level INFO
            Write-Log "   Architecture: $($serviceAnalysis.Architecture)" -Level INFO
            Write-Log "   Executable: $($serviceAnalysis.ExecutablePath)" -Level INFO
            Write-Log "   Running as: $($serviceAnalysis.Account)" -Level INFO
            Write-Log "   " -Level INFO
        }
    } catch {
        Write-Log "Error analyzing service $($service.Name): $($_.Exception.Message)" -Level ERROR
    }
    
    # Show progress
    if ($serviceCount % 10 -eq 0) {
        Write-Log "Processed $serviceCount/$($allServices.Count) services..." -Level DETAIL
    }
}

# Export service summary to CSV
$runningServices | Export-Csv -Path (Join-Path $resultDirectory "DotNet_Services.csv") -NoTypeInformation
Write-Log "Found $dotNetServiceCount .NET services out of $serviceCount total services." -Level INFO
Write-Log "Exported .NET services to DotNet_Services.csv" -Level DETAIL

#
# Section 5: Scheduled Tasks
#
Write-Log "" -Level INFO
Write-Log "[5] Scheduled Tasks" -Level SUCCESS
Write-Log "------------------------------" -Level INFO

$scheduledTasks = @()
$taskCount = 0
$dotNetTaskCount = 0

Write-Log "Scanning scheduled tasks..." -Level INFO
$allTasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }

Write-Log "Found $($allTasks.Count) enabled scheduled tasks to analyze." -Level INFO
foreach ($task in $allTasks) {
    $taskCount++
    try {
        $taskAnalysis = Get-ScheduledTaskDotNetInfo -Task $task
        
        if ($taskAnalysis -and $taskAnalysis.DotNetVersion -ne "Unknown" -and $taskAnalysis.DotNetVersion -ne "Not a .NET executable" -and $taskAnalysis.DotNetVersion -ne "Executable not found at path") {
            $dotNetTaskCount++
            
            $scheduledTasks += $taskAnalysis
            
            # Write short summary to console
            Write-Log "Task: $($task.TaskName)" -Level INFO
            Write-Log "   .NET Version: $($taskAnalysis.DotNetVersion)" -Level INFO
            Write-Log "   Executable: $($taskAnalysis.Executable)" -Level INFO
            Write-Log "   Architecture: $($taskAnalysis.Architecture)" -Level INFO
            Write-Log "   Run As: $($taskAnalysis.RunAsUser)" -Level INFO
            if ($taskAnalysis.Triggers.Count -gt 0) {
                Write-Log "   Triggers: $($taskAnalysis.Triggers -join ", ")" -Level INFO
            }
            Write-Log "   " -Level INFO
        }
    } catch {
        Write-Log "Error analyzing task $($Task.TaskName): $($_.Exception.Message)" -Level ERROR
    }
    
    # Show progress
    if ($taskCount % 10 -eq 0) {
        Write-Log "Processed $taskCount/$($allTasks.Count) tasks..." -Level DETAIL
    }
}

# Export task summary to CSV
$scheduledTasks | Export-Csv -Path (Join-Path $resultDirectory "DotNet_Tasks.csv") -NoTypeInformation
Write-Log "Found $dotNetTaskCount .NET scheduled tasks out of $taskCount total tasks." -Level INFO
Write-Log "Exported .NET tasks to DotNet_Tasks.csv" -Level DETAIL

#
# Final Summary
#
Write-Log "" -Level INFO
Write-Log "[6] Summary" -Level SUCCESS
Write-Log "------------------------------" -Level INFO
Write-Log "Analysis complete!" -Level SUCCESS
Write-Log "Found:" -Level INFO
Write-Log "   - $($frameworkVersions.Count) .NET Framework installations" -Level INFO
Write-Log "   - $($coreVersions.Count) .NET Core/.NET 5+ installations" -Level INFO
Write-Log "   - $dotNetProcessCount .NET processes (out of $processCount total)" -Level INFO
Write-Log "   - $dotNetServiceCount .NET services (out of $serviceCount total)" -Level INFO
Write-Log "   - $dotNetTaskCount .NET scheduled tasks (out of $taskCount total)" -Level INFO
Write-Log "" -Level INFO
Write-Log "Results saved to: $resultDirectory" -Level SUCCESS
Write-Log "Log file: $LogFile" -Level INFO