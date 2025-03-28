# Process Analysis Module

function Analyze-ProcessModules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Process]$Process,
        
        [Parameter(Mandatory=$false)]
        [string]$ProcessName = "Unknown",
        
        [Parameter()]
        [switch]$QuickAnalysis
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
        HasDebugging = $false
    }
    
    try {
        Write-Log "Analyzing modules for process $ProcessName (PID: $($Process.Id))..." -Level DETAIL
        
        try {
            $modules = $Process.Modules
        } catch {
            Write-Log "Access denied for process modules $ProcessName (PID: $($Process.Id)). This may require admin privileges." -Level ERROR
            return $processInfo
        }
        
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
                if ($netModules -contains $module.ModuleName) {
                    $moduleInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($module.FileName)
                    
                    # Record detailed module information for .NET related modules
                    if (-not $QuickAnalysis) {
                        $processInfo.ModuleDetails += [PSCustomObject]@{
                            Name = $module.ModuleName
                            Path = $module.FileName
                            Version = "$($moduleInfo.FileMajorPart).$($moduleInfo.FileMinorPart).$($moduleInfo.FileBuildPart).$($moduleInfo.FilePrivatePart)"
                            Company = $moduleInfo.CompanyName
                            Description = $moduleInfo.FileDescription
                        }
                    }
                    
                    Write-Log "Found .NET module $($module.ModuleName) version $($moduleInfo.FileMajorPart).$($moduleInfo.FileMinorPart).$($moduleInfo.FileBuildPart).$($moduleInfo.FilePrivatePart)" -Level DETAIL
                    
                    # Check for .NET Framework
                    if (Test-IsNetFrameworkRuntime -Module $module) {
                        $processInfo.FrameworkCLR = $true
                        $processInfo.DotNetVersion = Get-FrameworkVersionFromModule -Module $module
                    }
                    
                    # Check for .NET Core/5+
                    if (Test-IsNetCoreRuntime -Module $module) {
                        $processInfo.CoreCLR = $true
                        $processInfo.DotNetVersion = Get-CoreVersionFromModule -Module $module
                    }
                    
                    # Check for .NET Native
                    if (Test-IsNetNative -Module $module) {
                        $processInfo.NETNative = $true
                        $processInfo.DotNetVersion = ".NET Native"
                    }
                    
                    # Check for ML.NET
                    if ($module.ModuleName -eq "Microsoft.ML.dll") {
                        $processInfo.MLModules = $true
                    }
                    
                    # Check for debugging tools/symbols
                    if ($module.ModuleName -like "*debug*" -or $module.ModuleName -like "*diagnost*") {
                        $processInfo.HasDebugging = $true
                    }
                }
            } catch {
                Write-Log "Error analyzing module $($module.ModuleName): $($_.Exception.Message)" -Level ERROR
            }
        }
        
        # Determine bitness
        if ($Process.MainModule) {
            try {
                if ((Get-Command $Process.MainModule.FileName -ErrorAction SilentlyContinue).BitVersion -eq 32) {
                    $processInfo.BitVersion = "32-bit"
                } else {
                    $processInfo.BitVersion = "64-bit"
                }
            } catch {
                # Try alternative method for bitness detection
                $is64Bit = [IntPtr]::Size -eq 8
                $processInfo.BitVersion = if ($is64Bit) { "64-bit" } else { "32-bit" }
            }
        } else {
            # Fall back to process platform
            if ([Environment]::Is64BitProcess -eq [Environment]::Is64BitOperatingSystem) {
                $processInfo.BitVersion = "64-bit"
            } else {
                $processInfo.BitVersion = "32-bit"
            }
        }
        
        # If we've detected .NET, add more details
        if ($processInfo.DotNetVersion -ne "Not .NET") {
            # Try to get AppDomain information using reflection (may fail with access denied)
            if (-not $QuickAnalysis) {
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

function Get-DotNetProcesses {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeSystemProcesses = $true,
        
        [Parameter()]
        [switch]$QuickAnalysis
    )
    
    $runningProcesses = @()
    $processCount = 0
    $dotNetProcessCount = 0
    
    Write-Log "Scanning running processes..." -Level INFO
    
    try {
        $allProcesses = Get-Process
        
        # If not including system processes, filter them out
        if (-not $IncludeSystemProcesses) {
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
        
        Write-Log "Found $($allProcesses.Count) running processes to analyze." -Level INFO
        
        foreach ($process in $allProcesses) {
            $processCount++
            try {
                $processAnalysis = Analyze-ProcessModules -Process $process -ProcessName $process.ProcessName -QuickAnalysis:$QuickAnalysis
                
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
                        HasDebugSymbols = $processAnalysis.HasDebugging
                        Path = if ($process.MainModule) { $process.MainModule.FileName } else { "Access Denied" }
                        CommandLine = (Get-ProcessCommandLine -ProcessId $process.Id)
                    }
                    
                    # Log detailed modules to file if not in quick mode
                    if (-not $QuickAnalysis -and $processAnalysis.ModuleDetails.Count -gt 0) {
                        $moduleLogFile = Join-Path $script:ResultDirectory "Process_$($process.Id)_$($process.ProcessName)_Modules.csv"
                        $processAnalysis.ModuleDetails | Export-Csv -Path $moduleLogFile -NoTypeInformation
                        
                        Write-Log "Exported $($processAnalysis.ModuleDetails.Count) modules for $($process.ProcessName) to $moduleLogFile" -Level DETAIL
                    }
                    
                    # Write short summary to console
                    Write-Log "Process: $($process.ProcessName) (PID: $($process.Id))" -Level INFO
                    Write-Log "   .NET Version: $($processAnalysis.DotNetVersion)" -Level INFO
                    Write-Log "   Runtime: $(if ($processAnalysis.CoreCLR) { '.NET Core/5+' } elseif ($processAnalysis.FrameworkCLR) { '.NET Framework' } else { 'Unknown' })" -Level INFO
                    Write-Log "   Architecture: $($processAnalysis.BitVersion)" -Level INFO
                    Write-Log "   Path: $(if ($process.MainModule) { $process.MainModule.FileName } else { 'Access Denied' })" -Level INFO
                }
            } catch {
                Write-Log "Error analyzing process $($process.ProcessName) (PID: $($process.Id)): $($_.Exception.Message)" -Level ERROR
            }
            
            # Show progress for long-running analysis
            if ($processCount % 20 -eq 0) {
                Write-Log "Processed $processCount/$($allProcesses.Count) processes..." -Level DETAIL
            }
        }
    } catch {
        Write-Log "Error getting processes: $($_.Exception.Message)" -Level ERROR
    }
    
    Write-Log "Found $dotNetProcessCount .NET processes out of $processCount total processes." -Level INFO
    
    return [PSCustomObject]@{
        Processes = $runningProcesses
        TotalCount = $processCount
        DotNetCount = $dotNetProcessCount
    }
}

function Get-ProcessCommandLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$ProcessId
    )
    
    try {
        $wmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($wmiProcess) {
            return $wmiProcess.CommandLine
        }
    } catch {
        # Silently fail - command line is optional
    }
    
    return "Unknown"
}

Export-ModuleMember -Function Analyze-ProcessModules, Get-DotNetProcesses, Get-ProcessCommandLine