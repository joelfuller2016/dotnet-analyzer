# Service Analysis Module

function Get-ServiceDotNetInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $Service,
        
        [Parameter()]
        [switch]$QuickAnalysis
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
        ServiceType = "Win32"
        ModuleDetails = @()
    }
    
    try {
        Write-Log "Analyzing service $($Service.Name)..." -Level DETAIL
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($Service.Name)'" -ErrorAction SilentlyContinue
        
        if (-not $wmiService) {
            Write-Log "Service WMI information not found for $($Service.Name)" -Level WARNING
            return $serviceInfo
        }
        
        $serviceInfo.ProcessId = $wmiService.ProcessId
        $serviceInfo.ExecutablePath = $wmiService.PathName
        $serviceInfo.Account = $wmiService.StartName
        $serviceInfo.StartType = $wmiService.StartMode
        $serviceInfo.Description = $wmiService.Description
        
        # Try to extract install location
        try {
            $serviceInfo.InstallLocation = Split-Path -Parent $wmiService.PathName.Replace('"', '')
        } catch {
            $serviceInfo.InstallLocation = "Unknown"
        }
        
        # Get dependencies
        $dependencies = $Service.DependentServices | Select-Object -ExpandProperty Name
        if ($dependencies) {
            $serviceInfo.Dependencies = $dependencies
        }
        
        # Extract executable path from service path
        $exePath = $wmiService.PathName -replace '^"([^"]+)".*$', '$1'
        $exePath = $exePath -replace "^'([^']+)'.*$", '$1'
        
        # Determine service type
        if ($exePath -like "*\svchost.exe*") {
            $serviceInfo.ServiceType = "Shared Host"
            
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
                            $peReader = $null
                            $fileStream = [System.IO.File]::OpenRead($serviceDll)
                            
                            try {
                                $peReader = New-Object System.Reflection.PortableExecutable.PEReader([System.IO.Stream]$fileStream)
                                $serviceInfo.Architecture = if ($peReader.PEHeaders.PEHeader.Magic -eq 0x20B) { "64-bit" } else { "32-bit" }
                            } finally {
                                if ($peReader) { $peReader.Dispose() }
                                $fileStream.Dispose()
                            }
                        } catch {
                            # If error with PE headers, try based on file path
                            if ($serviceDll -like "*\SysWOW64\*") {
                                $serviceInfo.Architecture = "32-bit on 64-bit OS"
                            } elseif ($serviceDll -like "*\System32\*") {
                                $serviceInfo.Architecture = "64-bit"
                            } else {
                                $serviceInfo.Architecture = "Unknown"
                            }
                        }
                        
                        # Try to determine .NET Framework vs Core
                        if ($serviceInfo.DotNetVersion -like "*.NET Framework*") {
                            $serviceInfo.Runtime = ".NET Framework"
                        } elseif ($serviceInfo.DotNetVersion -like "*.NET Core*" -or $serviceInfo.DotNetVersion -like "*.NET 5*") {
                            $serviceInfo.Runtime = ".NET Core/5+"
                        }
                    } catch {
                        Write-Log "Error analyzing service DLL ${serviceDll}: $($_.Exception.Message)" -Level ERROR
                    }
                }
            }
        } else {
            # For normal services with executables
            $serviceInfo.ServiceType = "Executable"
            $serviceInfo.ExecutablePath = $exePath
            
            # Try to find process associated with service
            $serviceProcess = Get-Process -Id $wmiService.ProcessId -ErrorAction SilentlyContinue
            if ($serviceProcess) {
                Write-Log "Found process for service $($Service.Name): PID $($serviceProcess.Id)" -Level DETAIL
                
                # Analyze process for .NET
                $processAnalysis = Analyze-ProcessModules -Process $serviceProcess -ProcessName $Service.Name -QuickAnalysis:$QuickAnalysis
                $serviceInfo.DotNetVersion = $processAnalysis.DotNetVersion
                $serviceInfo.Runtime = if ($processAnalysis.CoreCLR) { ".NET Core/5+" } elseif ($processAnalysis.FrameworkCLR) { ".NET Framework" } else { "N/A" }
                $serviceInfo.Architecture = $processAnalysis.BitVersion
                
                # Get module details if not in quick mode
                if (-not $QuickAnalysis) {
                    $serviceInfo.ModuleDetails = $processAnalysis.ModuleDetails
                }
            } else {
                # If process not found (e.g., service not running), analyze the executable directly
                $serviceInfo.DotNetVersion = Get-FileDotNetVersion -FilePath $exePath
                
                # Determine .NET Runtime based on the version string
                if ($serviceInfo.DotNetVersion -like "*.NET Framework*") {
                    $serviceInfo.Runtime = ".NET Framework"
                } elseif ($serviceInfo.DotNetVersion -like "*.NET Core*" -or $serviceInfo.DotNetVersion -like "*.NET 5*") {
                    $serviceInfo.Runtime = ".NET Core/5+"
                }
                
                # Get architecture
                try {
                    $peReader = $null
                    $fileStream = [System.IO.File]::OpenRead($exePath)
                    
                    try {
                        $peReader = New-Object System.Reflection.PortableExecutable.PEReader([System.IO.Stream]$fileStream)
                        $serviceInfo.Architecture = if ($peReader.PEHeaders.PEHeader.Magic -eq 0x20B) { "64-bit" } else { "32-bit" }
                    } finally {
                        if ($peReader) { $peReader.Dispose() }
                        $fileStream.Dispose()
                    }
                } catch {
                    # Try alternative method for executable bitness
                    $serviceInfo.Architecture = "Unknown"
                }
            }
        }
        
        # Classify service runtime more precisely
        if ($serviceInfo.DotNetVersion -eq "Unknown" -or $serviceInfo.DotNetVersion -eq "Not .NET") {
            $serviceInfo.Runtime = "Non-.NET"
        }
    } catch {
        Write-Log "Error analyzing service $($Service.Name): $($_.Exception.Message)" -Level ERROR
    }
    
    return $serviceInfo
}

function Get-DotNetServices {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeSystemServices = $true,
        
        [Parameter()]
        [switch]$IncludeStoppedServices = $false,
        
        [Parameter()]
        [switch]$QuickAnalysis
    )
    
    $runningServices = @()
    $serviceCount = 0
    $dotNetServiceCount = 0
    
    Write-Log "Scanning services..." -Level INFO
    
    try {
        # Get all services or just running services based on parameter
        if ($IncludeStoppedServices) {
            $allServices = Get-Service
        } else {
            $allServices = Get-Service | Where-Object { $_.Status -eq 'Running' }
        }
        
        # Exclude system services if requested
        if (-not $IncludeSystemServices) {
            $systemServiceNames = @(
                "wuauserv", "WSearch", "WinDefend", "Dhcp", "Dnscache", 
                "LanmanServer", "LanmanWorkstation", "MSDTC", "PlugPlay", 
                "SamSs", "Schedule", "SENS", "Spooler", "W32Time", "winmgmt"
            )
            
            $allServices = $allServices | Where-Object { $systemServiceNames -notcontains $_.Name }
        }
        
        Write-Log "Found $($allServices.Count) services to analyze." -Level INFO
        
        foreach ($service in $allServices) {
            $serviceCount++
            try {
                $serviceAnalysis = Get-ServiceDotNetInfo -Service $service -QuickAnalysis:$QuickAnalysis
                
                if ($serviceAnalysis.DotNetVersion -ne "Unknown" -and $serviceAnalysis.DotNetVersion -ne "Not .NET") {
                    $dotNetServiceCount++
                    $runningServices += $serviceAnalysis
                    
                    # Store detailed module information if not in quick mode
                    if (-not $QuickAnalysis -and $serviceAnalysis.ModuleDetails.Count -gt 0) {
                        $moduleLogFile = Join-Path $script:ResultDirectory "Service_$($service.Name)_Modules.csv"
                        $serviceAnalysis.ModuleDetails | Export-Csv -Path $moduleLogFile -NoTypeInformation
                        Write-Log "Saved module details for service $($service.Name) to $moduleLogFile" -Level DETAIL
                    }
                    
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
            
            # Show progress for long-running analysis
            if ($serviceCount % 10 -eq 0) {
                Write-Log "Processed $serviceCount/$($allServices.Count) services..." -Level DETAIL
            }
        }
    } catch {
        Write-Log "Error getting services: $($_.Exception.Message)" -Level ERROR
    }
    
    Write-Log "Found $dotNetServiceCount .NET services out of $serviceCount total services." -Level INFO
    
    return [PSCustomObject]@{
        Services = $runningServices
        TotalCount = $serviceCount
        DotNetCount = $dotNetServiceCount
    }
}

function Get-WindowsServiceControllers {
    [CmdletBinding()]
    param()
    
    # Used to look for additional registration patterns for .NET services
    $serviceControllers = @()
    
    # ServiceController registry path
    $controllerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"
    
    if (Test-Path $controllerPath) {
        $services = Get-ChildItem $controllerPath
        
        foreach ($service in $services) {
            try {
                $sourceName = Split-Path -Leaf $service.PSPath
                $eventMessageFile = (Get-ItemProperty -Path $service.PSPath).EventMessageFile
                
                if ($eventMessageFile -like "*.NET*" -or $eventMessageFile -like "*Framework*" -or 
                    $eventMessageFile -like "*Microsoft*" -or $eventMessageFile -like "*.exe") {
                    
                    $serviceControllers += [PSCustomObject]@{
                        Name = $sourceName
                        MessageFile = $eventMessageFile
                        Is64bit = ($eventMessageFile -notlike "*\SysWOW64\*")
                        IsDotNet = ($eventMessageFile -like "*.NET*" -or $eventMessageFile -like "*Framework*")
                    }
                }
            } catch {
                # Skip services that cause errors
            }
        }
    }
    
    return $serviceControllers
}

Export-ModuleMember -Function Get-ServiceDotNetInfo, Get-DotNetServices, Get-WindowsServiceControllers