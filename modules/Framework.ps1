# .NET Framework Detection Module

function Get-DotNetFrameworkVersionFromRegistry {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$DetailedOutput
    )
    
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
            IsPrerelease = $false
            TargetFramework = "v1.0"
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
            IsPrerelease = $false
            TargetFramework = "v1.1"
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
                        IsPrerelease = $false
                        TargetFramework = $versionKey.PSChildName
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
                            IsPrerelease = $false
                            TargetFramework = $versionKey.PSChildName
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
                        528372 { ".NET Framework 4.8.1" }
                        528449 { ".NET Framework 4.8.1" }
                        533320 { ".NET Framework 4.8.1" }
                        533325 { ".NET Framework 4.8.1" }
                        default { "4.x (Release: $release)" }
                    }
                    
                    $targetFramework = $dotNetVersion -replace ".NET Framework ", "v"
                    
                    $results += [PSCustomObject]@{
                        Version = $dotNetVersion
                        ServicePack = $sp
                        InstallPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
                        Profile = $profile
                        Release = $release
                        IsPrerelease = $false
                        TargetFramework = $targetFramework
                    }
                    Write-Log "Found $dotNetVersion Release $release" -Level DETAIL
                }
            }
        }
    }
    
    return $results
}

function Test-IsNetFrameworkRuntime {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Reflection.Module]$Module
    )
    
    $isFramework = $false
    
    # Core Framework modules that identify a .NET Framework runtime
    $frameworkModules = @(
        "mscorlib.dll", 
        "clr.dll", 
        "clrjit.dll",
        "System.dll",
        "System.Core.dll"
    )
    
    if ($frameworkModules -contains $Module.ModuleName) {
        $isFramework = $true
    }
    
    return $isFramework
}

function Get-FrameworkVersionFromModule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Reflection.Module]$Module
    )
    
    $version = "Unknown .NET Framework version"
    
    try {
        if ($Module.ModuleName -eq "mscorlib.dll" -or $Module.ModuleName -eq "clr.dll") {
            $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Module.FileName)
            
            switch ($fileInfo.FileMajorPart) {
                2 { 
                    $version = ".NET Framework 2.0/3.0/3.5"
                    if ($fileInfo.FileMinorPart -eq 0) {
                        if ($fileInfo.FileBuildPart -eq 50727) {
                            if ($fileInfo.FilePrivatePart -le 1434) {
                                $version = ".NET Framework 2.0 RTM"
                            } elseif ($fileInfo.FilePrivatePart -le 3053) {
                                $version = ".NET Framework 2.0 SP1"
                            } elseif ($fileInfo.FilePrivatePart -le 4927) {
                                $version = ".NET Framework 2.0 SP2"
                            }
                        }
                    }
                }
                4 { 
                    $version = ".NET Framework 4.0+"
                    if ($fileInfo.FileMinorPart -eq 0) {
                        if ($fileInfo.FileBuildPart -eq 30319) {
                            if ($fileInfo.FilePrivatePart -le 1008) {
                                $version = ".NET Framework 4.0 RTM"
                            } elseif ($fileInfo.FilePrivatePart -le 17929) {
                                $version = ".NET Framework 4.0 Update" 
                            } elseif ($fileInfo.FilePrivatePart -le 18408) {
                                $version = ".NET Framework 4.5 Developer Preview"
                            } elseif ($fileInfo.FilePrivatePart -le 34209) {
                                $version = ".NET Framework 4.5/4.5.1"
                            } elseif ($fileInfo.FilePrivatePart -le 36213) {
                                $version = ".NET Framework 4.5.2"
                            } elseif ($fileInfo.FilePrivatePart -le 42000) {
                                $version = ".NET Framework 4.6/4.6.1"
                            } elseif ($fileInfo.FilePrivatePart -le 42259) {
                                $version = ".NET Framework 4.6.2"
                            } elseif ($fileInfo.FilePrivatePart -le 42847) {
                                $version = ".NET Framework 4.7"
                            } elseif ($fileInfo.FilePrivatePart -le 43634) {
                                $version = ".NET Framework 4.7.2" 
                            } elseif ($fileInfo.FilePrivatePart -le 53535) {
                                $version = ".NET Framework 4.8/4.8.1"
                            } else {
                                $version = ".NET Framework 4.8+" 
                            }
                        }
                    }
                }
            }
        }
    } catch {
        Write-Log "Error determining .NET Framework version from module: $($_.Exception.Message)" -Level ERROR
    }
    
    return $version
}

Export-ModuleMember -Function Get-DotNetFrameworkVersionFromRegistry, Test-IsNetFrameworkRuntime, Get-FrameworkVersionFromModule