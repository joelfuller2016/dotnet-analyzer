# .NET Core/Modern Detection Module

function Get-DotNetCoreVersions {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludePreview,
        
        [Parameter()]
        [switch]$DetailedOutput
    )
    
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
                $isPreview = $_.Name -match "preview"
                
                if (-not $isPreview -or ($isPreview -and $IncludePreview)) {
                    $type = if ($runtimePath -like "*Microsoft.AspNetCore.App*") {
                        "ASP.NET Core Runtime"
                    } elseif ($runtimePath -like "*Microsoft.WindowsDesktop.App*") {
                        "Windows Desktop Runtime"
                    } else {
                        ".NET Core/.NET Runtime"
                    }
                    
                    $versionInfo = [PSCustomObject]@{
                        Version = $_.Name
                        Type = $type
                        InstallPath = $_.FullName
                        SDKs = "N/A"
                        IsPrerelease = $isPreview
                        RuntimeType = ($runtimePath -split '\\' | Select-Object -Last 1)
                    }
                    
                    # Add more details if requested
                    if ($DetailedOutput) {
                        $infoJsonPath = Join-Path $_.FullName ".version"
                        if (Test-Path $infoJsonPath) {
                            try {
                                $versionContent = Get-Content $infoJsonPath -Raw -ErrorAction SilentlyContinue
                                $versionInfo | Add-Member -NotePropertyName VersionDetails -NotePropertyValue $versionContent
                            } catch {
                                Write-Log "Error reading version details for $($_.Name): $($_.Exception.Message)" -Level ERROR
                            }
                        }
                    }
                    
                    $results += $versionInfo
                    Write-Log "Found $type version $($_.Name) at $($_.FullName)" -Level DETAIL
                }
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
                $isPreview = $_.Name -match "preview"
                
                if (-not $isPreview -or ($isPreview -and $IncludePreview)) {
                    $sdkInfo = [PSCustomObject]@{
                        Version = $_.Name
                        Type = ".NET Core/.NET SDK"
                        InstallPath = $_.FullName
                        SDKs = "N/A"
                        IsPrerelease = $isPreview
                        RuntimeType = "SDK"
                    }
                    
                    # Get which runtimes this SDK supports
                    if ($DetailedOutput) {
                        try {
                            $sdkInfo | Add-Member -NotePropertyName SupportedRuntimes -NotePropertyValue (Get-SdkSupportedRuntimes -SdkPath $_.FullName)
                        } catch {
                            Write-Log "Error determining supported runtimes for SDK $($_.Name): $($_.Exception.Message)" -Level ERROR
                        }
                    }
                    
                    $results += $sdkInfo
                    Write-Log "Found .NET Core/.NET SDK version $($_.Name) at $($_.FullName)" -Level DETAIL
                }
            }
        }
    }
    
    # Look for global.json files in user profile directories (common for development)
    if ($DetailedOutput) {
        $userProfilePaths = @(
            [Environment]::GetFolderPath("UserProfile"),
            [Environment]::GetFolderPath("MyDocuments")
        )
        
        foreach ($userPath in $userProfilePaths) {
            $globalJsonFiles = Get-ChildItem -Path $userPath -Filter "global.json" -Recurse -ErrorAction SilentlyContinue -Depth 3
            
            foreach ($globalJson in $globalJsonFiles) {
                try {
                    $jsonContent = Get-Content -Path $globalJson.FullName -Raw | ConvertFrom-Json
                    
                    if ($jsonContent.sdk.version) {
                        $results += [PSCustomObject]@{
                            Version = $jsonContent.sdk.version
                            Type = "Project SDK Reference"
                            InstallPath = $globalJson.DirectoryName
                            SDKs = $jsonContent.sdk.version
                            IsPrerelease = ($jsonContent.sdk.version -match "preview")
                            RuntimeType = "Project Reference"
                            Source = "global.json"
                        }
                        
                        Write-Log "Found project SDK reference $($jsonContent.sdk.version) in $($globalJson.FullName)" -Level DETAIL
                    }
                } catch {
                    Write-Log "Error processing global.json at $($globalJson.FullName): $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }
    
    return $results
}

function Get-SdkSupportedRuntimes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SdkPath
    )
    
    $runtimes = @()
    
    try {
        # First look for the runtime.json file
        $runtimeJsonPath = Join-Path $SdkPath "runtime.json"
        
        if (Test-Path $runtimeJsonPath) {
            $runtimeJson = Get-Content $runtimeJsonPath -Raw | ConvertFrom-Json
            $runtimes = $runtimeJson
        } else {
            # Alternatively, check the SDK's MSBuild properties
            $propsFilePath = Join-Path $SdkPath "Sdks\Microsoft.NET.Sdk\targets\Microsoft.NET.RuntimeIdentifierInference.targets"
            
            if (Test-Path $propsFilePath) {
                $propsContent = Get-Content $propsFilePath -Raw
                
                # Extract supported target frameworks from the XML
                if ($propsContent -match "NETCoreAppCurrent") {
                    $runtimes += "Current .NET/.NET Core"
                }
                
                $matches = [regex]::Matches($propsContent, 'TargetFramework.*?netcoreapp([0-9\.]+)')
                foreach ($match in $matches) {
                    $runtimes += ".NET Core $($match.Groups[1].Value)"
                }
                
                $matches = [regex]::Matches($propsContent, 'TargetFramework.*?net([0-9\.]+)')
                foreach ($match in $matches) {
                    $runtimes += ".NET $($match.Groups[1].Value)"
                }
            }
        }
    } catch {
        Write-Log "Error determining SDK supported runtimes: $($_.Exception.Message)" -Level ERROR
    }
    
    return $runtimes
}

function Test-IsNetCoreRuntime {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Reflection.Module]$Module
    )
    
    $isCore = $false
    
    # Core modules that identify a .NET Core/.NET 5+ runtime
    $coreModules = @(
        "coreclr.dll",
        "hostpolicy.dll",
        "System.Private.CoreLib.dll",
        "netstandard.dll",
        "hostfxr.dll",
        "CoreCLR.dll"
    )
    
    if ($coreModules -contains $Module.ModuleName) {
        $isCore = $true
    }
    
    return $isCore
}

function Get-CoreVersionFromModule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Reflection.Module]$Module
    )
    
    $version = "Unknown .NET Core version"
    
    try {
        if ($Module.ModuleName -eq "coreclr.dll" -or $Module.ModuleName -eq "hostpolicy.dll" -or $Module.ModuleName -eq "System.Private.CoreLib.dll") {
            $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Module.FileName)
            
            if ($fileInfo.FileMajorPart -ge 7) {
                $version = ".NET $($fileInfo.FileMajorPart).x"
            } elseif ($fileInfo.FileMajorPart -ge 5) {
                $version = ".NET $($fileInfo.FileMajorPart).$($fileInfo.FileMinorPart)"
            } elseif ($fileInfo.FileMajorPart -ge 3) {
                $version = ".NET Core $($fileInfo.FileMajorPart).$($fileInfo.FileMinorPart)"
            } else {
                $version = ".NET Core $($fileInfo.FileMajorPart).$($fileInfo.FileMinorPart)"
            }
        }
    } catch {
        Write-Log "Error determining .NET Core version from module: $($_.Exception.Message)" -Level ERROR
    }
    
    return $version
}

function Test-IsNetNative {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Reflection.Module]$Module
    )
    
    $isNative = $false
    
    # Modules that identify .NET Native
    $nativeModules = @(
        "mrt100_app.dll",
        "mrt100.dll"
    )
    
    if ($nativeModules -contains $Module.ModuleName) {
        $isNative = $true
    }
    
    return $isNative
}

Export-ModuleMember -Function Get-DotNetCoreVersions, Test-IsNetCoreRuntime, Get-CoreVersionFromModule, Test-IsNetNative, Get-SdkSupportedRuntimes