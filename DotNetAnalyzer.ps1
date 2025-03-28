# .NET Analyzer - Comprehensive script for detecting .NET components on a system
# Version: 2.0
# This script is modular and can be extended with new detection capabilities

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$QuickScan,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoSystemComponents,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON", "TEXT")]
    [string]$Format = "CSV",
    
    [Parameter(Mandatory=$false)]
    [switch]$NoProcesses,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoServices,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoTasks,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoColor,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeStoppedServices,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabledTasks,
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Check for help parameter
if ($Help) {
    Write-Host @"
    
.NET Analyzer - Comprehensive .NET component detection
=====================================================

DESCRIPTION:
    This script scans your system for .NET Framework and .NET Core/5+ components,
    identifying installed versions and applications that use .NET.

PARAMETERS:
    -OutputPath             Path to store results (default: TEMP directory)
    -QuickScan              Perform faster analysis with less detail
    -NoSystemComponents     Exclude system processes, services and tasks
    -Format                 Output format: CSV, JSON, or TEXT (default: CSV)
    -NoProcesses            Skip analysis of running processes
    -NoServices             Skip analysis of system services
    -NoTasks                Skip analysis of scheduled tasks
    -NoColor                Disable colored console output
    -IncludeStoppedServices Analyze services that aren't currently running
    -IncludeDisabledTasks   Analyze tasks that are currently disabled
    -Help                   Display this help information

EXAMPLES:
    .\DotNetAnalyzer.ps1
        Performs full analysis with default settings
        
    .\DotNetAnalyzer.ps1 -QuickScan -NoSystemComponents
        Performs quick analysis of user applications only
        
    .\DotNetAnalyzer.ps1 -OutputPath "C:\Reports" -Format JSON
        Saves detailed report in JSON format to specified folder

NOTES:
    - Administrative privileges recommended for complete analysis
    - Analysis of a full system may take several minutes
    - Results are exported to CSV/JSON/TEXT files by default
    
"@
    exit
}

# Script Start
$moduleRootPath = Join-Path $PSScriptRoot "modules"

# First check if there's a modules folder next to the script
if (-not (Test-Path $moduleRootPath)) {
    # Try to create it
    try {
        New-Item -ItemType Directory -Path $moduleRootPath -Force | Out-Null
        Write-Host "Created modules directory at $moduleRootPath"
        Write-Host "Please place required module files in this directory and run again."
        exit
    } catch {
        Write-Host "Error: Modules folder not found and couldn't be created at $moduleRootPath"
        Write-Host "This script requires the following modules:"
        Write-Host "  - Utils.ps1"
        Write-Host "  - Framework.ps1"
        Write-Host "  - Core.ps1"
        Write-Host "  - Process.ps1"
        Write-Host "  - Service.ps1"
        Write-Host "  - Task.ps1"
        exit
    }
}

# Try to load the utility module first (required for logging)
$utilsModule = Join-Path $moduleRootPath "Utils.ps1"
if (-not (Test-Path $utilsModule)) {
    Write-Host "Error: Utility module not found at $utilsModule"
    exit
}

# Load modules as script blocks to avoid PS module dependency
# This keeps the script working as a simple file with no installation
try {
    # Utility module (required)
    . ([ScriptBlock]::Create([System.IO.File]::ReadAllText($utilsModule)))
    
    # Framework detection module
    $frameworkModule = Join-Path $moduleRootPath "Framework.ps1"
    if (Test-Path $frameworkModule) {
        . ([ScriptBlock]::Create([System.IO.File]::ReadAllText($frameworkModule)))
    } else {
        Write-Host "Warning: Framework module not found at $frameworkModule. Framework detection will be limited."
    }
    
    # Core detection module
    $coreModule = Join-Path $moduleRootPath "Core.ps1"
    if (Test-Path $coreModule) {
        . ([ScriptBlock]::Create([System.IO.File]::ReadAllText($coreModule)))
    } else {
        Write-Host "Warning: Core module not found at $coreModule. .NET Core detection will be limited."
    }
    
    # Process module
    $processModule = Join-Path $moduleRootPath "Process.ps1"
    if (Test-Path $processModule) {
        . ([ScriptBlock]::Create([System.IO.File]::ReadAllText($processModule)))
    } else {
        Write-Host "Warning: Process module not found at $processModule. Process analysis will be disabled."
        $NoProcesses = $true
    }
    
    # Service module
    $serviceModule = Join-Path $moduleRootPath "Service.ps1"
    if (Test-Path $serviceModule) {
        . ([ScriptBlock]::Create([System.IO.File]::ReadAllText($serviceModule)))
    } else {
        Write-Host "Warning: Service module not found at $serviceModule. Service analysis will be disabled."
        $NoServices = $true
    }
    
    # Task module
    $taskModule = Join-Path $moduleRootPath "Task.ps1"
    if (Test-Path $taskModule) {
        . ([ScriptBlock]::Create([System.IO.File]::ReadAllText($taskModule)))
    } else {
        Write-Host "Warning: Task module not found at $taskModule. Task analysis will be disabled."
        $NoTasks = $true
    }
} catch {
    Write-Host "Error loading modules: $($_.Exception.Message)"
    exit
}

# Initialize environment and configure logging
$env = Initialize-Environment -LogPath (Join-Path $OutputPath "DotNetAnalysis.log") -ResultPath $OutputPath -Verbose (-not $QuickScan) -ColoredOutput (-not $NoColor) -Format $Format -QuickScan $QuickScan

# Print banner
Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                    .NET ANALYZER v2.0                    " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "  System: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Date  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "  Admin : $(if($env.IsAdmin) { 'Yes' } else { 'No (limited functionality)' })" -ForegroundColor White
Write-Host "  Output: $($env.ResultDirectory)" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host ""

# Store results for summary report
$results = @{}

# Detect installed .NET Framework versions
if (Get-Command Get-DotNetFrameworkVersionFromRegistry -ErrorAction SilentlyContinue) {
    Write-Host "[1] Analyzing installed .NET Framework versions..." -ForegroundColor Green
    try {
        $frameworkVersions = Get-DotNetFrameworkVersionFromRegistry
        $results.FrameworkVersions = $frameworkVersions
        Export-Results -Data $frameworkVersions -Filename "DotNet_Framework_Versions" -Description "Installed .NET Framework Versions"
    } catch {
        Write-Log "Error analyzing .NET Framework installations: $($_.Exception.Message)" -Level ERROR
    }
} else {
    Write-Log "Skipping .NET Framework analysis as module function not available" -Level WARNING
}

# Detect installed .NET Core versions
if (Get-Command Get-DotNetCoreVersions -ErrorAction SilentlyContinue) {
    Write-Host "[2] Analyzing installed .NET Core/.NET 5+ versions..." -ForegroundColor Green
    try {
        $coreVersions = Get-DotNetCoreVersions -IncludePreview -DetailedOutput:(-not $QuickScan)
        $results.CoreVersions = $coreVersions
        Export-Results -Data $coreVersions -Filename "DotNet_Core_Versions" -Description "Installed .NET Core/.NET 5+ Versions"
    } catch {
        Write-Log "Error analyzing .NET Core installations: $($_.Exception.Message)" -Level ERROR
    }
} else {
    Write-Log "Skipping .NET Core analysis as module function not available" -Level WARNING
}

# Analyze running processes
if (-not $NoProcesses -and (Get-Command Get-DotNetProcesses -ErrorAction SilentlyContinue)) {
    Write-Host "[3] Analyzing running processes..." -ForegroundColor Green
    try {
        $processAnalysis = Get-DotNetProcesses -IncludeSystemProcesses:(-not $NoSystemComponents) -QuickAnalysis:$QuickScan
        $results.Processes = $processAnalysis.Processes
        $results.ProcessCount = $processAnalysis.TotalCount
        Export-Results -Data $processAnalysis.Processes -Filename "DotNet_Processes" -Description "Running Processes Using .NET"
    } catch {
        Write-Log "Error analyzing processes: $($_.Exception.Message)" -Level ERROR
    }
}

# Analyze running services
if (-not $NoServices -and (Get-Command Get-DotNetServices -ErrorAction SilentlyContinue)) {
    Write-Host "[4] Analyzing services..." -ForegroundColor Green
    try {
        $serviceAnalysis = Get-DotNetServices -IncludeSystemServices:(-not $NoSystemComponents) -IncludeStoppedServices:$IncludeStoppedServices -QuickAnalysis:$QuickScan
        $results.Services = $serviceAnalysis.Services
        $results.ServiceCount = $serviceAnalysis.TotalCount
        Export-Results -Data $serviceAnalysis.Services -Filename "DotNet_Services" -Description "Services Using .NET"
    } catch {
        Write-Log "Error analyzing services: $($_.Exception.Message)" -Level ERROR
    }
}

# Analyze scheduled tasks
if (-not $NoTasks -and (Get-Command Get-DotNetScheduledTasks -ErrorAction SilentlyContinue)) {
    Write-Host "[5] Analyzing scheduled tasks..." -ForegroundColor Green
    try {
        $taskAnalysis = Get-DotNetScheduledTasks -IncludeSystemTasks:(-not $NoSystemComponents) -IncludeDisabled:$IncludeDisabledTasks -QuickAnalysis:$QuickScan
        $results.Tasks = $taskAnalysis.Tasks
        $results.TaskCount = $taskAnalysis.TotalCount
        Export-Results -Data $taskAnalysis.Tasks -Filename "DotNet_Tasks" -Description "Scheduled Tasks Using .NET"
    } catch {
        Write-Log "Error analyzing scheduled tasks: $($_.Exception.Message)" -Level ERROR
    }
}

# Add scan configuration to results
$results.ScanConfig = Get-ScanConfiguration
$results.ResultDirectory = $env.ResultDirectory

# Export scan configuration
Export-Results -Data @($results.ScanConfig) -Filename "ScanConfiguration" -Description "Scan Configuration and Settings"

# Show summary
Write-Host ""
Show-AnalysisResults -Results $results
Write-Host ""

# Create HTML report if needed
# Disabled for now - could be enabled in the future
<#
if ($Format -eq "HTML") {
    Write-Host "[6] Generating HTML report..." -ForegroundColor Green
    $htmlReport = Join-Path $env.ResultDirectory "DotNetAnalysis_Report.html"
    # TODO: Implement HTML report generation
}
#>

Write-Host "Analysis complete! Results saved to: $($env.ResultDirectory)" -ForegroundColor Green
Write-Host ""