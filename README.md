# .NET Analyzer and Version Finder

This repository contains tools to identify and analyze .NET components on Windows systems.

## DotNetVersionFinder.ps1 (Recommended)

This is an all-in-one PowerShell script that efficiently detects .NET versions and their locations on your system.

### Features

- Detects installed .NET SDKs and runtimes using both dotnet CLI and filesystem checks
- Identifies .NET Framework versions from registry
- Scans running processes for .NET usage
- Analyzes running services for .NET components
- Examines scheduled tasks for .NET executables
- Exports results to CSV files for further analysis
- Provides detailed summary of findings

### Usage

```powershell
# Basic usage - scans everything
.\DotNetVersionFinder.ps1

# Quick scan with less detail
.\DotNetVersionFinder.ps1 -Quick

# Skip specific components
.\DotNetVersionFinder.ps1 -SkipProcesses -SkipTasks

# Exclude system components
.\DotNetVersionFinder.ps1 -NoSystemItems

# Specify custom output path
.\DotNetVersionFinder.ps1 -OutputPath "C:\Reports\DotNetScan"

# Show help
.\DotNetVersionFinder.ps1 -Help
```

### Output

The script creates a timestamped folder (by default in your TEMP directory) containing:

- **DotNet_SDKs.csv** - Installed .NET SDKs
- **DotNet_Core_Runtimes.csv** - Installed .NET Core/.NET 5+ runtimes
- **DotNet_Framework_Versions.csv** - Installed .NET Framework versions
- **DotNet_Processes.csv** - Running processes using .NET
- **DotNet_Services.csv** - Services using .NET
- **DotNet_Tasks.csv** - Scheduled tasks using .NET
- **DotNetScan.log** - Detailed execution log

## Other Tools in this Repository

This repository also includes a modular version of the analyzer with more detailed output capabilities. It consists of:

- **DotNetAnalyzer.ps1** - Main script that coordinates module loading and execution
- **modules/** - Directory containing specialized modules:
  - **Framework.ps1** - .NET Framework detection
  - **Core.ps1** - .NET Core/.NET 5+ detection
  - **Process.ps1** - Process analysis module
  - **Service.ps1** - Service analysis module
  - **Task.ps1** - Scheduled tasks analysis module
  - **Utils.ps1** - Common utilities and functions

For most users, the **DotNetVersionFinder.ps1** script is recommended for its simplicity and ease of use.

## Requirements

- Windows operating system
- PowerShell 5.0 or higher
- Administrative privileges (for complete analysis of services and processes)

## Notes

- For full functionality, run with administrative privileges
- Analysis of a complete system may take several minutes
- The tool does not modify any system components

## Examples

### Finding .NET SDK versions (similar to `dotnet --list-sdks`)

```powershell
.\DotNetVersionFinder.ps1 -SkipProcesses -SkipServices -SkipTasks
```

### Analyzing only user applications (no system components)

```powershell
.\DotNetVersionFinder.ps1 -NoSystemItems -OutputPath "C:\Temp\DotNetUserApps"
```

### Quick scan of everything

```powershell
.\DotNetVersionFinder.ps1 -Quick
```
