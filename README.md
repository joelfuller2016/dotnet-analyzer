# .NET Analyzer PowerShell Scripts

This repository contains PowerShell scripts for detecting and analyzing .NET components on a Windows system.

## Available Scripts

### 1. DotNetFinder.ps1 (Recommended)

A consolidated, all-in-one script that focuses on simplicity and efficiency. This script directly finds all .NET versions installed on your system, including their locations, and works without requiring any additional files.

**Features:**
- Identifies .NET Framework, .NET Core, and .NET 5+ versions
- Uses the `dotnet` CLI for additional SDK detection
- Finds .NET components in running processes, services, and scheduled tasks
- Provides a simple summary grouped by .NET type
- Exports results to a CSV file

### 2. DotNetAnalyzer.ps1 (Advanced, Modular)

A more comprehensive, modular script system that provides detailed analysis of all .NET components with additional metadata. This approach requires all module files to be present.

**Features:**
- More detailed analysis with numerous data points about each component
- Modular design that can be extended with new detection capabilities
- Thorough reporting in multiple formats (CSV, JSON, TEXT)
- Advanced filtering and customization options

### 3. FindNETVersions.ps1 & DotNet_Simple_Analyzer.ps1 (Legacy)

The original scripts that were the foundation for the current versions. Kept for reference.

## Quick Start

### For most users (simple, efficient approach):

```powershell
# Download and run the single-file DotNetFinder script
.\DotNetFinder.ps1

# Run with output to a specific file
.\DotNetFinder.ps1 -OutputFile "C:\Reports\dotnet_results.csv"

# Perform a quicker scan (skips some detailed analysis)
.\DotNetFinder.ps1 -QuickScan

# Skip specific component types
.\DotNetFinder.ps1 -SkipProcesses -SkipServices
```

### For detailed analysis (requires all module files):

```powershell
# Download all files and run the analyzer
.\DotNetAnalyzer.ps1

# Run with specific options
.\DotNetAnalyzer.ps1 -QuickScan -NoSystemComponents -Format JSON
```

## DotNetFinder.ps1 Parameters

- `OutputFile` - Specify a file path for CSV output
- `QuickScan` - Perform a faster analysis with less detail
- `SkipProcesses` - Don't analyze running processes
- `SkipServices` - Don't analyze system services
- `SkipTasks` - Don't analyze scheduled tasks

## Requirements

- Windows operating system
- PowerShell 5.0 or higher
- Administrative privileges (for complete service and process analysis)

## Output Example

The DotNetFinder script provides a summary like this:

```
=========== .NET COMPONENT SUMMARY ===========
Found 37 .NET components on this system

.NET Core/.NET (12 components)
  - 6.0.22
  - 7.0.11
  - 8.0.0

.NET Framework (8 components)
  - 4.8
  - 4.7.2
  - 3.5 SP1

.NET SDK (5 components)
  - 6.0.417
  - 7.0.401
  - 8.0.101
...
```

A detailed CSV is also generated with all components and their locations.

## Notes

- Some processes and services may require administrative privileges to analyze
- The script only analyzes services that are currently running by default
- Only enabled scheduled tasks are analyzed by default
- Analysis of large systems may take several minutes to complete

## License

This project is licensed under the MIT License.
