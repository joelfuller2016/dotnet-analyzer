# .NET Analyzer PowerShell Scripts

This repository contains two PowerShell scripts designed to identify and analyze .NET-based components on a Windows system:

1. **FindNETVersions.ps1** - A comprehensive, deep analysis script
2. **DotNet_Simple_Analyzer.ps1** - A simplified version for basic analysis

## Features

These scripts will analyze:

- Installed .NET Framework versions (including service packs and release numbers)
- Installed .NET Core and .NET 5+ versions
- Running processes that use .NET
- Running services that use .NET
- Scheduled tasks that use .NET

The deep analysis script (`FindNETVersions.ps1`) provides additional details:

- Exact installation paths for all .NET components
- Detailed runtime information (Framework vs Core/5+)
- Architecture detection (32-bit vs 64-bit)
- GC mode detection (Server vs Workstation)
- JIT compiler identification
- Comprehensive logging to CSV files for further analysis
- Detection of ML.NET components
- More granular version information

## Requirements

- Windows operating system
- PowerShell 5.0 or higher
- Administrative privileges (for complete service and process analysis)

## Usage

### Basic Usage

```powershell
# Clone the repository
git clone https://github.com/joelfuller2016/dotnet-analyzer.git
cd dotnet-analyzer

# Run the basic script
.\DotNet_Simple_Analyzer.ps1

# Or run the comprehensive script for detailed analysis
.\FindNETVersions.ps1
```

### Output

The basic script will display the results in the console, while the comprehensive script will:

1. Create a timestamped directory in your TEMP folder
2. Export all findings to CSV files in that directory
3. Create a detailed log file
4. Display summary information in the console

Example output location:
```
C:\Users\username\AppData\Local\Temp\DotNetAnalysis_20250328_123456\
```

## CSV Output Files (comprehensive script)

- **DotNet_Framework_Versions.csv** - Installed .NET Framework versions
- **DotNet_Core_Versions.csv** - Installed .NET Core and .NET 5+ versions
- **DotNet_Processes.csv** - Running processes using .NET
- **DotNet_Services.csv** - Running services using .NET
- **DotNet_Tasks.csv** - Scheduled tasks using .NET
- **Process_X_NAME_Modules.csv** - Detailed module information for each .NET process

## Notes

- Some processes and services may require administrative privileges to analyze
- The script only analyzes services that are currently running
- Only enabled scheduled tasks are analyzed
- Analysis of large systems may take several minutes to complete

## License

This project is licensed under the MIT License - see the LICENSE file for details.
