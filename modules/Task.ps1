# Task Scheduler Analysis Module

function Get-ScheduledTaskDotNetInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $Task,
        
        [Parameter()]
        [switch]$QuickAnalysis
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
            IsSystemTask = $false
        }
        
        # Get detailed task information if available
        try {
            $taskDetails = Get-ScheduledTask $Task.TaskPath.TrimEnd("\") + "\" + $Task.TaskName -ErrorAction SilentlyContinue | 
                           Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            
            if ($taskDetails) {
                $taskInfo.LastRunTime = $taskDetails.LastRunTime
                $taskInfo.NextRunTime = $taskDetails.NextRunTime
                $taskInfo.LastTaskResult = $taskDetails.LastTaskResult
            }
        } catch {
            Write-Log "Could not get task details for $($Task.TaskName): $($_.Exception.Message)" -Level ERROR
        }
        
        # Determine if this is a system task
        if ($Task.TaskPath -like "\Microsoft\Windows\*") {
            $taskInfo.IsSystemTask = $true
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
                try {
                    $exePath = [System.Environment]::ExpandEnvironmentVariables($exePath)
                } catch {
                    Write-Log "Error expanding environment variables in path: $exePath" -Level ERROR
                }
                
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
                                $peReader = $null
                                $fileStream = [System.IO.File]::OpenRead($exePath)
                                
                                try {
                                    $peReader = New-Object System.Reflection.PortableExecutable.PEReader([System.IO.Stream]$fileStream)
                                    $taskInfo.Architecture = if ($peReader.PEHeaders.PEHeader.Magic -eq 0x20B) { "64-bit" } else { "32-bit" }
                                } finally {
                                    if ($peReader) { $peReader.Dispose() }
                                    $fileStream.Dispose()
                                }
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
        
        # Get triggers if not in quick mode
        if (-not $QuickAnalysis) {
            $triggers = $taskXml.Task.Triggers
            if ($triggers) {
                $triggerTypes = @(
                    "BootTrigger", "CalendarTrigger", "DailyTrigger", "EventTrigger", 
                    "IdleTrigger", "LogonTrigger", "MonthlyDOWTrigger", "MonthlyTrigger", 
                    "RegistrationTrigger", "SessionStateChangeTrigger", "TimeTrigger", "WeeklyTrigger"
                )
                
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
        }
        
        return $taskInfo
    } catch {
        Write-Log "Error analyzing task $($Task.TaskName): $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Get-DotNetScheduledTasks {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeSystemTasks = $true,
        
        [Parameter()]
        [switch]$IncludeDisabled = $false,
        
        [Parameter()]
        [switch]$QuickAnalysis
    )
    
    $scheduledTasks = @()
    $taskCount = 0
    $dotNetTaskCount = 0
    
    Write-Log "Scanning scheduled tasks..." -Level INFO
    
    try {
        # Get all tasks or just enabled tasks based on parameter
        if ($IncludeDisabled) {
            $allTasks = Get-ScheduledTask
        } else {
            $allTasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
        }
        
        # Exclude system tasks if requested
        if (-not $IncludeSystemTasks) {
            $allTasks = $allTasks | Where-Object { $_.TaskPath -notlike "\Microsoft\Windows\*" }
        }
        
        Write-Log "Found $($allTasks.Count) scheduled tasks to analyze." -Level INFO
        
        foreach ($task in $allTasks) {
            $taskCount++
            try {
                $taskAnalysis = Get-ScheduledTaskDotNetInfo -Task $task -QuickAnalysis:$QuickAnalysis
                
                if ($taskAnalysis -and $taskAnalysis.DotNetVersion -ne "Unknown" -and 
                    $taskAnalysis.DotNetVersion -ne "Not a .NET executable" -and 
                    $taskAnalysis.DotNetVersion -ne "Executable not found at path") {
                    
                    $dotNetTaskCount++
                    $scheduledTasks += $taskAnalysis
                    
                    # Write short summary to console
                    Write-Log "Task: $($task.TaskName)" -Level INFO
                    Write-Log "   .NET Version: $($taskAnalysis.DotNetVersion)" -Level INFO
                    Write-Log "   Executable: $($taskAnalysis.Executable)" -Level INFO
                    Write-Log "   Architecture: $($taskAnalysis.Architecture)" -Level INFO
                    Write-Log "   Run As: $($taskAnalysis.RunAsUser)" -Level INFO
                    if ($taskAnalysis.Triggers.Count -gt 0 -and -not $QuickAnalysis) {
                        Write-Log "   Triggers: $($taskAnalysis.Triggers[0])" -Level INFO
                        if ($taskAnalysis.Triggers.Count -gt 1) {
                            Write-Log "   ... and $($taskAnalysis.Triggers.Count - 1) more triggers" -Level INFO
                        }
                    }
                    Write-Log "   " -Level INFO
                }
            } catch {
                Write-Log "Error analyzing task $($task.TaskName): $($_.Exception.Message)" -Level ERROR
            }
            
            # Show progress for long-running analysis
            if ($taskCount % 10 -eq 0) {
                Write-Log "Processed $taskCount/$($allTasks.Count) tasks..." -Level DETAIL
            }
        }
    } catch {
        Write-Log "Error getting scheduled tasks: $($_.Exception.Message)" -Level ERROR
    }
    
    Write-Log "Found $dotNetTaskCount .NET scheduled tasks out of $taskCount total tasks." -Level INFO
    
    return [PSCustomObject]@{
        Tasks = $scheduledTasks
        TotalCount = $taskCount
        DotNetCount = $dotNetTaskCount
    }
}

Export-ModuleMember -Function Get-ScheduledTaskDotNetInfo, Get-DotNetScheduledTasks