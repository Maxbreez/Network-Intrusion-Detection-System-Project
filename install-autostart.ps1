<#
.SYNOPSIS
    Sets up (or tears down) a Scheduled Task so nids.py launches at logon.

.DESCRIPTION
    Wanted this to auto-start but it's a GUI app that needs live capture,
    so it can't just run as a normal headless Windows service (services
    run in session 0 - no desktop, no capture access, doesn't work).
    A per-user logon task is basically the closest thing.

    Heads up - you'll probably still hit a UAC prompt, or capture will
    just fail to start, unless your UAC settings allow silent elevation
    for scheduled tasks. That's a Windows policy thing, nothing this
    script can fix.

.PARAMETER Uninstall
    Tears the task back down instead of creating it.

.EXAMPLE
    .\install-autostart.ps1
.EXAMPLE
    .\install-autostart.ps1 -Uninstall
#>
param(
    [switch]$Uninstall
)

$TaskName = "NIDS"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    } else {
        Write-Host "No scheduled task named '$TaskName' found - nothing to remove."
    }
    return
}

$PythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $PythonCmd) { $PythonCmd = Get-Command python -ErrorAction SilentlyContinue }
if (-not $PythonCmd) {
    Write-Error "Could not find python.exe on PATH. Install Python or add it to PATH first, then re-run this script."
    return
}
$PythonExe = $PythonCmd.Source

$Action = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$ScriptDir\nids.py`"" -WorkingDirectory $ScriptDir
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Principal $Principal -Settings $Settings `
    -Description "Launches nids.py (NIDS) at logon" -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName' - nids.py will launch at your next logon."
Write-Host "To remove it later: .\install-autostart.ps1 -Uninstall"
Write-Host "To test it right now without logging out: Start-ScheduledTask -TaskName '$TaskName'"
