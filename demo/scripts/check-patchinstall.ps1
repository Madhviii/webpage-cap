<#
.SYNOPSIS
This is to check the patch installation by the Chef process to install updates from Windows Update

.DESCRIPTION
This script is run after the completion of the Chef process for the patching and based on the values of the logs and events 
the below task runs.

.EXAMPLE
check-patchinstall.ps1

.NOTES
Version:        1.0.0 (Sept 2020)
Author:         Srinath S
Creation Date:  Sept 12th, 2020
#>
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
param(
  [Parameter(Mandatory = $false)]
  [String] $email,
  [String] $reboot
)

#------------------------------------------------------------------------------------------------------------
$logPath = "C:\ops\os_patching\check-patchinstall.txt"

function log-entry($level, $msg) {
  write-host $msg
  if($script:logPath -ne $null) {
    $t = get-date -format u
    $entry = "$t`t$level`t$msg"
    $entry | out-file -filepath $script:logPath -Append
  }
}
# Changing the log file to check-patchinstall.txt from check-patchinstall.log
# Hence adding logic to remove the old file
$oldlogPath = "C:\ops\os_patching\check-patchinstall.log"
if (test-path $oldlogPath) {
  $f = get-item $oldlogPath
  if($f.lastWriteTime -lt $(get-date).AddDays(-21)) {
    remove-item $oldlogPath
  }
}

# clear the log file if it hasn't been touched in 21 days
if (test-path $logPath) {
  $f = get-item $logPath
  if($f.lastWriteTime -lt $(get-date).AddDays(-21)) {
    remove-item $logPath
  }
}

$email_addr = $email
$reboot_value = $reboot
$update_status = 'failed'
log-entry 'info' 'Clearing the software distribution folder....'
C:\ops\os_patching\clear-softwaredistribution.ps1
start-sleep 50
log-entry 'info' 'software folder cleared'

try {
$patchdate = (Get-ScheduledTask -TaskName "os_patching_install_updates" | Get-ScheduledTaskInfo).LastRunTime
if (!$Patchdate){
    log-entry 'Info' "No Schedule task found.."
    }
    else
    {
    log-entry 'Info' "Schedule task is present and checking further...."
    }
}

catch {
  log-entry 'error' 'No Schedule task available!'
  throw "No Schedule task is available!"
  Cleartasks
}

$dt = Get-Date $patchdate -Format "M/dd/yyyy hh:mm:ss" # converting to this form to match the date in Get-WinEvent Output
$a = (Get-WinEvent -FilterHashTable @{ProviderName=”Microsoft-Windows-WindowsUpdateClient”;ID=19} | Where-Object { $_.TimeCreated -ge $dt }) | ft timecreated, message -auto
log-entry 'Info' "All Patches details: "$a
if (!$a)
{
  log-entry 'error' "Patch Installation has failed, Schedule task will re-run"
  log-entry 'Info' "initiating the schedule task to run again"
  $taskstate = (Get-ScheduledTask | Where-Object TaskName -eq "os_patching_install_updates").State
  if ($taskstate -eq "ready")
  {
    Start-ScheduledTask -TaskName "os_patching_install_updates"
    log-entry 'Info' "Schedule task has been started again"
  }
  Else {
    $update_status = 'failed'
    log-entry 'error' "Schedule task is not ready"
  }
}
Else
{
  log-entry 'Info' "Patches are installed running checks...."
  $update = get-hotfix | Where-Object {$_.installedon -ge $patchdate.AddDays(-1) } 
  if($update) 
  {
    $update_status = 'success'
    Write-Output "Patch is installed"
    log-entry 'Info' "Patches are installed Exiting....No more Checks"
    log-entry 'Info' "Patche Status: $update_status"
    log-entry 'Info' "Exiting..."
  }
  else 
  {
    Write-Output "No patch installed."
    log-entry 'Info' "No Patch is installed.... Running the tasks again"
    $taskstate = (Get-ScheduledTask | Where-Object TaskName -eq "os_patching_install_updates").State
    if ($taskstate -eq "ready") {
      Start-ScheduledTask -TaskName "os_patching_install_updates"
      log-entry 'Info' "Schedule task has been started again"
    }
    Else {
      log-entry 'error' "Schedule task is not ready. Calling manual patch install script for security updates installation...."
      $update_status = 'failed'
    }
  }
}

log-entry 'info' '[check-post patch install]post-patch status checking completed'
log-entry 'info' "[check-post patch install]Update status: $update_status"

if ( $update_status -eq 'failed') {
 log-entry 'warn' '[check-post patch install]Updates installation failed, will trigger manual update installation script'
 C:\ops\os_patching\manual_updates_installation.ps1 -email $email_addr -reboot $reboot_value
}

if ( $update_status -eq 'success' ) {
 log-entry 'info' '[check-post patch install]Updates installation successfully completed, calling reporting script'
 C:\ops\os_patching\patch_report.ps1 -email $email_addr
}
