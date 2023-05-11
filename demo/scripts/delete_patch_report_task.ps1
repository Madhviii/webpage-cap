# Delete the post patching patch report scheduled task.

$logPath="C:\ops\os_patching\logs\delete_patch_report_task.txt"

if ( Test-Path $logPath ) {
  Remove-Item -force $logPath
}

function log-entry($level, $msg) {
  write-host $msg
  if($script:logPath -ne $null) {
    $t = get-date -format u
    $entry = "$t`t$level`t$msg"
    $entry | out-file -filepath $script:logPath -Append
  }
}

function clearTasks() {
  $t = get-scheduledTask -TaskName "os_patching_patch_report" -EA Ignore
  if (!$t) {
    log-entry 'info' 'No scheduled task found to clear: os_patching_patch_report'
    return
  }
  log-entry 'info' 'Clearing post-reboot scheduled task'
  try {
    cmd.exe /c 'powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -command "Unregister-ScheduledTask -TaskName os_patching_patch_report -Confirm:$false"'
  }
  catch {
    log-entry 'error' 'Could not delete scheduled task os_patching_patch_report!'
    log-entry 'error' $_
  }
}
clearTasks
