<#
.SYNOPSIS
Chef driving process to install updates from Windows Update, and handle multiple reboots.

.DESCRIPTION
Use PSWindowsUpdate to selectively install updates from Windows Update, and handle multiple reboots.
Script is put in place via Chef templating in cookbook os_patching. Values for most parameters are filled in via that process.

Work flow:
1. Email the start of patching
2. Check for pending reboots
3. Handle reboot if needed
4. Install servicing stack updates
5. Handle reboot if needed
6. Install general updates
7. Handle reboot if needed

If reboots are not supressed, handling the reboot will cause a scheduled task to be setup that triggers when the system starts
This task is passed the stage to run, and how many reboots have already occured, and the workflow resumes from there.

.PARAMETER stage
Optional What stage to execute.

.PARAMETER rebootCount
Optional Defaults to 0 (no reboots have yet occured). Pass in the current reboot count to allow the script to keep track of number of reboots. Increment for each subsequent call to the script post-reboot.

.EXAMPLE
install-ospatches.ps1 -stage servicing -rebootCount 0

.EXAMPLE
install-ospatches.ps1 -stage general -rebootCount 1

.EXAMPLE
install-ospatches.ps1


.NOTES
Version:        1.0.0 (May 2020)
Author:         Lehman, Michael <michael.lehman@capgemini.com>
Creation Date:  Jan 30th, 2020
Modified Date:  May 23rd, 2022
#>
#------------------------------------------------------------------------------------------------------------
param(
  [Parameter(Mandatory = $false)]
  [String] $stage,

  [Parameter(Mandatory = $false)]
  [Int] $rebootCount = 0

)

#------------------------------------------------------------------------------------------------------------
function log-entry($level, $msg) {
  write-host $msg
  if($script:logPath -ne $null) {
    $t = get-date -format u
    $entry = "$t`t$level`t$msg"
    $entry | out-file -filepath $script:logPath -Append
  }
}

#------------------------------------------------------------------------------------------------------------
# Chef Template Parameters
#------------------------------------------------------------------------------------------------------------
#  noReboot
# Optional Switch to suppress reboots. Only stage will be used as a parameter in this mode.

#  maxReboots
# Optional Maximum number of reboot cycles to allow before exiting. -1 means infinite. Defaults to -1.

#  timeEnd
# Optional  Time past which no additional actions/reboot cycles will be started (YYYY/MM/DD HH/mm). Note that this only checks at the start of an action. Once an action starts, it runs to completion. Defaults to not checking.

#  logPath
# Optional A file to log to. Log entries will be appended. If nothing is specified, $env:TEMP\install_os_patches.txt will be created and logged to.

#  sleepDelay
# Optional A sleep in seconds at the start of the script to allow killing of the tasks post-reboot in case of issues. Defaults to 300 sec (5min)

# Emailaddr
# Email notifications for the provided email id's
#------------------------------------------------------------------------------------------------------------

$logPath = "c:\ops\os_patching\os_patching_log.txt"
$sleepDelay = 100
$emailAddr = ""

$patchList =  [ordered]@{}

$patchList['1_servicing'] = @()
$patchList['1_servicing'] += 'Servicing Stack Update for Windows Server'

$patchList['2_general'] = @()
$patchList['2_general'] += 'Cumulative Update for Windows Server'
$patchList['2_general'] += 'Cumulative Security Update for Internet Explorer'
$patchList['2_general'] += 'Cumulative Update for .NET'
$patchList['2_general'] += 'Office 365 Client Update'
$patchList['2_general'] += 'Security Update for Windows Server'
$patchList['2_general'] += 'Update for Windows Server'
$patchList['2_general'] += 'Security Update for Microsoft .NET Framework'
$patchList['2_general'] += 'Security Only update for .NET Framework'
$patchList['2_general'] += 'Security Monthly Quality Rollup for Windows Server'
$patchList['2_general'] += 'Security Only Quality Update for Windows Server'
$patchList['2_general'] += 'Security Update for Microsoft ASP.NET'
$patchList['2_general'] += 'Definition Update for Microsoft Office'
$patchList['2_general'] += 'Security Update for Microsoft Office'
$patchList['2_general'] += 'Security Update for Microsoft Excel'
$patchList['2_general'] += 'Security Update for Microsoft OneNote'
$patchList['2_general'] += 'Security Update for Microsoft PowerPoint'
$patchList['2_general'] += 'Security Update for Microsoft Visual Studio'
$patchList['2_general'] += 'Security Update for Microsoft Visual C'
$patchList['2_general'] += 'Security Update for Microsoft InfoPath'
$patchList['2_general'] += 'Security Update for Microsoft Access'
$patchList['2_general'] += 'Security Update for Microsoft Outlook'
$patchList['2_general'] += 'Security Update for Microsoft Project'
$patchList['2_general'] += 'Security Update for Microsoft Publisher'
$patchList['2_general'] += 'Security Update for Microsoft Excel'
$patchList['2_general'] += 'Security Update for Microsoft Visio'
$patchList['2_general'] += 'Security Update for Microsoft Word'
$patchList['2_general'] += 'Security Update for Microsoft Silverlight'
$patchList['2_general'] += 'Security Update for Adobe Flash Player'
$patchList['2_general'] += 'Update for Microsoft Office'
$patchList['2_general'] += 'Update for Windows Defender Antivirus antimalware platform'
$patchList['2_general'] += 'Update for Microsoft Defender Antivirus antimalware platform'
$patchList['2_general'] += 'Security Intelligence Update for Windows Defender Antivirus'
$patchList['2_general'] += 'Security Intelligence Update for Microsoft Defender Antivirus'
$patchList['2_general'] += 'Security Update for Skype for Business'
$patchList['2_general'] += 'Update for Skype for Business'
$patchList['2_general'] += '7-zip update'
$patchList['2_general'] += 'Adobe Acrobat Reader DC update'
$patchList['2_general'] += 'Mozilla Firefox update'
$patchList['2_general'] += 'Wireshark update'
$patchList['2_general'] += 'Google Chrome update'
$patchList['2_general'] += 'Git for Windows update'
$patchList['2_general'] += 'Vmware tools update'
$patchList['2_general'] += 'Spectre Variant 2 and Meltdown update'
$patchList['2_general'] += 'Information Disclosure Vulnerability (CVE-2017-8529) update'
$patchList['2_general'] += 'Windows Speculative Execution Vulnerabilities update'
$patchList['2_general'] += 'SSL 3.0 Vulnerability update'
$patchList['2_general'] += 'Microsoft 365 Apps Update'
$patchList['2_general'] += 'Service Pack 1 for Microsoft Office'
$patchList['2_general'] += 'Service Pack 2 for Microsoft Office'
$patchList['2_general'] += 'Windows Malicious Software Removal'
$patchList['2_general'] += 'Update for Microsoft OneDrive for Business'
$patchList['2_general'] += 'Putty update'
$patchList['2_general'] += 'Artifex Ghostscript update'
$patchList['2_general'] += 'Update for Windows Server 2008 R2'
$patchList['2_general'] += '2018-05 Security Only Quality Update for Windows Server 2012 R2'
$patchList['2_general'] += 'Microsoft .NET Framework 4.8'
$patchList['2_general'] += '2021-06 Security and Quality Rollup for .NET Framework'
$patchList['2_general'] += '2019-03 Update for .NET Framework 3'
$patchList['2_general'] += 'Update for Removal of Adobe Flash Player'

$rebootMethod = "automatic"
$noReboot = $true
if($rebootMethod -eq 'automatic') {
  $noReboot = $false
}
$maxReboots = 5
if($maxReboots -is [int]) {
  if($maxReboots -lt 1){
    throw "MaxReboots must be an integer of -1 (infinity) or a positive number"
  }
} else {
  throw "MaxReboots must be an integer of -1 (infinity) or a positive number"
}

$timeEnd = "2023/03/05 02:00"
if($timeEnd -ne '') {
  try {
    [datetime]::ParseExact($timeEnd , 'yyyy/MM/dd HH:mm', $null)
  }
  catch {
    throw "timeEnd is in the wrong format ($timeEnd). Use this format yyyy/MM/dd HH:mm"
  }
}

#------------------------------------------------------------------------------------------------------------
# Functions
#------------------------------------------------------------------------------------------------------------
function clearTasks() {
  $t = get-scheduledTask -TaskName "os_patching_post_reboot" -EA Ignore
  if (!$t) {
    log-entry 'info' 'No scheduled task found to clear: os_patching_post_reboot'
    return
  }
  log-entry 'info' 'Clearing post-reboot scheduled task'
  try {
    cmd.exe /c 'powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -command "Unregister-ScheduledTask -TaskName os_patching_post_reboot -Confirm:$false"'
  }
  catch {
    log-entry 'error' 'Could not delete scheduled task os_patching_post_reboot!'
    log-entry 'error' $_
  }
}


#------------------------------------------------------------------------------------------------------------
function testPendingReboot () {
  if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) {
    log-entry 'info' "Reboot Detected via: HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    return $true
  }

  if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) {
    log-entry 'info' "Reboot Detected via: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    return $true
  }
  if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) {
    log-entry 'info' "Reboot Detected via: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager, PendingFileRenameOperations"
    return $true
  }
  return $false
}

#............................................................
function handleReboot() {
  if ((testPendingReboot) -eq $false) {
    log-entry 'info' 'No reboot needed - Continuing...'
    return
  }
  else {
    log-entry 'info' 'A reboot is needed'
  }

  if ($noReboot) {
    log-entry 'info' 'Reboots supressed. Continuing...'
    return
  }

  if ($script:maxReboots -ge 0 -and $script:rebootCount -ge $script:maxReboots - 1) {
    log-entry 'info' 'This reboot will be final reboot due to maxReboots'
  }

  $script:rebootCount += 1
  $t = get-scheduledTask -TaskName "os_patching_post_reboot" -EA Ignore
  if ($t) {
    clearTasks
  }

  log-entry 'info' 'Setting up scheduled task to handle post-reboot tasks'
  $cwd = $PSCommandPath.SubString(0, $PSCommandPath.LastIndexOf('\') + 1)

  # keep in mind that stage here is the stage we just executed, but will be empty on the first run through if a reboot is needed
  $cmd = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -File ' + $PSCommandPath + " -rebootCount $script:rebootCount"
  if($null -ne $script:stage -and $script:stage -ne '') {
    $cmd += " -stage $script:stage"
  }

  $action = New-ScheduledTaskAction -Execute powershell.exe -Argument $cmd -WorkingDirectory $cwd
  $trigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 3)
  $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew
  $t = Register-ScheduledTask -TaskName "os_patching_post_reboot" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -EA Ignore
  if ($t) {
    log-entry 'info' 'Post reboot task created'
  }
  else {
    log-entry 'error' 'Post reboot task could NOT be created'
  }

  log-entry 'info' 'Rebooting'
  restart-computer -force
  exit
}

#............................................................
function installPatches($stage) {
  log-entry 'info' "$stage - Stage Starting"
  foreach($title in $script:patchList[$stage]) {
    log-entry 'info' "$stage - Checking for $title"
     Install-WindowsUpdate -verbose -install -IgnoreReboot -AcceptAll -NotCategory 'Drivers' -IgnoreUserInput -title $title *>> $logPath
  }
  log-entry 'info' "$stage - Stage Complete"
}

#............................................................
#Function for sending email
function send_patch_status($email,$emailcc){
## Variables
$smtpMail ="smtp.resideo.com"  ## Add SMTP Server Name ##
$from ="patching_notifications@resideo.com"
$to=$email.Split(",").Trim()
$to_tmp = @()
foreach($i in $to)
{
  $to_tmp += $i
}
$Notify_to = $to_tmp
$Notify_cc = $emailcc
#$failed_to = 'isresideo-automation.in@capgemini.com'
#$scriptName="Install Patches"
$server_name=hostname
$subject="$server_name OS Patching Notification : Start of Patching"
$timeEnd 
$inputType="Email"
$notify_body = "HI, 

*** This is an Automated message about patching notification of the server ***

Patching for server $server_name is being started....
Notification will be sent out post the completion of patching.

In case of any queries or details contact - Wintel Team.

Thanks and Regards,
Automation Team

# Do not reply to this email, this is an auto-generated email."
  
################Sending status via email########################

   Send-MailMessage -Body $notify_body -Subject $subject -SmtpServer $smtpMail -From $from -To $Notify_to -Cc $Notify_cc -Priority High

} # ### SENDPATCH REPORT FUNCTION ENDS


#============================================================================================================
#------------------------------------------------------------------------------------------------------------
# Main Script
#------------------------------------------------------------------------------------------------------------
#============================================================================================================

# clear the log file if it hasn't been touched in 21 days
if (test-path $logPath) {
  $f = get-item $logPath
  if($f.lastWriteTime -lt $(get-date).AddDays(-21)) {
    remove-item $logPath
  }
}

# log the pararmeters we were called with
log-entry 'info' "install-ospatches.ps1 called with:`r`nstage: $stage`r`nnoReboot: $noReboot`r`nrebootCount: $rebootCount`r`nmaxReboots: $maxReboots`r`ntimeEnd: $timeEnd"

# Email Notification for the server and log
if($rebootCount -eq 0)
{
    log-entry 'info' "Checking for sending Email Notifications"

    if ($emailAddr -ne "" -or $emailAddr -ne $null)
    {
     $emailcc ="isresideo-wintel.in@capgemini.com"
      send_patch_status "$emailAddr" "$emailcc"
      log-entry 'info' "Sending Email Notifications for the $emailaddr and CC'ing Wintel DL"
      $mailsent ="yes"
    }
    else
    { log-entry 'info' "No email notifications for the server"
    }
}
   else
    { log-entry 'info' "Reboot Count is more than 0. The email notifications is already sent for the server"
    }

# make sure we have our pre-reqs
try {
  import-module PSWindowsUpdate
}
catch {
  log-entry 'error' 'Required module PSWindowsUpdate is not available!'
  throw "Required module PSWindowsUpdate is not available!"
}


# Check if we're still inside the specified window, and exit if we've exceeced it
if ($null -ne $timeEnd -and $timeEnd -ne '') {
  $d = [DateTime]::parseExact($timeEnd, "yyyy/MM/dd HH:mm", $null)

  # if the current date/time is greater than the end time, we've exceeded the time
  if ((get-date)-gt $d) {
    log-entry 'warn' 'TimeEnd reached! Clearing tasks and exiting...'
    clearTasks
    return
  }
}

# Check if we've reached the maximum number of reboots we're allowing, and exit if we've exceeded it
if ($maxReboots -ge 0 -and $rebootCount -ge $maxReboots) {
    $reboot_value = "no_reboot"
  log-entry 'info' 'Max rebootcount reached. Installing the patches without Reboot'
  #C:\ops\os_patching\check-patchinstall.ps1 -email $emailAddr -reboot $rebootMethod
  C:\ops\os_patching\manual_updates_installation.ps1 -email $email_addr -reboot $reboot_value
  #clearTasks
  exit
}


# Sleep for specified second
# This is a safety feature in case of errors to allow admins to stop/clear the task after a reboot
if ($sleepDelay -gt 0) {
  log-entry 'info' "Sleeping for $sleepDelay seconds"
  start-sleep $sleepDelay
}

# Check if a reboot from other processes is needed before starting
handleReboot

# if no stage was passed in, we're in the first call.. get the first key from the patchList/stages
# if a key was passed in, that is the stage that was just executed.. get the next stage (if there is one)
if($null -eq $stage -or $stage -eq '') {
  log-entry 'info' "PatchList:" $patchList
  $stage = $($patchList.keys)[0]
  log-entry 'info' "Patch Stage: $stage"
  $stageKey = 0
} else {
  $stageKey = [array]::indexof($patchList.keys, $stage)
  if($stageKey -eq -1) {
    log-entry 'error' "Specified stage ($stage) was not found in the patchList"
    clearTasks
    return
  }
  log-entry "Resuming after stage $stage ($stageKey)"
  #stage found.. increment so we execute the next stage
  $stageKey += 1
}

# handle each stage
# If the system reboots, we should just come back into this loop at the next stage and carry
while($stageKey -lt $patchList.count) {
  log-entry 'info' "Stage Count: " $patchList.count
  $stage = $($patchList.keys)[$stageKey]
  installPatches $stage
  handleReboot
  $stageKey += 1
}

clearTasks
log-entry 'info' 'All stages complete. Running the post install checks...'
start-sleep 50
if ($emailAddr -eq "" -or $emailAddr -eq $null)
{
  log-entry 'info' "Email address not provided"
  $emailAddr="isresideo-wintel.in@capgemini.com"
  log-entry 'info' $emailAddr
}
# $tasks=Get-ScheduledTask -TaskName "os_patching_post_reboot" -ErrorAction SilentlyContinue
# $task_name=$tasks.TaskName
#if ( $task_name -eq $null ){
  C:\ops\os_patching\check-patchinstall.ps1 -email $emailAddr -reboot $rebootMethod
#}
