# script for manual installation of failed updates

param(
  [Parameter(Mandatory = $false)]
  [String] $email,
  [String] $reboot
 )
$email_addr=$email
$reboot_val=$reboot
if($reboot_val -eq "automatic"){ $restart="forcerestart" }
if($reboot_val -eq "manual" -or $reboot_val -eq "no_reboot" ) { $restart="norestart" }
  
$oldlogPath="c:\ops\os_patching\manual_updates.txt"
if ( Test-Path $oldlogPath ) {
  Remove-Item -force $oldlogPath
}

$logPath="c:\ops\os-patching\manual_updates.txt"
if ( Test-Path $logPath ) {
  Remove-Item -force $logPath
}

#Function for the WriteLog
function log-entry($level, $msg) {
  write-host $msg
  if($script:logPath -ne $null) {
    $t = get-date -format u
    $entry = "$t`t$level`t$msg"
    $entry | out-file -filepath $script:logPath -Append
  }
}
log-entry 'info' "Input Parameter:$reboot_val"
log-entry 'info' "Restart Value:$restart"
$run_as_user=whoami
log-entry 'info' "Run as User:$run_as_user"
  
# function to download and install patches.
function install_patch(){
    # Need to download the update from IIS
    $server_os=(Get-WMIObject win32_operatingsystem).caption
    log-entry 'info' $server_os
    # define URL'S/path based on env id to download update/s from, based on OS version
    if($server_os -match '2016'){
      $legacy_path='C:\hab\user\windows_2016_legacy\config\user.toml'
      $config_path='C:\hab\user\windows_2016_config\config\user.toml'
    if( Test-Path $legacy_path ){
      $file_content=Get-Content $legacy_path | Select-String 'environment_id'
      log-entry 'info' "$legacy_path Env id: $file_content"
      if($file_content -match 'ny17') { $update_url="https://infra-wsus-amer.resideo.com/Manual-Updates-Repo/win-2016/" }
      if($file_content -match 'nl85') { $update_url="https://infra-wsus-emea.resideo.com/Manual-Updates-Repo/win-2016/" }
      if($file_content -match 'aws') { $update_url="https://infra-wsus-aws.resideo.com/Manual-Updates-Repo/win-2016/" }
    }
    if( Test-Path $config_path){
        $file_content=Get-Content $config_path | Select-String 'environment_id'
        log-entry 'info' "$config_path Env id: $file_content"
        if($file_content -match 'ny17') { $update_url="https://infra-wsus-amer.resideo.com/Manual-Updates-Repo/win-2016/" }
        if($file_content -match 'nl85') { $update_url="https://infra-wsus-emea.resideo.com/Manual-Updates-Repo/win-2016/" }
        if($file_content -match 'aws') { $update_url="https://infra-wsus-aws.resideo.com/Manual-Updates-Repo/win-2016/" }
      }
    }
    if($server_os -match '2012'){
      $legacy_path='C:\hab\user\windows_2012_legacy\config\user.toml'
      if( Test-Path $legacy_path ){
        $file_content=Get-Content $legacy_path | Select-String 'environment_id'
        log-entry 'info' "$legacy_path Env id: $file_content"     
        if($file_content -match 'ny17') { $update_url="https://infra-wsus-amer.resideo.com/Manual-Updates-Repo/win-2012/" }
        if($file_content -match 'nl85') { $update_url="https://infra-wsus-emea.resideo.com/Manual-Updates-Repo/win-2012/" }
        if($file_content -match 'aws') { $update_url="https://infra-wsus-aws.resideo.com/Manual-Updates-Repo/win-2012/" }
      }
    }
    if($server_os -match '2012 R2'){
      $legacy_path='C:\hab\user\windows_2012_legacy\config\user.toml'
      if( Test-Path $legacy_path ){
        $file_content=Get-Content $legacy_path | Select-String 'environment_id'
        log-entry 'info' "$legacy_path Env id: $file_content"     
        if($file_content -match 'ny17') { $update_url="https://infra-wsus-amer.resideo.com/Manual-Updates-Repo/win-2012R2/" }
        if($file_content -match 'nl85') { $update_url="https://infra-wsus-emea.resideo.com/Manual-Updates-Repo/win-2012R2/" }
        if($file_content -match 'aws') { $update_url="https://infra-wsus-aws.resideo.com/Manual-Updates-Repo/win-2012R2/" }
      }
    }
    log-entry 'info' "Update Path:$update_url"
    try{
        log-entry 'info' "Attempting to set registry entry HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\DisableFristRunCustomize to 1" 
        # Set-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\Main" -name "DisableFirstRunCustomize" -value 1
        Set-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main" -name "DisableFirstRunCustomize" -value 1
     }
    catch{
        log-entry 'warn' "Unable to set the registry entry required for enabling patch files, cannot proceed further, exiting!!"
        return
    }
    try{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $r=iwr "$update_url"
    log-entry 'info' $r
    log-entry 'info' $r.StatusCode
    $filelist=@()
    $filelist=$r.ParsedHtml.links | Select-Object nameProp
    log-entry 'info' $filelist.nameProp
    log-entry 'info' $filelist.nameProp.Count
    if($filelist.nameProp.Count -ge 1)
    {
        foreach($file in $filelist.nameProp)
        {
            if($file -match '.msu')
            {
                log-entry 'info' "$file is a patch file, downloading it"
                $file_path="c:\ops\$file"
                if (Test-Path "$file_path"){ log-entry 'info' "Patch file $file is already present" }
                else { 
                    log-entry 'info' "Patch file $file_path does not exists, downloading it"
                    $progressPreference = 'silentlyContinue'
                    Invoke-WebRequest -Uri "$update_url/$file" -OutFile "$file_path"
                    $progressPreference = 'Continue'
                    if( Test-Path "$file_path")
                    {
                        if ((Get-Item "$file_path").length -gt 0kb) { log-entry 'info' "Patch file $file is downloaded and is not empty" }
                    }
                }
            }
            else { log-entry 'info' "$file is not a patch file" }
        }
    }
    }
    catch{ log-entry 'error' "Update download or installation failed"}
}
  
install_patch
$InstalledPatches = Get-HotFix | Select-Object -ExpandProperty HotFixID
$Files = Get-ChildItem -Path 'C:\ops' -Filter *.msu -Recurse | Where-Object { $InstalledPatches -notcontains ( $_.BaseName -replace '^.*?\-(kb\d{7})\-.*$', '$1' ) }
if( -not $Files ){
    log-entry 'warn' "No Msu files found"
    exit
}
# moving the output file to c:\ops\os_patching from c:\ops
# Removing old file
$old_updates_list='c:\ops\os_patching\Patchs_Install_new.txt'
if(Test-Path -Path $updates_list){ Remove-Item -force $old_updates_list }

$updates_list='C:\ops\os_patching\logs\Patches_Install_new.txt'
if(Test-Path -Path $updates_list){ Remove-Item -force $updates_list }

foreach( $File in $Files ){
    $File.FullName | Out-File -FilePath $updates_list -Append
    $update=$File.FullName
    log-entry 'info' "Update Name:$update"
    Start-Process -FilePath "wusa.exe" -ArgumentList "$update /quiet /norestart" -Wait
    #Start-Process -FilePath "wusa.exe" -ArgumentList "$update /quiet /$restart" -Wait
}

# Create a task to run patch report script on startup after reboot.
# C:\ops\os_patching\patch_report.ps1 -email $email_addr -reboot $reboot_value

log-entry 'info' 'Setting up scheduled task to execute patch report on reboot'
# $cwd = $PSCommandPath.SubString(0, $PSCommandPath.LastIndexOf('\') + 1)
$script_path = "C:\ops\os_patching\patch_report.ps1"
$cmd = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -File ' + $script_path + " -email $script:email -reboot $script:reboot_val"

$action = New-ScheduledTaskAction -Execute powershell.exe -Argument $cmd
# -WorkingDirectory $cwd
$trigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 3)
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew
$t = Register-ScheduledTask -TaskName "os_patching_patch_report" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -EA Ignore
if ($t) {
  log-entry 'info' 'Post reboot reporting task created'
}
else {
  log-entry 'error' 'Post reboot reporting task could NOT be created'
}

if($reboot_val -eq "automatic")
{
  log-entry 'info' 'Rebooting'
  restart-computer -force
}
