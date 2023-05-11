Stop-Service -Name wuauserv
Stop-Service -Name bits
Get-ChildItem C:\Windows\SoftwareDistribution -Recurse | Remove-Item -Recurse -Force
Start-Service -Name bits
Start-Service -Name wuauserv