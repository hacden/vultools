#usage:powershell download3.ps1
$url = "http://192.168.43.111/1.exe"
$output = "3.exe"
$start_time = Get-Date
Invoke-WebRequest -Uri $url -OutFile $output
Write-Output "Time : $((Get-Date).Subtract($start_time).Seconds) second(s)"