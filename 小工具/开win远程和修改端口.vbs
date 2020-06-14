Set WshShell=CreateObject("Wscript.Shell")

Function Imput()
	imputport = InputBox("请输入一个端口号，注意：这个端口号目前不能被其它程序使用，否则会影响终端服务","开启远程和更改终端端口号", "3389", 10, 10)

If imputport<>"" Then
	If IsNumeric(imputport) Then
		opentemi = "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" 
		WshShell.RegWrite opentemi&"fDenyTSConnections",0,"REG_DWORD" 

		path1 = "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp\"
		WshShell.RegWrite path1&"PortNumber",imputport,"REG_DWORD"
			
		path2 = "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\"
		WshShell.RegWrite path2&"PortNumber",imputport,"REG_DWORD"
		
		wscript.echo "操作成功"
	Else wscript.echo "输入出错，请重新输入"
		Imput()
	

	End If
		Else wscript.echo "操作已经取消"
	End If
End Function
Imput()
set WshShell = nothing


