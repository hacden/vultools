@echo off
color 0A
title 3389连接痕迹清除bat
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /f
del /a /f /q %HOMEPATH%\Documents\Default.rdp
del /a /f /q %HOMEPATH%\Documents\远程桌面\Default.rdp
echo 命令执行成功，请手动查看是否清除。
ping 127.0.0.1 -c 5 > nul
exit