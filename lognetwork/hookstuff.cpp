#include "hookstuff.h"

std::list<SockMonitor*> lsock;

//BOOL (__stdcall *Resume_VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = NULL;

int (__stdcall *Resume_connect)(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen) = NULL;

int (__stdcall *Resume_WSARecv)(
  _In_     SOCKET s,
  _Inout_  LPWSABUF lpBuffers,
  _In_     DWORD dwBufferCount,
  _Out_    LPDWORD lpNumberOfBytesRecvd,
  _Inout_  LPDWORD lpFlags,
  _In_     LPWSAOVERLAPPED lpOverlapped,
  _In_     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) = NULL;

int (__stdcall *Resume_WSASend)(
  _In_   SOCKET s,
  _In_   LPWSABUF lpBuffers,
  _In_   DWORD dwBufferCount,
  _Out_  LPDWORD lpNumberOfBytesSent,
  _In_   DWORD dwFlags,
  _In_   LPWSAOVERLAPPED lpOverlapped,
  _In_   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) = NULL;

void setup_hook(char *module, char *name_export, void *Hook_func, void *trampo, DWORD addr)
{
	DWORD OldProtect;
	DWORD len;
	FARPROC Proc;

	if (addr != 0)
	{
		Proc = (FARPROC)addr;
	}
	else
	{
		Proc = GetProcAddress(GetModuleHandleA(module), name_export);
		if (!Proc)
			return;
	}
	len = 0;
	while (len < 5)
		len += LDE((BYTE*)Proc + len , LDE_X86);
	memcpy(trampo, Proc, len);
	*(BYTE *)((BYTE*)trampo + len) = 0xE9;
	*(DWORD *)((BYTE*)trampo + len + 1) = (BYTE*)Proc - (BYTE*)trampo - 5;
	VirtualProtect(Proc, len, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(BYTE*)Proc = 0xE9;
	*(DWORD*)((char*)Proc + 1) = (BYTE*)Hook_func - (BYTE*)Proc - 5;
	VirtualProtect(Proc, len, OldProtect, &OldProtect);
}

/* Be careful this DRM calls a lot VirtualProtect */
/* They don't call for example one time VirtualProtect on .txt section, but about (.txt section size / 4) ... */
/*BOOL __stdcall Hook_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    DWORD return_addr;
	DWORD dwOldProt;

	__asm
	{
		mov eax, [ebp + 4]
		mov return_addr, eax
	}
	if (lpAddress >= (LPVOID)dwTxtBase && lpAddress <= (LPVOID)(dwTxtBase + dwTxtSize))
	{
		if (flNewProtect == PAGE_EXECUTE_READ)
		return (Resume_VirtualProtect(lpAddress, dwSize, PAGE_NOACCESS, lpflOldProtect));
	}
	return (Resume_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect));
}*/
VOID LogSetKey(VOID)
{
	dbg_msg("[+] Hook_AES_SetKey!\n");
}

DWORD (__stdcall *Resume_AES_SetKey)(void) = NULL;

DWORD __declspec (naked)Hook_AES_SetKey(void)
{
	__asm
	{
		//jmp $
		pushad

		//push	eax
		call	LogSetKey
		//add	esp, 0x4

		popad
		jmp Resume_AES_SetKey
	}
}


DWORD first_run = 0;

VOID PatchFault(VOID)
{
	DWORD OldProtect;
	PVOID Proc = (PVOID)0x0044BB38;

	VirtualProtect(Proc, 5, PAGE_EXECUTE_READWRITE, &OldProtect);
	//*(BYTE *)((BYTE*)Proc) = 0x90;
	//*(BYTE *)((BYTE*)Proc + 1) = 0xE9;
	//*(DWORD*)(Proc) = 0xFFFFFFFF;
	//*(DWORD*)((DWORD*)Proc + 4) = 0xFFFFFFFF;
	memset(Proc, 0x90, 5);
	VirtualProtect(Proc, 5, OldProtect, &OldProtect);
}

int __stdcall Hook_connect(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen)
{
	DWORD dwBaseAddr = 0;
	sockaddr_in *serv = (sockaddr_in*)name;
	DWORD port;
	char *addr;

	addr = inet_ntoa(serv->sin_addr);
	port = ntohs(serv->sin_port);

	dbg_msg("[+] connect called !\n");
	dbg_msg("[+] serv : %s:%d\n", addr, port);
	if (port != 443)
	{
		lsock.push_back(new SockMonitor(s, addr, port));
	}
	/*if (first_run == 0)
	{
		/*__asm
		{
			jmp $
		}*/
		/*dwBaseAddr = (DWORD)GetModuleHandleA(NULL);
		printf("[+] dwBaseAddr = %08X\n", dwBaseAddr);
		/* 00D4BFD0   /E1 51           LOOPDE SHORT eso.00D4C023 
		0x94bfd0
		*/
		/*first_run = 1;
		Resume_AES_SetKey = (DWORD(__stdcall *)(void))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memset(Resume_AES_SetKey, 0x90, 0x1000);
		setup_hook("TESO", "TESO", &Hook_AES_SetKey, Resume_AES_SetKey, dwBaseAddr + 0x94bfd0);
		PatchFault();
	}*/

	return Resume_connect(s, name, namelen);
}

int __stdcall Hook_WSARecv(
  _In_     SOCKET s,
  _Inout_  LPWSABUF lpBuffers,
  _In_     DWORD dwBufferCount,
  _Out_    LPDWORD lpNumberOfBytesRecvd,
  _Inout_  LPDWORD lpFlags,
  _In_     LPWSAOVERLAPPED lpOverlapped,
  _In_     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	int ret;
  	std::list<SockMonitor*>::const_iterator lit (lsock.begin()), lend(lsock.end());

	ret = Resume_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
  	for (; lit != lend; ++lit)
  	{
  		if ((*lit)->s == s)
  		{
			dbg_msg("[+] WSARecv : %s:%d (encrypted: %s)\n", (*lit)->addr.c_str(), (*lit)->port, ((*lit)->encrypted == FALSE) ? "FALSE" : "TRUE");
			if (dwBufferCount != 1)
			{
				dbg_msg("[-] dwBufferCount != 1");
				__asm
				{
					jmp $
				}
			}
			hexdump(lpBuffers[0].buf, *lpNumberOfBytesRecvd);
			ParsePacketServ(*lit, (BYTE*)lpBuffers[0].buf, *lpNumberOfBytesRecvd);
			break;
  		}
  	}
	return (ret);
}

int __stdcall Hook_WSASend(
  _In_   SOCKET s,
  _In_   LPWSABUF lpBuffers,
  _In_   DWORD dwBufferCount,
  _Out_  LPDWORD lpNumberOfBytesSent,
  _In_   DWORD dwFlags,
  _In_   LPWSAOVERLAPPED lpOverlapped,
  _In_   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	int ret;
  	std::list<SockMonitor*>::const_iterator lit (lsock.begin()), lend(lsock.end());

	ret = Resume_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
  	for (; lit != lend; ++lit)
  	{
  		if ((*lit)->s == s)
  		{
			dbg_msg("[+] WSASend : %s:%d (encrypted: %s)\n", (*lit)->addr.c_str(), (*lit)->port, ((*lit)->encrypted == FALSE) ? "FALSE" : "TRUE");
			if (dwBufferCount != 1)
			{
				dbg_msg("[-] dwBufferCount != 1");
				__asm
				{
					jmp $
				}
			}
			hexdump(lpBuffers[0].buf, *lpNumberOfBytesSent);
			ParsePacketClient(*lit, (BYTE*)lpBuffers[0].buf, *lpNumberOfBytesSent);
			break;
  		}
  	}
	return (ret);
}

void setup_Hook_VirtualProtect(void)
{
	/*Resume_VirtualProtect = (BOOL(__stdcall *)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_VirtualProtect, 0x90, 0x1000);
	setup_hook("kernel32.dll", "VirtualProtect", &Hook_VirtualProtect, Resume_VirtualProtect, 0);*/
}

void setup_Hook_connect(void)
{
	LoadLibraryA("Ws2_32.dll");

	Resume_connect = (int(__stdcall *)(SOCKET, const struct sockaddr*, int))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_connect, 0x90, 0x1000);
	setup_hook("Ws2_32.dll", "connect", &Hook_connect, Resume_connect, 0);
}

void setup_Hook_recv(void)
{
	LoadLibraryA("Ws2_32.dll");

	Resume_WSARecv = (int(__stdcall *)(SOCKET,
LPWSABUF,
DWORD,
LPDWORD,
LPDWORD,
LPWSAOVERLAPPED,
LPWSAOVERLAPPED_COMPLETION_ROUTINE))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_WSARecv, 0x90, 0x1000);
	setup_hook("Ws2_32.dll", "WSARecv", &Hook_WSARecv, Resume_WSARecv, 0);
}

void setup_Hook_send(void)
{
	LoadLibraryA("Ws2_32.dll");

	Resume_WSASend = (int(__stdcall *)(SOCKET,
LPWSABUF,
DWORD,
LPDWORD,
DWORD,
LPWSAOVERLAPPED,
LPWSAOVERLAPPED_COMPLETION_ROUTINE))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_WSASend, 0x90, 0x1000);
	setup_hook("Ws2_32.dll", "WSASend", &Hook_WSASend, Resume_WSASend, 0);
}

void setup_all_hook(void)
{
	setup_Hook_connect();
	setup_Hook_recv();
	setup_Hook_send();
}