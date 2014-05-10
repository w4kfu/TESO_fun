#ifndef HOOK_STUFF_H_
#define HOOK_STUFF_H_

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stddef.h>
#include <Winsock2.h>

#include <string>
#include <list>

#pragma comment(lib, "Ws2_32.lib")

#include "dbg.h"
#include "packet.h"

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CTR_Mode;

struct SockMonitor
{
	SOCKET s;
	std::string addr;
	DWORD port;
	BOOL encrypted;
	BYTE PrivateKeyClient_01[0x14];
	BYTE PrivateKeyClient_02[0x14];
	BYTE PrivateKeyClient_03[0x14];
	BYTE PrivateKeyClient_04[0x14];
	CTR_Mode<AES>::Decryption d_recv;
	CTR_Mode<AES>::Decryption d_send;

	SockMonitor(SOCKET sock, char *a, DWORD p)
	{
		s = sock;
		addr = a;
		port = p;
		encrypted = FALSE;
	}
};

#define LDE_X86 0

#ifdef __cplusplus
extern "C"
#endif
int __stdcall LDE(void* address , DWORD type);

void setup_hook(char *module, char *name_export, void *Hook_func, void *trampo, DWORD addr);
void setup_all_hook(void);

#endif // HOOK_STUFF_H_