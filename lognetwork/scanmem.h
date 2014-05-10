#ifndef SCANMEM_H_
#define SCANMEM_H_

#include "dbg.h"

#include <windows.h>
#include <tlhelp32.h>

struct CKey
{
	BYTE *bKeyPub_01;
	DWORD dwKeyPubSize_01;
	BYTE *bKeyPriv_01;
	DWORD dwKeyPrivSize_01;
	BYTE *bKeyPub_02;
	DWORD dwKeyPubSize_02;
	BYTE *bKeyPriv_02;
	DWORD dwKeyPrivSize_02;
	BYTE *bKeyPub_03;
	DWORD dwKeyPubSize_03;
	BYTE *bKeyPriv_03;
	DWORD dwKeyPrivSize_03;
	BYTE *bKeyPub_04;
	DWORD dwKeyPubSize_04;
	BYTE *bKeyPriv_04;
	DWORD dwKeyPrivSize_04;
	BYTE *bKeyPub_05;
	DWORD dwKeyPubSize_05;
	BYTE *bKeyPriv_05;
	DWORD dwKeyPrivSize_05;
};

BOOL SuspendAllThreads(BOOL stop);
BOOL Scan4Key(BYTE *PrivateKeyClient_01, BYTE *PrivateKeyClient_02, BYTE *PrivateKeyClient_03, BYTE *PrivateKeyClient_04);

#endif // SCANMEM_H_