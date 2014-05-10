#include "scanmem.h"

BOOL SuspendAllThreads(BOOL stop)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
	THREADENTRY32 te32;
	DWORD dwOwnerPID = GetCurrentProcessId();
	DWORD dwOwnerTID = GetCurrentThreadId();
	HANDLE hThread;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		dbg_msg("[-] SuspendAllThreads - CreateToolhelp32Snapshot() failed\n");
		return FALSE;
	}
	te32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hThreadSnap, &te32)) 
	{
		dbg_msg("[-] SuspendAllThreads - Thread32First() failed\n");
		CloseHandle(hThreadSnap);
		return FALSE;
	}
	do 
	{ 
		if (te32.th32OwnerProcessID == dwOwnerPID && te32.th32ThreadID != dwOwnerTID)
		{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			if (stop == TRUE)
			{
 				SuspendThread(hThread);
			}
			else
			{
				ResumeThread(hThread);
			}
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

VOID DumpKeys(struct CKey *ckey)
{
	dbg_msg("[+] bKeyPub_01 :\n");
	hexdump(ckey->bKeyPub_01, ckey->dwKeyPubSize_01);
	dbg_msg("[+] bKeyPriv_01 :\n");
	hexdump(ckey->bKeyPriv_01, ckey->dwKeyPrivSize_01);

	dbg_msg("[+] bKeyPub_02 :\n");
	hexdump(ckey->bKeyPub_02, ckey->dwKeyPubSize_02);
	dbg_msg("[+] bKeyPriv_02 :\n");
	hexdump(ckey->bKeyPriv_02, ckey->dwKeyPrivSize_02);	

	dbg_msg("[+] bKeyPub_03 :\n");
	hexdump(ckey->bKeyPub_03, ckey->dwKeyPubSize_03);
	dbg_msg("[+] bKeyPriv_03 :\n");
	hexdump(ckey->bKeyPriv_03, ckey->dwKeyPrivSize_03);	

	dbg_msg("[+] bKeyPub_04 :\n");
	hexdump(ckey->bKeyPub_04, ckey->dwKeyPubSize_04);
	dbg_msg("[+] bKeyPriv_04 :\n");
	hexdump(ckey->bKeyPriv_04, ckey->dwKeyPrivSize_04);	

	dbg_msg("[+] bKeyPub_05 :\n");
	hexdump(ckey->bKeyPub_05, ckey->dwKeyPubSize_05);
	dbg_msg("[+] bKeyPriv_05 :\n");
	hexdump(ckey->bKeyPriv_05, ckey->dwKeyPrivSize_05);
}

#define SIZE_PATTERN_KEY (8 * 5)

BOOL Scan4Key(BYTE *PrivateKeyClient_01, BYTE *PrivateKeyClient_02, BYTE *PrivateKeyClient_03, BYTE *PrivateKeyClient_04)
{
	DWORD i;
	DWORD Limit = 0x80000000; //0xC0000000 : 0x80000000;
	MEMORY_BASIC_INFORMATION MemInfo;
	HANDLE hProc = GetCurrentProcess();
	SIZE_T sRet;
	DWORD PageCount;
	DWORD j, k;
	//BYTE *bData = NULL;
	struct CKey *ckey = NULL;
	BYTE PageBuffer[0x1000];
	SIZE_T BytesRead = 0;
	//DWORD OldProtect;

	i = 0x2389000;
	for (i = 0x0; i < Limit; i++)
	{
		sRet = VirtualQueryEx(hProc, (LPCVOID)i, &MemInfo, sizeof(MemInfo));
		if (sRet == 0 || MemInfo.State == MEM_FREE || MemInfo.State == MEM_RESERVE || (MemInfo.Protect & PAGE_READONLY) != 0 || (MemInfo.Protect & PAGE_GUARD) != 0 ||
			(MemInfo.Protect & PAGE_EXECUTE) != 0 || (MemInfo.Protect & PAGE_NOACCESS) != 0)
		{
			if (sRet == 0)
			{
              i += 0x1000;
            }
            else
            {
              i += MemInfo.RegionSize;
            }
            continue;
		}
		PageCount = MemInfo.RegionSize / 0x1000;
		for (j = 0; j < PageCount; j++)
		{
			/*sRet = VirtualQueryEx(hProc, (LPCVOID)(i + j * 0x1000), &MemInfo, sizeof(MemInfo));
			if ((MemInfo.Protect & PAGE_READONLY) != 0 || (MemInfo.Protect & PAGE_GUARD) != 0)
				continue;*/
			//if (!VirtualProtect((LPVOID)(i + j * 0x1000), 0x1000, PAGE_EXECUTE_READWRITE, &OldProtect))
				//continue;
			//printf("Working on %08X\n", (LPVOID)(i + j * 0x1000));
			//Sleep(10);
			if (ReadProcessMemory(hProc, (LPCVOID)(i + j * 0x1000), PageBuffer, sizeof(PageBuffer), &BytesRead) && BytesRead != 0)
			{
			//memcpy_s(PageBuffer, sizeof(PageBuffer), (LPVOID)(i + j * 0x1000), 1);
				//Sleep(10);
				for (k = 0; k < (0x1000 - SIZE_PATTERN_KEY); k++)
				{
					ckey = (struct CKey *)(PageBuffer + k);
					if (ckey->dwKeyPubSize_01 == 0x80 && ckey->dwKeyPrivSize_01 == 0x14 &&
						ckey->dwKeyPubSize_02 == 0x80 && ckey->dwKeyPrivSize_02 == 0x14 &&
						ckey->dwKeyPubSize_03 == 0x80 && ckey->dwKeyPrivSize_03 == 0x14 &&
						ckey->dwKeyPubSize_04 == 0x80 && ckey->dwKeyPrivSize_04 == 0x14 &&
						ckey->dwKeyPubSize_05 == 0x80 && ckey->dwKeyPrivSize_05 == 0x14)
					{
						dbg_msg("[+] FOUND at %08X!\n", (DWORD)(i + j * 0x1000));
						DumpKeys(ckey);
						memcpy(PrivateKeyClient_01, ckey->bKeyPriv_01, 0x14);
						memcpy(PrivateKeyClient_02, ckey->bKeyPriv_02, 0x14);
						memcpy(PrivateKeyClient_03, ckey->bKeyPriv_03, 0x14);
						memcpy(PrivateKeyClient_04, ckey->bKeyPriv_04, 0x14);
						return TRUE;
					}
				//bData += 1;
				}
			//VirtualProtect((LPVOID)(i + j * 0x1000), 0x1000, OldProtect, &OldProtect);		
			}
		}
		i += 0x1000 * PageCount;
	}
	return FALSE;
}