#include <Windows.h>
#include <stdio.h>

#include "aes.h"

struct main_teso_conf
{
	HANDLE hFile;
	HANDLE hMap;
	BYTE *bMap;
	DWORD dwFileSize;
	DWORD ImageBase;
	DWORD NumberOfSections;
	PIMAGE_SECTION_HEADER ish;
	DWORD dwOffsetKey;
	DWORD dwOffsetSize;
};

struct virta_size
{
	DWORD dwVA;
	DWORD dwSize;
};

struct all_block
{
	DWORD dwSize;
	BYTE *bData;
};

void hex_dump(void *data, int size)
{
	unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    for (n = 1; n <= size; n++)
	{
        if (n % 16 == 1)
		{
            sprintf_s(addrstr, sizeof(addrstr), "%.4x", ((unsigned int)p - (unsigned int)data));
        }
        c = *p;
        if (isalnum(c) == 0)
		{
            c = '.';
        }
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat_s(hexstr, sizeof(hexstr), bytestr, sizeof(hexstr) - strlen(hexstr) - 1);
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat_s(charstr, sizeof(charstr), bytestr, sizeof(charstr) - strlen(charstr) - 1);
        if (n % 16 == 0)
		{
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
		else if (n % 8 == 0)
		{
            strncat_s(hexstr, sizeof(hexstr), "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat_s(charstr, sizeof(charstr), " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++;
    }

    if (strlen(hexstr) > 0)
	{
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

BOOL LoadFile(char *FileName, struct main_teso_conf *conf)
{
	IMAGE_DOS_HEADER *idh = NULL;
	IMAGE_NT_HEADERS *inh = NULL;

	conf->hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (conf->hFile == INVALID_HANDLE_VALUE)
    {
		printf("[-] CreateFileA() failed : %X\n", GetLastError());
		return FALSE;
    }
	conf->dwFileSize = GetFileSize(conf->hFile, 0);
	conf->hMap = CreateFileMappingA(conf->hFile, 0, PAGE_READONLY, 0, conf->dwFileSize, 0);
	if (conf->hMap == NULL)
	{
		printf("[-] CreateFileMappingA() failed : %X\n", GetLastError());
		return FALSE;
	}
	conf->bMap = (BYTE*)MapViewOfFile(conf->hMap, FILE_MAP_READ, 0, 0, conf->dwFileSize);
	if (conf->bMap == NULL)
	{
		printf("[-] MapViewOfFile() failed : %X\n", GetLastError());
		return FALSE;
	}
	idh = (IMAGE_DOS_HEADER *)conf->bMap;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] IMAGE_DOS_SIGNATURE failed\n");
		return FALSE;
	}
	inh = (IMAGE_NT_HEADERS *)((BYTE*)conf->bMap + idh->e_lfanew);
	if (inh->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[-] IMAGE_NT_SIGNATURE\n");
		return FALSE;
	}
	idh = (IMAGE_DOS_HEADER*)conf->bMap;
	inh = (IMAGE_NT_HEADERS *)((BYTE*)conf->bMap + idh->e_lfanew);
	conf->NumberOfSections = inh->FileHeader.NumberOfSections;
	conf->ImageBase = inh->OptionalHeader.ImageBase;
	conf->ish = (IMAGE_SECTION_HEADER*)((BYTE*)inh + sizeof(IMAGE_NT_HEADERS));
	return TRUE;
}

DWORD RVA2Offset(DWORD dwRVA, struct main_teso_conf *conf)
{
	DWORD i;

	for (i = 0; i < conf->NumberOfSections; i++)
	{
		if ((conf->ish[i].VirtualAddress <= dwRVA) && 
			((conf->ish[i].VirtualAddress + conf->ish[i].SizeOfRawData) > dwRVA))
		{
			dwRVA -= conf->ish[i].VirtualAddress;
			dwRVA += conf->ish[i].PointerToRawData;
			return dwRVA;
		}
	}
	return 0;
}

VOID CloseFile(struct main_teso_conf *conf)
{
	if (conf->bMap)
		UnmapViewOfFile(conf->bMap);
	if (conf->hMap)
		CloseHandle(conf->hMap);
	if (conf->hFile)
		CloseHandle(conf->hFile);
}

VOID Write2File(char *FileName, BYTE *data, DWORD dwSize)
{
	HANDLE hFile;
	DWORD dwWritten;

	hFile = CreateFileA(FileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFile failed : %u\n", GetLastError());
		return;
	}
	WriteFile(hFile, data, dwSize, &dwWritten, 0);
	if (dwWritten != dwSize)
	{
		printf("[-] dwWritten != dwSize : %u\n", GetLastError());
	}
	CloseHandle(hFile);
}

/* 

We are looking for this pattern, in fact it's an obfuscated call to 0x1735893 (aes_setkey_dec()) :

- 0x224FF1F : Return address
- 0x1CE9A21 : AES context struct
- 0x2208FE6 : AES key
- 0x80      : Size of the AES Key in bit

.reloc:01646C07 68 80 00 00 00                          push    80h
.reloc:01646C0C 68 E6 8F 20 02                          push    offset byte_2208FE6
.reloc:01646C11 68 21 9A CE 01                          push    offset unk_1CE9A21
.reloc:01646C16 68 1F FF 24 02                          push    offset sub_224FF1F
.reloc:01646C1B 68 93 58 73 01                          push    offset loc_1735893
.reloc:01646C20 C3                                      retn

*/

#define SIZE_PATTERN_KEY 25

VOID Scan4Key(struct main_teso_conf *conf)
{
	DWORD i;
	DWORD dwVAKey;

	for (i = 0; i < conf->dwFileSize - (SIZE_PATTERN_KEY); i++)
	{
		if ((conf->bMap[i] == 0x68) && (*(DWORD*)(conf->bMap + i + 1) == 0x80) && 
			(conf->bMap[i + 5] == 0x68 && conf->bMap[i + 10] == 0x68) &&
			(conf->bMap[i + 15] == 0x68 && conf->bMap[i + 20] == 0x68) &&
			(conf->bMap[i + 25] == 0xC3))
			{
				dwVAKey = *(DWORD*)(conf->bMap + i + 6);
				conf->dwOffsetKey = RVA2Offset(dwVAKey - conf->ImageBase, conf);
				return;
			}
	}
}

/* 

We are looking for this pattern :

struct { DWORD RVA, DWORD Size}

For deciphering all blocks defined by RVA and Size.

.reloc:01736B10 00 10 00 00             dword_1736B10   dd 1000h                ; DATA XREF: sub_1678FA7+3r
.reloc:01736B10                                                                 ; .reloc:0223C319r ...
.reloc:01736B14 02 00 00 00                             dd 2
.reloc:01736B18 00 20 00 00                             dd 2000h

*/

#define SIZE_PATTERN_STRUCT 8

VOID Scan4Struct(struct main_teso_conf *conf)
{
	DWORD i;

	for (i = 0; i < conf->dwFileSize - (SIZE_PATTERN_STRUCT); i++)
	{
		if (*(DWORD*)(conf->bMap + i) == 0x1000 &&
			*(DWORD*)(conf->bMap + i + 4) == 0x02)
		{
			conf->dwOffsetSize = i;
			return;
		}
	}
}

BOOL TestFirstBlock(struct main_teso_conf *conf, char *bAESKey, struct virta_size *va_size)
{
	BYTE bData[16] = {0};
	DWORD dwActualOffset = 0;
	DWORD dwActualSize = 0;
	aes_context aes_ctx;

	while (va_size->dwVA != 0xFFFFFFFF)
	{
		if ((va_size->dwSize + dwActualSize) >= 16)
		{
			dwActualOffset = RVA2Offset(va_size->dwVA, conf);
			memcpy(bData + dwActualSize, conf->bMap + dwActualOffset, 16 - dwActualSize);
			dwActualSize +=  16 - dwActualSize;
			break;
		}
		else
		{
			dwActualOffset = RVA2Offset(va_size->dwVA, conf);
			memcpy(bData + dwActualSize, conf->bMap + dwActualOffset, va_size->dwSize);
			dwActualSize += va_size->dwSize;
		}
		va_size++;
	}
	aes_setkey_dec(&aes_ctx, bAESKey, 0x80);
	aes_crypt_ecb(&aes_ctx, AES_DECRYPT, bData, bData);
	if (bData[0] != 0x90 && bData[1] != 0xC3)
		return FALSE;
	return TRUE;
}

VOID RealAllBlock(struct main_teso_conf *conf, struct virta_size *va_size, struct all_block *ablock)
{
	DWORD dwActualOffset = 0;
	DWORD dwLeftSize = 0;

	while (va_size->dwVA != 0xFFFFFFFF)
	{
		ablock->bData = realloc(ablock->bData, ablock->dwSize + va_size->dwSize);
		if (ablock->bData == NULL)
		{
			printf("[-] realloc failed\n");
			return;
		}
		dwActualOffset = RVA2Offset(va_size->dwVA, conf);
		memcpy(ablock->bData + ablock->dwSize, conf->bMap + dwActualOffset, va_size->dwSize);
		ablock->dwSize += va_size->dwSize;
		va_size++;
	}
	/* 64 padding for sha256 */
	dwLeftSize = 64 - (ablock->dwSize % 64);
	ablock->bData = realloc(ablock->bData, ablock->dwSize + dwLeftSize);
	if (ablock->bData == NULL)
	{
		printf("[-] realloc failed\n");
		return;
	}
	memset(ablock->bData + ablock->dwSize, 0, dwLeftSize);
	ablock->dwSize += dwLeftSize;
}

VOID DeciphAllBlock(struct main_teso_conf *conf, char *bAESKey, struct all_block *ablock)
{
	aes_context aes_ctx;
	DWORD i;

	aes_setkey_dec(&aes_ctx, bAESKey, 0x80);
	for (i = 0; i < ablock->dwSize / 16; i++)
	{
		aes_crypt_ecb(&aes_ctx, AES_DECRYPT, ablock->bData + (i * 16), ablock->bData + (i * 16));
	}
}

VOID WriteBackBlock(struct main_teso_conf *conf, struct virta_size *va_size, struct all_block *ablock)
{
	BYTE *bResult = NULL;
	DWORD dwActualOffset = 0;
	BYTE *bData = NULL;

	bResult = malloc(sizeof (char) * conf->dwFileSize);
	if (bResult == NULL)
	{
		printf("[-] malloc failed\n");
		return;
	}
	memcpy(bResult, conf->bMap, conf->dwFileSize);
	bData = ablock->bData;
	while (va_size->dwVA != 0xFFFFFFFF)
	{
		dwActualOffset = RVA2Offset(va_size->dwVA, conf);
		memcpy(bResult + dwActualOffset, bData, va_size->dwSize);
		bData += va_size->dwSize;
		va_size++;
	}
	Write2File("result.exe", bResult, conf->dwFileSize);
	free(bResult);
}

int main(int argc, char *argv[])
{
	struct main_teso_conf conf = {0};
	char bAESKey[16] = {0};
	struct virta_size *va_size = NULL;
	struct all_block ablock = {0};

	if (argc != 2)
	{
		printf("Usage : %s <eso_binary>\n", argv[0]);
		return 1;
	}
	if (LoadFile(argv[1], &conf) == FALSE)
	{
		goto end;
	}
	Scan4Key(&conf);
	if (conf.dwOffsetKey == 0)
	{
		printf("[-] Can't find offset of the AES key\n");
		goto end;
	}
	memcpy(bAESKey, conf.bMap + conf.dwOffsetKey, 16);
	printf("[+] AES key :\n");
	hex_dump(bAESKey, 16);
	Scan4Struct(&conf);
	if (conf.dwOffsetSize == 0)
	{
		printf("[-] Can't find offset of struct offset/size\n");
		goto end;
	}
	va_size = (struct virta_size*)(conf.bMap + conf.dwOffsetSize);
	if (TestFirstBlock(&conf, bAESKey, va_size) == FALSE)
	{
		printf("[-] First block was not well deciphered\n");
		goto end;
	}
	printf("[+] First block is OK, the AES key should be ok\n");
	RealAllBlock(&conf, va_size, &ablock);
	if (ablock.bData == NULL)
	{
		goto end;
	}
	DeciphAllBlock(&conf, bAESKey, &ablock);
	WriteBackBlock(&conf, va_size, &ablock);
end:
	if (ablock.bData != NULL)
	{
		free(ablock.bData);
	}
	CloseFile(&conf);
	return 0;
}