#include "mnf.h"

void hex_dump(void *data, size_t size)
{
	unsigned char *p =(unsigned char*)data;
    unsigned char c;
    size_t n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};

    for(n = 1; n <= size; n++)
	{
        if (n % 16 == 1)
		{
            sprintf(addrstr, "%.4x",
               ((unsigned int)p-(unsigned int)data));
        }
        c = *p;
        if (isalnum(c) == 0)
		{
            c = '.';
        }
        sprintf(bytestr, "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        sprintf(bytestr, "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if (n % 16 == 0)
		{
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
		else if (n % 8 == 0)
		{
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++;
    }

    if (strlen(hexstr) > 0)
	{
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

void PrintMNFHeader(struct mnf_header *head)
{
	printf("Magic        = 0x%08X\n", head->Magic);
	printf("NS_Version   = 0x%04X\n", head->NS_Version);
	printf("Nb_dat_files = 0x%02X\n", head->Nb_dat_files);
	printf("unk_1        = 0x%08X\n", head->unk_1);
	printf("TotalSize    = 0x%08X\n", head->TotalSize);
}

BOOL ReadMNF(HANDLE h)
{
	struct mnf_header MNFh;
	DWORD dwRead;
	BYTE unk[0xA];
	DWORD dwFileCount_1;
	DWORD dwFileCount_2;
	
	memset(&MNFh, 0, MNF_HEADER_SIZE);

	ReadFile(h, &MNFh, MNF_HEADER_SIZE, &dwRead, 0);
	
	if (MNFh.Magic != MNF_SIG)
	{
		printf("[-] Wrong magic number : %08X\n", MNFh.Magic);
		return FALSE;
	}
	PrintMNFHeader(&MNFh);
	ReadFile(h, &unk, 0xA, &dwRead, 0);
	hex_dump(unk, 0xA);
	
	/* BIG ENDIAN START */
	ReadFile(h, &dwFileCount_1, 0x4, &dwRead, 0);
	dwFileCount_1 = swap_uint32(dwFileCount_1);
	ReadFile(h, &dwFileCount_2, 0x4, &dwRead, 0);
	dwFileCount_2 = swap_uint32(dwFileCount_2);
	printf("dwFileCount_1 = 0x%08X (%d)\n", dwFileCount_1, dwFileCount_1);
	printf("dwFileCount_2 = 0x%08X (%d)\n", dwFileCount_2, dwFileCount_2);
	UncompData(h);
	return TRUE;
}