#include "mnf.h"

void DumpFiles(unsigned char *buf, size_t size, char *name)
{
	FILE *fp;
	
	fp = fopen(name, "w");
	if (!fp)
	{
		printf("[-] DumpFiles\n");
		return;
	}
	fwrite(buf, 1, size, fp);
	fclose(fp);
}

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

void ExtractTable3(DWORD dwFileCount_1, struct comp_buf *block_2, struct comp_buf *block_3)
{
	struct entry_table3 entry;
	DWORD dwFileNum;
	DWORD dwUnk;
	unsigned char *pB2;
	unsigned char *pB3;
	DWORD i;
	
	pB2 = block_2->buf_uncomp;
	pB3 = block_3->buf_uncomp;
	for (i = 0; i < dwFileCount_1; i++)
	{
		dwFileNum = *(DWORD*)pB2;
		pB2 += 4;
		dwUnk = *(DWORD*)pB2;
		pB2 += 4;
		memcpy(&entry, pB3, sizeof (struct entry_table3));
		pB3 += sizeof (struct entry_table3);
		//printf("[+] dwFileNum = %08X (%d)\n", dwFileNum, dwFileNum);
		//printf("[+] dwUnk = %08X (%d)\n", dwUnk, dwUnk);	
		ListViewAddItems(&entry);
		//if (i > 5)
			//break;
	}
}

BOOL ReadMNF(HANDLE h)
{
	struct mnf_header MNFh;
	DWORD dwRead;
	BYTE unk[0xA];
	DWORD dwFileCount_1;
	DWORD dwFileCount_2;
	struct comp_buf *block_1 = NULL;
	struct comp_buf *block_2 = NULL;
	struct comp_buf *block_3 = NULL;
	
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
	block_1 = UncompData(h);
	DumpFiles(block_1->buf_uncomp, block_1->uncomp_size, "table1.bin");
	block_2 = UncompData(h);
	DumpFiles(block_2->buf_uncomp, block_2->uncomp_size, "table2.bin");
	block_3 = UncompData(h);
	DumpFiles(block_3->buf_uncomp, block_3->uncomp_size, "table3.bin");
	ExtractTable3(dwFileCount_1, block_2, block_3);
	return TRUE;
}