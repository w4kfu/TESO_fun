#include "mnf.h"

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
	
	memset(&MNFh, 0, MNF_HEADER_SIZE);

	ReadFile(h, &MNFh, MNF_HEADER_SIZE, &dwRead, 0);
	
	if (MNFh.Magic != MNF_SIG)
	{
		printf("[-] Wrong magic number : %08X\n", MNFh.Magic);
		return FALSE;
	}
	PrintMNFHeader(&MNFh);
	return TRUE;
}