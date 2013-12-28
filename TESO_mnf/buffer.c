#include "buffer.h"

unsigned int swap_uint32(unsigned int val)
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

struct comp_buf *UncompData(HANDLE h)
{
	struct comp_buf* ncomp = NULL;
	DWORD dwRead;
	
	ncomp = malloc(SIZE_COMP_BUF);
	if (ncomp == NULL)
	{
		printf("[-] malloc failed\n");
		return ncomp;
	}
	ReadFile(h, &ncomp->size, 0x4, &dwRead, 0);
	ncomp->size = swap_uint32(ncomp->size);	
	ReadFile(h, &ncomp->uncomp_size, 0x4, &dwRead, 0);
	ncomp->uncomp_size = swap_uint32(ncomp->uncomp_size);
	printf("[+] Size = 0x%08X (%d)\n", ncomp->size, ncomp->size);
	printf("[+] UncompSize = 0x%08X (%d)\n", ncomp->uncomp_size, ncomp->uncomp_size);
	return ncomp;
}