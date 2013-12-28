#include "buffer.h"

unsigned int swap_uint32(unsigned int val)
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

void Uncomp(unsigned char *buf_src, size_t len_src, unsigned char *buf_dst, size_t len_dst)
{
    z_stream strm = {0};

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = buf_src;
    strm.avail_in = 0;
    strm.next_out = buf_dst;
    if (inflateInit2(&strm, windowBits | ENABLE_ZLIB_GZIP) < 0)
    {
        printf("[-] inflateInit2 failed\n", 0);
        exit(EXIT_FAILURE);
    }
    strm.avail_in = len_src;
	strm.avail_out = len_dst;
	if (inflate(&strm, Z_NO_FLUSH) != Z_STREAM_END)
	{
		printf("[-] inflate() failed\n");
		exit(EXIT_FAILURE);
	}
    strm.next_out = buf_dst;
	inflateEnd(&strm);
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
	ReadFile(h, &ncomp->uncomp_size, 0x4, &dwRead, 0);
	ncomp->uncomp_size = swap_uint32(ncomp->uncomp_size);
	ReadFile(h, &ncomp->comp_size, 0x4, &dwRead, 0);
	ncomp->comp_size = swap_uint32(ncomp->comp_size);	
	printf("[+] CompSize = 0x%08X (%d)\n", ncomp->comp_size, ncomp->comp_size);
	printf("[+] UncompSize = 0x%08X (%d)\n", ncomp->uncomp_size, ncomp->uncomp_size);
	ncomp->buf_comp = malloc(ncomp->comp_size * sizeof (char));
	if (ncomp->buf_comp == NULL)
	{
		printf("[-] malloc failed\n");
		free(ncomp);
		return NULL;
	}
	ReadFile(h, ncomp->buf_comp, ncomp->comp_size, &dwRead, 0);
	ncomp->buf_uncomp  = malloc(ncomp->uncomp_size * sizeof (char));
	if (ncomp->buf_uncomp == NULL)
	{
		printf("[-] malloc failed\n");
		free(ncomp->buf_comp);
		free(ncomp);
		return NULL;
	}
	Uncomp(ncomp->buf_comp, ncomp->comp_size, ncomp->buf_uncomp, ncomp->uncomp_size);
	return ncomp;
}