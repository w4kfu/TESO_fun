#ifndef _BUFFER_H
#define _BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "zlib.h"

#define windowBits 15
#define ENABLE_ZLIB_GZIP 32

#define SIZE_COMP_BUF sizeof (struct comp_buf)

struct comp_buf
{
    unsigned int uncomp_size;
    unsigned int comp_size;
    unsigned char *buf_comp;
	unsigned char *buf_uncomp;
};

unsigned int swap_uint32(unsigned int val);
struct comp_buf *UncompData(HANDLE h);

#endif