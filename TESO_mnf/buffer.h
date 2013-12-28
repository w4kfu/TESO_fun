#ifndef _BUFFER_H
#define _BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define SIZE_COMP_BUF sizeof (struct comp_buf)

struct comp_buf
{
    unsigned int size;
    unsigned int uncomp_size;
    unsigned char *buf_comp;
};

unsigned int swap_uint32(unsigned int val);
struct comp_buf *UncompData(HANDLE h);

#endif