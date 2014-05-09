#ifndef _DBG_H
#define _DBG_H

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define FILE_DBG "dbg_msg.txt"

void dbg_msg(char *format, ...);
void hexdump(void *data, int size);

#endif