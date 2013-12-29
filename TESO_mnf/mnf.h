#ifndef _MNF_H
#define _MNF_H

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "buffer.h"

# define MNF_SIG	0x3253454D

# define TYPE_WAVE	0x46464952
# define TYPE_DDS	1
# define TYPE_ZOS	2
# define TYPE_BKHD	0x44484B42

# define MNF_HEADER_SIZE sizeof (struct mnf_header)

#pragma pack(push,1)
struct mnf_header
{
    unsigned int Magic;
    unsigned short NS_Version;
    unsigned char Nb_dat_files;
    unsigned int unk_1;
    unsigned int TotalSize;
};
#pragma pack(pop)

#pragma pack(push,1)
struct entry_table3
{
	unsigned int UncompSize;
	unsigned int CompSize;
	unsigned int unk_0;
	unsigned int Offset;
	unsigned char Type;
	unsigned char ArchiveNum;
	unsigned short unk_1;
};
#pragma pack(pop)

BOOL ReadMNF(HANDLE h, char *FileName);
char *TypeFile(DWORD dwType);
void ExtractFile(char *BaseName, struct entry_table3 *entry);

#endif