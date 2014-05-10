#ifndef PACKET_H_
#define PACKET_H_

#include "dbg.h"
#include "scanmem.h"
#include "zlib.h"

struct PacketBuf
{
	DWORD dwSize;
	BYTE *bData;
};

struct TESO_Buffer
{
	WORD	size;
	BYTE	*bData;
};

struct ZLIB_Buffer
{
	DWORD	uncomp_size;
	DWORD	comp_size;
	BYTE	*bData;
	BYTE	*bUData;
};

VOID ParsePacketHeader(BYTE *bData, DWORD dwSize);

#endif // PACKET_H_