#ifndef PACKET_H_
#define PACKET_H_

#include "dbg.h"
#include "scanmem.h"
#include "zlib.h"
#include "cryptopp/dll.h"

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

VOID ParsePacketServ(BYTE *bData, DWORD dwSize);	// RECV

VOID ParsePacketHeader(BYTE *bData, DWORD dwSize);	// SEND

#endif // PACKET_H_