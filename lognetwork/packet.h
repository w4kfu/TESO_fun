#ifndef PACKET_H_
#define PACKET_H_

#define WIN32_LEAN_AND_MEAN

#include "dbg.h"
#include "scanmem.h"
#include "zlib.h"
#include "hookstuff.h"

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

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/nbtheory.h"
using CryptoPP::ModularExponentiation;

#include "cryptopp/dh.h"
using CryptoPP::DH;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/dh2.h"
using CryptoPP::DH2;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

#include "cryptopp/modes.h"
using CryptoPP::CTR_Mode;

VOID ParsePacketServ(struct SockMonitor *smon, BYTE *bData, DWORD dwSize); // RECV

VOID ParsePacketClient(struct SockMonitor *smon, BYTE *bData, DWORD dwSize); // SEND

#endif // PACKET_H_