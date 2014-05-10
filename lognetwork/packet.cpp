#include "packet.h"

BOOL GetByte(struct PacketBuf *packet, BYTE *value)
{
	if (packet->dwSize < 1)
	{
		dbg_msg("[-] GetByte - dwSize < 1\n");
		return FALSE;
	}
	*value = *(packet->bData);
	packet->bData += 1;
	packet->dwSize -= 1;
	return TRUE;
}

BOOL GetWord(struct PacketBuf *packet, WORD *value)
{
	if (packet->dwSize < 2)
	{
		dbg_msg("[-] GetWord - packet->dwSize < 2\n");
		return FALSE;
	}
	*value = *(packet->bData) << 8;
	packet->bData += 1;
	packet->dwSize -= 1;
	*value += *(packet->bData);
	packet->bData += 1;
	packet->dwSize -= 1;	
	return TRUE;
}

BOOL GetDword(struct PacketBuf *packet, DWORD *value)
{
	if (packet->dwSize < 4)
	{
		dbg_msg("[-] GetDword - packet->dwSize < 4\n");
		return FALSE;
	}
	*value = *(packet->bData) << 24;
	packet->bData += 1;
	packet->dwSize -= 1;
	*value += *(packet->bData) << 16;
	packet->bData += 1;
	packet->dwSize -= 1;
	*value += *(packet->bData) << 8;
	packet->bData += 1;
	packet->dwSize -= 1;	
	*value += *(packet->bData);
	packet->bData += 1;
	packet->dwSize -= 1;	
	return TRUE;
}

BOOL GetBuffer(struct PacketBuf *packet, struct TESO_Buffer *value)
{
	if (GetWord(packet, &value->size) == FALSE)
		return FALSE;
	if (packet->dwSize < value->size)
	{
		dbg_msg("[-] GetBuffer - packet->dwSize < value->size\n");
		return FALSE;		
	}
	value->bData = packet->bData;
	packet->bData += value->size + 1;
	packet->dwSize -= value->size + 1;
	return TRUE;
}

BOOL GetZlibBuffer(struct PacketBuf *packet, struct ZLIB_Buffer *value)
{
	if (GetDword(packet, &value->uncomp_size) == FALSE)
		return FALSE;
	if (GetDword(packet, &value->comp_size) == FALSE)
		return FALSE;
	if (packet->dwSize < value->comp_size)
	{
		dbg_msg("[-] GetZlibBuffer - packet->dwSize < value->comp_size\n");
		return FALSE;		
	}
	value->bData = packet->bData;
	packet->bData += value->comp_size;
	packet->dwSize -= value->comp_size;
	return TRUE;
}

VOID ManageCrypto(VOID)
{
	SuspendAllThreads(TRUE);

	Scan4Key();
	//Sleep(4000);

	SuspendAllThreads(FALSE);
}

VOID Handle_0x2B10(struct PacketBuf *p)
{
	struct TESO_Buffer token = {0};
	struct TESO_Buffer version = {0};
	DWORD unk_dword_00 = 0;
	struct ZLIB_Buffer zlib_00 = {0};
	DWORD unk_dword_01 = 0;
	DWORD unk_dword_02 = 0;
	DWORD unk_dword_03 = 0;
	struct ZLIB_Buffer zlib_01 = {0};
	struct ZLIB_Buffer zlib_02 = {0};
	struct ZLIB_Buffer zlib_03 = {0};
	struct ZLIB_Buffer zlib_04 = {0};
	DWORD unk_dword_04 = 0;
	BYTE unk_byte_00 = 0;
	struct TESO_Buffer language = {0};

	if (GetBuffer(p, &token) == FALSE)
		return;
	dbg_msg("\t[+] token = %s\n", token.bData);
	if (GetBuffer(p, &version) == FALSE)
		return;
	dbg_msg("\t[+] version = %s\n", version.bData);
	if (GetDword(p, &unk_dword_00) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_00 = %08X\n", unk_dword_00);
	if (GetZlibBuffer(p, &zlib_00) == FALSE)
		return;
	hexdump(zlib_00.bData, zlib_00.comp_size);
	if (GetDword(p, &unk_dword_01) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_01 = %08X\n", unk_dword_01);
	if (GetDword(p, &unk_dword_02) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_02 = %08X\n", unk_dword_02);
	if (GetDword(p, &unk_dword_03) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_03 = %08X\n", unk_dword_03);
	if (GetZlibBuffer(p, &zlib_01) == FALSE)
		return;
	hexdump(zlib_01.bData, zlib_01.comp_size);
	if (GetZlibBuffer(p, &zlib_02) == FALSE)
		return;
	hexdump(zlib_02.bData, zlib_02.comp_size);
	if (GetZlibBuffer(p, &zlib_03) == FALSE)
		return;
	hexdump(zlib_03.bData, zlib_03.comp_size);
	if (GetZlibBuffer(p, &zlib_04) == FALSE)
		return;
	hexdump(zlib_04.bData, zlib_04.comp_size);
	if (GetDword(p, &unk_dword_04) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_04 = %08X\n", unk_dword_04);
	if (GetByte(p, &unk_byte_00) == FALSE)
		return;
	dbg_msg("\t[+] unk_byte_00 = %08X\n", unk_byte_00);
	if (GetBuffer(p, &language) == FALSE)
		return;
	dbg_msg("\t[+] language = %s\n", language.bData);
	ManageCrypto();
}

VOID HandleOpcode(WORD Opcode, struct PacketBuf *p)
{
	switch (Opcode)
	{
		case 0x2B10:
			Handle_0x2B10(p);
			break;
		default:
			dbg_msg("[-] Unknow opcode : %04X\n", Opcode);
	}
}

VOID ParsePacketHeader(BYTE *bData, DWORD dwSize)
{
	struct PacketBuf pHeader = {0};
	struct PacketBuf p = {0};
	DWORD dwPacketSize = 0;
	WORD NS_version = 0;
	WORD NS_streamID = 0;
	DWORD dwDataSize = 0;
	WORD Opcode = 0;

	if (dwSize == 1)
	{
		return;
	}
	pHeader.dwSize = dwSize;
	pHeader.bData = bData;
	GetDword(&pHeader, &dwPacketSize);
	//pHeader.dwSize = dwPacketSize;
	if (GetWord(&pHeader, &NS_version) == FALSE)
		return;
	if (GetWord(&pHeader, &NS_streamID) == FALSE)
		return;
	if (GetDword(&pHeader, &dwDataSize) == FALSE)
		return;
	if (GetWord(&pHeader, &Opcode) == FALSE)
		return;
	dbg_msg("[+] NS_version = %04X\n", NS_version);
	dbg_msg("[+] NS_streamID = %04X\n", NS_streamID);
	dbg_msg("[+] Size = %08X\n", dwDataSize);
	dbg_msg("[+] Opcode = %04X\n", Opcode);
	p.dwSize = pHeader.dwSize;
	p.bData = pHeader.bData;
	HandleOpcode(Opcode, &p);
	if (p.dwSize != 0)
		dbg_msg("[+] Data left = %d\n", p.dwSize);
}

