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

BOOL UncompZlibBuffer(struct ZLIB_Buffer *zlib)
{
	zlib->bUData = (BYTE*)malloc(sizeof (char) * zlib->uncomp_size);
	if (zlib->bUData == NULL)
		return FALSE;
	if (uncompress(zlib->bUData, &zlib->uncomp_size, zlib->bData, zlib->comp_size) != Z_OK)
	{
		dbg_msg("[-] UncompZlibBuffer - uncompress failed\n");
		return FALSE;
	}
	hexdump(zlib->bUData, zlib->uncomp_size);
	return TRUE;
}

VOID CleanZlibBuffer(struct ZLIB_Buffer *zlib)
{
	if (zlib->bUData != NULL)
		free(zlib->bUData);
}

VOID GetPrivateKey(struct SockMonitor *smon)
{
	SuspendAllThreads(TRUE);
	if (Scan4Key(smon->PrivateKeyClient_01, smon->PrivateKeyClient_02, smon->PrivateKeyClient_03, smon->PrivateKeyClient_04) == FALSE)
	{
		dbg_msg("[+] Relaunch scan ...\n");
		if (Scan4Key(smon->PrivateKeyClient_01, smon->PrivateKeyClient_02, smon->PrivateKeyClient_03, smon->PrivateKeyClient_04) == FALSE)
		{
			dbg_msg("[+] Failed to find private key\n");
			ExitProcess(0);
		}
	}
	//Sleep(4000);
	SuspendAllThreads(FALSE);
	smon->PrivKeySet = TRUE;
}

VOID GenAESKey(struct SockMonitor *smon, BYTE *key_01_pub_server, BYTE *key_04_pub_server, BYTE *IV)
{
	byte TESO_pub[128] = {
		0xA1, 0x33, 0x42, 0xC0, 0xC1, 0x6E, 0x7D, 0x3B, 0x5E, 0x01, 0xC4, 0xE8,
		0x84, 0xB5, 0x13, 0x4F, 0xAD, 0x32, 0x48, 0x44, 0x59, 0xEB, 0xD1, 0x91,
		0xBC, 0x28, 0x40, 0x21, 0x18, 0x7E, 0xDE, 0x9C, 0x79, 0x60, 0xF3, 0x3C,
		0xFA, 0xDD, 0x89, 0xA0, 0x70, 0x09, 0x01, 0xC2, 0x46, 0x2A, 0xB2, 0xD5,
		0x87, 0xEC, 0xC3, 0xBF, 0xFE, 0x6A, 0x87, 0xBE, 0x4E, 0x74, 0xCF, 0x07,
		0x1D, 0x23, 0x08, 0x2C, 0x27, 0xE2, 0x89, 0xDB, 0x62, 0xDF, 0x61, 0xE9,
		0x79, 0x48, 0x98, 0xCC, 0x94, 0x0B, 0x53, 0x03, 0x14, 0x40, 0x2C, 0x65,
		0x73, 0xE4, 0x8D, 0x02, 0x40, 0x18, 0xD6, 0x6F, 0x23, 0x52, 0x65, 0x89,
		0xB7, 0x8F, 0xE2, 0x14, 0x6E, 0x45, 0xAF, 0x14, 0x36, 0x24, 0x76, 0x2E,
		0x72, 0xAD, 0x59, 0x28, 0x46, 0x18, 0x69, 0x77, 0x77, 0x08, 0x7E, 0xE6,
		0x8B, 0xA2, 0xA7, 0x56, 0x20, 0x68, 0x28, 0xD8
	};

	DH dh;		
	AutoSeededRandomPool rnd;
	Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
			"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
			"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
			"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
			"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
			"DF1FB2BC2E4A4371");
	Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
			"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
			"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
			"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
			"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
			"855E6EEB22B3B2E5");
	Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");
	dh.AccessGroupParameters().Initialize(p, q, g);
	DH2 dhA(dh);

	SecByteBlock sharedA(dhA.AgreedValueLength());
	SecByteBlock sharedB(dhA.AgreedValueLength());

	if(!dhA.Agree(sharedA, smon->PrivateKeyClient_01, smon->PrivateKeyClient_02, TESO_pub, key_01_pub_server))
	{
		printf("[-] dhA.Agree failed\n");
	}

	if(!dhA.Agree(sharedB, smon->PrivateKeyClient_01, smon->PrivateKeyClient_03, TESO_pub, key_04_pub_server))
	{
		printf("[-] dhA.Agree failed\n");
	}

	int aesKeyLength = SHA256::DIGESTSIZE;
	int defBlockSize = AES::BLOCKSIZE;

	SecByteBlock key(SHA256::DIGESTSIZE);
	SHA256().CalculateDigest(key, sharedB, sharedB.size()); 
	smon->d_recv.SetKeyWithIV(key, aesKeyLength, IV);	

	SecByteBlock key2(SHA256::DIGESTSIZE);
	SHA256().CalculateDigest(key2, sharedA, sharedA.size()); 
	smon->d_send.SetKeyWithIV(key2, aesKeyLength, IV);
	smon->KeySet = TRUE;
}

VOID Handle_0x2B10(struct SockMonitor *smon, struct PacketBuf *p)
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
	//hexdump(zlib_00.bData, zlib_00.comp_size);
	printf("[+] Key_pub_04\n");
	UncompZlibBuffer(&zlib_00);
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
	//hexdump(zlib_01.bData, zlib_01.comp_size);
	printf("[+] Key_pub_03\n");
	UncompZlibBuffer(&zlib_01);
	if (GetZlibBuffer(p, &zlib_02) == FALSE)
		return;
	//hexdump(zlib_02.bData, zlib_02.comp_size);
	printf("[+] Key_pub_01\n");
	UncompZlibBuffer(&zlib_02);
	if (GetZlibBuffer(p, &zlib_03) == FALSE)
		return;
	//hexdump(zlib_03.bData, zlib_03.comp_size);
	UncompZlibBuffer(&zlib_03);
	printf("[+] Key_pub_02\n");
	if (GetZlibBuffer(p, &zlib_04) == FALSE)
		return;
	//hexdump(zlib_04.bData, zlib_04.comp_size);
	UncompZlibBuffer(&zlib_04);
	printf("[+] Key_pub_05\n");
	if (GetDword(p, &unk_dword_04) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_04 = %08X\n", unk_dword_04);
	if (GetByte(p, &unk_byte_00) == FALSE)
		return;
	dbg_msg("\t[+] unk_byte_00 = %02X\n", unk_byte_00);
	if (GetBuffer(p, &language) == FALSE)
		return;
	dbg_msg("\t[+] language = %s\n", language.bData);
	GetPrivateKey(smon);
	CleanZlibBuffer(&zlib_00);
	CleanZlibBuffer(&zlib_01);
	CleanZlibBuffer(&zlib_02);
	CleanZlibBuffer(&zlib_03);
	CleanZlibBuffer(&zlib_04);
}

VOID Handle_0x2B0A(struct SockMonitor *smon, struct PacketBuf *p)
{
	BYTE unk_byte_00 = 0;

	if (GetByte(p, &unk_byte_00) == FALSE)
		return;
	dbg_msg("\t[+] unk_byte_00 = %08X\n", unk_byte_00);
	if (smon->KeySet != TRUE || smon->PrivKeySet != TRUE)
	{
		dbg_msg("Setting encryption to TRUE without key\n");
		ExitProcess(0);
	}
	smon->encrypted = TRUE;
}

VOID Handle_0x2B08(struct SockMonitor *smon, struct PacketBuf *p)
{
	BYTE unk_byte_00 = 0;

	struct ZLIB_Buffer zlib_00 = {0};
	struct ZLIB_Buffer zlib_01 = {0};
	struct ZLIB_Buffer zlib_02 = {0};
	struct ZLIB_Buffer zlib_03 = {0};
	struct ZLIB_Buffer zlib_04 = {0};

	if (GetByte(p, &unk_byte_00) == FALSE)
		return;
	dbg_msg("\t[+] unk_byte_00 = %08X\n", unk_byte_00);	
	if (GetZlibBuffer(p, &zlib_00) == FALSE)
		return;
	UncompZlibBuffer(&zlib_00);
	if (GetZlibBuffer(p, &zlib_01) == FALSE)
		return;
	UncompZlibBuffer(&zlib_01);
	if (GetZlibBuffer(p, &zlib_02) == FALSE)
		return;
	UncompZlibBuffer(&zlib_02);
	if (GetZlibBuffer(p, &zlib_03) == FALSE)
		return;
	UncompZlibBuffer(&zlib_03);
	if (GetZlibBuffer(p, &zlib_04) == FALSE)
		return;
	UncompZlibBuffer(&zlib_04);
	GenAESKey(smon, zlib_00.bUData, zlib_04.bUData, zlib_02.bUData);
	UncompZlibBuffer(&zlib_04);
	CleanZlibBuffer(&zlib_00);
	CleanZlibBuffer(&zlib_01);
	CleanZlibBuffer(&zlib_02);
	CleanZlibBuffer(&zlib_03);
	CleanZlibBuffer(&zlib_04);
}


VOID Handle_0x0110(struct SockMonitor *smon, struct PacketBuf *p)
{
	struct TESO_Buffer username = {0};
	struct TESO_Buffer language = {0};
	DWORD unk_dword_00 = 0;
	struct ZLIB_Buffer zlib_00 = {0};
	BYTE unk_byte_00 = 0;
	DWORD unk_dword_01 = 0;
	DWORD unk_dword_02 = 0;
	struct ZLIB_Buffer zlib_01 = {0};
	struct ZLIB_Buffer zlib_02 = {0};
	struct ZLIB_Buffer zlib_03 = {0};
	struct ZLIB_Buffer zlib_04 = {0};
	DWORD unk_dword_03 = 0;
	struct TESO_Buffer version = {0};
	struct TESO_Buffer uuid = {0};

	if (GetBuffer(p, &username) == FALSE)
		return;
	dbg_msg("\t[+] username = %s\n", username.bData);
	if (GetBuffer(p, &language) == FALSE)
		return;
	dbg_msg("\t[+] language = %s\n", language.bData);
	if (GetDword(p, &unk_dword_00) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_00 = %08X\n", unk_dword_00);
	if (GetZlibBuffer(p, &zlib_00) == FALSE)
		return;
	UncompZlibBuffer(&zlib_00);
	if (GetByte(p, &unk_byte_00) == FALSE)
		return;
	dbg_msg("\t[+] unk_byte_00 = %08X\n", unk_byte_00);	
	if (GetDword(p, &unk_dword_01) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_01 = %08X\n", unk_dword_01);
	if (GetDword(p, &unk_dword_02) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_02 = %08X\n", unk_dword_02);
	if (GetZlibBuffer(p, &zlib_01) == FALSE)
		return;
	UncompZlibBuffer(&zlib_01);
	if (GetZlibBuffer(p, &zlib_02) == FALSE)
		return;
	UncompZlibBuffer(&zlib_02);
	if (GetZlibBuffer(p, &zlib_03) == FALSE)
		return;
	UncompZlibBuffer(&zlib_03);
	if (GetZlibBuffer(p, &zlib_04) == FALSE)
		return;
	UncompZlibBuffer(&zlib_04);
	if (GetDword(p, &unk_dword_03) == FALSE)
		return;
	dbg_msg("\t[+] unk_dword_03 = %08X\n", unk_dword_03);
	if (GetBuffer(p, &version) == FALSE)
		return;
	dbg_msg("\t[+] version = %s\n", version.bData);
	if (GetBuffer(p, &uuid) == FALSE)
		return;
	dbg_msg("\t[+] uuid = %s\n", uuid.bData);
	GetPrivateKey(smon);
	CleanZlibBuffer(&zlib_00);
	CleanZlibBuffer(&zlib_01);
	CleanZlibBuffer(&zlib_02);
	CleanZlibBuffer(&zlib_03);
	CleanZlibBuffer(&zlib_04);
}

VOID Handle_0x010B(struct SockMonitor *smon, struct PacketBuf *p)
{
	BYTE unk_byte_00 = 0;
	struct ZLIB_Buffer zlib_00 = {0};
	struct ZLIB_Buffer zlib_01 = {0};
	struct ZLIB_Buffer zlib_02 = {0};
	struct ZLIB_Buffer zlib_03 = {0};
	struct ZLIB_Buffer zlib_04 = {0};

	if (GetByte(p, &unk_byte_00) == FALSE)
		return;
	dbg_msg("\t[+] unk_byte_00 = %08X\n", unk_byte_00);	
	if (GetZlibBuffer(p, &zlib_00) == FALSE)
		return;
	UncompZlibBuffer(&zlib_00);
	if (GetZlibBuffer(p, &zlib_01) == FALSE)
		return;
	UncompZlibBuffer(&zlib_01);
	if (GetZlibBuffer(p, &zlib_02) == FALSE)	// IV ?
		return;
	UncompZlibBuffer(&zlib_02);
	if (GetZlibBuffer(p, &zlib_03) == FALSE)
		return;
	UncompZlibBuffer(&zlib_03);
	if (GetZlibBuffer(p, &zlib_04) == FALSE)
		return;
	UncompZlibBuffer(&zlib_04);
	GenAESKey(smon, zlib_00.bUData, zlib_04.bUData, zlib_02.bUData);
	CleanZlibBuffer(&zlib_00);
	CleanZlibBuffer(&zlib_01);
	CleanZlibBuffer(&zlib_02);
	CleanZlibBuffer(&zlib_03);
	CleanZlibBuffer(&zlib_04);
}

VOID Handle_0x010A(struct SockMonitor *smon, struct PacketBuf *p)
{
	BYTE unk_byte_00 = 0;

	if (GetByte(p, &unk_byte_00) == FALSE)
		return;
	dbg_msg("\t[+] unk_byte_00 = %08X\n", unk_byte_00);
	if (smon->KeySet != TRUE || smon->PrivKeySet != TRUE)
	{
		dbg_msg("Setting encryption to TRUE without key\n");
		ExitProcess(0);
	}
	smon->encrypted = TRUE;
}

VOID HandleOpcode(struct SockMonitor *smon, WORD Opcode, struct PacketBuf *p)
{
	switch (Opcode)
	{
		case 0x010A:
			Handle_0x010A(smon, p);
			break;
		case 0x010B:
			Handle_0x010B(smon, p);
			break;
		case 0x0110:
			Handle_0x0110(smon, p);
			break;			
		case 0x2B08:
			Handle_0x2B08(smon, p);
			break;
		case 0x2B0A:
			Handle_0x2B0A(smon, p);
			break;
		case 0x2B10:
			Handle_0x2B10(smon, p);
			break;
		default:
			dbg_msg("[-] Unknow opcode : %04X\n", Opcode);
	}
}

VOID ParsePacketServ(struct SockMonitor *smon, BYTE *bData, DWORD dwSize)
{
	struct PacketBuf p = {0};
	WORD Opcode = 0;
	BYTE *bDecData = NULL;
	DWORD dwDataSize = 0;

	if (dwSize <= 4)
		return;
	if (smon->encrypted == TRUE)
	{
		bDecData = (BYTE*)malloc(sizeof (char) * dwSize);
		if (bDecData == NULL)
		{
			dbg_msg("[-] ParsePacketServ - malloc failed\n");
			return;
		}
		smon->d_recv.ProcessData((byte*)bDecData, (byte*)(bData + 1), dwSize - 1);
		dbg_msg("[+] Decrypted :\n");
		hexdump(bDecData, dwSize - 1);
		p.bData = bDecData;
		p.dwSize = dwSize - 1;
		GetDword(&p, &dwDataSize);
	}
	else
	{
		p.dwSize = dwSize;
		p.bData = bData;		
	}
	if (GetWord(&p, &Opcode) == FALSE)
		return;
	dbg_msg("[+] Opcode = %04X\n", Opcode);
	HandleOpcode(smon, Opcode, &p);
	if (bDecData != NULL)
		free(bDecData);
}

VOID ParsePacketClient(struct SockMonitor *smon, BYTE *bData, DWORD dwSize)
{
	struct PacketBuf pHeader = {0};
	struct PacketBuf p = {0};
	DWORD dwPacketSize = 0;
	WORD NS_version = 0;
	WORD NS_streamID = 0;
	DWORD dwDataSize = 0;
	WORD Opcode = 0;
	BYTE *bDecData = NULL;

	if (dwSize == 1)
	{
		return;
	}
	pHeader.dwSize = dwSize;
	pHeader.bData = bData;
	GetDword(&pHeader, &dwPacketSize);
	if (smon->encrypted == TRUE)
	{
		bDecData = (BYTE*)malloc(sizeof (char) * dwPacketSize);
		if (bDecData == NULL)
		{
			dbg_msg("[-] ParsePacketClient - malloc failed\n");
			return;
		}
		smon->d_send.ProcessData((byte*)bDecData, (byte*)(pHeader.bData + 1), dwPacketSize - 1);
		dbg_msg("[+] Decrypted :\n");
		hexdump(bDecData, dwPacketSize - 1);
		pHeader.bData = bDecData;
		pHeader.dwSize = dwPacketSize - 1;
		GetDword(&pHeader, &dwDataSize);
	}
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
	HandleOpcode(smon, Opcode, &p);
	if (p.dwSize != 0)
		dbg_msg("[+] Data left = %d\n", p.dwSize);
	if (bDecData != NULL)
		free(bDecData);
}

