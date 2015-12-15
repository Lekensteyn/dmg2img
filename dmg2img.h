/*
 * DMG2IMG dmg2img.h
 * 
 * Copyright (c) 2004 vu1tur <to@vu1tur.eu.org> This program is free software; you
 * can redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <zlib.h>
#include <bzlib.h>
#include "adc.h"
#include <unistd.h>

#define BT_ADC   0x80000004
#define BT_ZLIB  0x80000005
#define BT_BZLIB 0x80000006

#define BT_ZERO 0x00000000
#define BT_RAW 0x00000001
#define BT_IGNORE 0x00000002
#define BT_COMMENT 0x7ffffffe
#define BT_TERM 0xffffffff

#define SECTOR_SIZE 0x200

#ifdef __MINGW32__
#define fseeko fseeko64
#endif

z_stream z;
bz_stream bz;

const char plist_begin[] = "<plist version=\"1.0\">";
const char plist_end[] = "</plist>";
const char list_begin[] = "<array>";
const char list_end[] = "</array>";
const char chunk_begin[] = "<data>";
const char chunk_end[] = "</data>";
const char blkx_begin[] = "<key>blkx</key>";
const char name_key[] = "<key>Name</key>";
const char name_begin[] = "<string>";
const char name_end[] = "</string>";

int convert_int(int i)
{
	int o;
	char *p_i = (char *) &i;
	char *p_o = (char *) &o;
	p_o[0] = p_i[3];
	p_o[1] = p_i[2];
	p_o[2] = p_i[1];
	p_o[3] = p_i[0];
	return o;
}

uint64_t convert_int64(uint64_t i)
{
	uint64_t o;
	char *p_i = (char *) &i;
	char *p_o = (char *) &o;
	p_o[0] = p_i[7];
	p_o[1] = p_i[6];
	p_o[2] = p_i[5];
	p_o[3] = p_i[4];
	p_o[4] = p_i[3];
	p_o[5] = p_i[2];
	p_o[6] = p_i[1];
	p_o[7] = p_i[0];
	return o;
}

uint32_t convert_char4(unsigned char *c)
{
	return (((uint32_t) c[0]) << 24) | (((uint32_t) c[1]) << 16) |
	(((uint32_t) c[2]) << 8) | ((uint32_t) c[3]);
}

uint64_t convert_char8(unsigned char *c)
{
	return ((uint64_t) convert_char4(c) << 32) | (convert_char4(c + 4));
}

struct _kolyblk {
	uint32_t Signature;
	uint32_t Version;
	uint32_t HeaderSize;
	uint32_t Flags;
	uint64_t RunningDataForkOffset;
	uint64_t DataForkOffset;
	uint64_t DataForkLength;
	uint64_t RsrcForkOffset;
	uint64_t RsrcForkLength;
	uint32_t SegmentNumber;
	uint32_t SegmentCount;
	uint32_t SegmentID1;
	uint32_t SegmentID2;
	uint32_t SegmentID3;
	uint32_t SegmentID4;
	uint32_t DataForkChecksumType;
	uint32_t Reserved1;
	uint32_t DataForkChecksum;
	uint32_t Reserved2;
	char Reserved3[120];
	uint64_t XMLOffset;
	uint64_t XMLLength;
	char Reserved4[120];
	uint32_t MasterChecksumType;
	uint32_t Reserved5;
	uint32_t MasterChecksum;
	uint32_t Reserved6;
	char Reserved7[120];
	uint32_t ImageVariant;
	uint64_t SectorCount;
	char Reserved8[12];
} __attribute__ ((__packed__));
struct _kolyblk kolyblk;


struct _mishblk {
	uint32_t BlocksSignature;
	uint32_t InfoVersion;
	uint64_t FirstSectorNumber;
	uint64_t SectorCount;
	uint64_t DataStart;
	uint32_t DecompressedBufferRequested;
	uint32_t BlocksDescriptor;
	char Reserved1[24];
	uint32_t ChecksumType;
	uint32_t Reserved2;
	uint32_t Checksum;
	uint32_t Reserved3;
	char Reserved4[120];
	uint32_t BlocksRunCount;
	char *Data;
} __attribute__ ((__packed__));


void read_kolyblk(FILE* F, struct _kolyblk* k)
{
	fread(k, 0x200, 1, F);
	k->Signature = convert_int(k->Signature);
	k->Version = convert_int(k->Version);
	k->HeaderSize = convert_int(k->HeaderSize);
	k->Flags = convert_int(k->Flags);
	k->RunningDataForkOffset = convert_int64(k->RunningDataForkOffset);
	k->DataForkOffset = convert_int64(k->DataForkOffset);
	k->DataForkLength = convert_int64(k->DataForkLength);
	k->RsrcForkOffset = convert_int64(k->RsrcForkOffset);
	k->RsrcForkLength = convert_int64(k->RsrcForkLength);
	k->SegmentNumber = convert_int(k->SegmentNumber);
	k->SegmentCount = convert_int(k->SegmentCount);
	k->DataForkChecksumType = convert_int(k->DataForkChecksumType);
	k->DataForkChecksum = convert_int(k->DataForkChecksum);
	k->XMLOffset = convert_int64(k->XMLOffset);
	k->XMLLength = convert_int64(k->XMLLength);
	k->MasterChecksumType = convert_int(k->MasterChecksumType);
	k->MasterChecksum = convert_int(k->MasterChecksum);
	k->ImageVariant = convert_int(k->ImageVariant);
	k->SectorCount = convert_int64(k->SectorCount);
}

void print_mishblk(FILE *f, struct _mishblk *m)
{
	fprintf(f, "%-28s: %08"  PRIx32 "\n", "BlocksSignature", m->BlocksSignature);
	fprintf(f, "%-28s: %08"  PRIx32 "\n", "InfoVersion", m->InfoVersion);
	fprintf(f, "%-28s: %016" PRIx64 "\n", "FirstSectorNumber", m->FirstSectorNumber);
	fprintf(f, "%-28s: %016" PRIx64 "\n", "SectorCount", m->SectorCount);
	fprintf(f, "%-28s: %016" PRIx64 "\n", "DataStart", m->DataStart);
	fprintf(f, "%-28s: %08"  PRIx32 "\n", "DecompressedBufferRequested", m->DecompressedBufferRequested);
	fprintf(f, "%-28s: %08"  PRIx32 "\n", "BlocksDescriptor", m->BlocksDescriptor);
	fprintf(f, "%-28s: %08"  PRIx32 "\n", "ChecksumType", m->ChecksumType);
	fprintf(f, "%-28s: %08"  PRIx32 "\n", "Checksum", m->Checksum);
	fprintf(f, "%-28s: %08"  PRIx32 "\n", "BlocksRunCount", m->BlocksRunCount);
}

void fill_mishblk(char* c, struct _mishblk* m)
{
	memset(m, 0, sizeof(struct _mishblk));
	memcpy(m, c, 0xCC);
	m->BlocksSignature = convert_int(m->BlocksSignature);
	m->InfoVersion = convert_int(m->InfoVersion);
	m->FirstSectorNumber = convert_int64(m->FirstSectorNumber);
	m->SectorCount = convert_int64(m->SectorCount);
	m->DataStart = convert_int64(m->DataStart);
	m->DecompressedBufferRequested = convert_int(m->DecompressedBufferRequested);
	m->BlocksDescriptor = convert_int(m->BlocksDescriptor);
	m->ChecksumType = convert_int(m->ChecksumType);
	m->Checksum = convert_int(m->Checksum);
	m->BlocksRunCount = convert_int(m->BlocksRunCount);
}

