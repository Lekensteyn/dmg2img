/*
 * DMG2IMG dmg2img.c
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

#define _FILE_OFFSET_BITS 64
#define VERSION "dmg2img v1.6.4 (c) vu1tur (to@vu1tur.eu.org)"
#define USAGE "\
Usage: dmg2img [-l] [-p N] [-s] [-v] [-V] [-d] <input.dmg> [<output.img>]\n\
or     dmg2img [-l] [-p N] [-s] [-v] [-V] [-d] -i <input.dmg> -o <output.img>\n\n\
Options: -s (silent) -v (verbose) -V (extremely verbose) -d (debug)\n\
         -l (list partitions) -p N (extract only partition N)"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include "dmg2img.h"
#include "base64.h"
#include "mntcmd.h"

/* take chunk size to be 1 MByte so it will work even with little RAM */
#define CHUNKSIZE 0x100000
#define DECODEDSIZE 0x100000

FILE *FIN = NULL, *FOUT = NULL, *FDBG = NULL;
int debug = 0;
int verbose = 1;
int listparts = 0;
int extractpart = -1;
double percent;
unsigned int offset;

void mem_overflow()
{
	printf("ERROR: not enough memory\n");
	if (FIN != NULL)
		fclose(FIN);
	if (FDBG != NULL)
		fclose(FDBG);
	if (FOUT != NULL)
		fclose(FOUT);
	exit(-1);
}

void error_dmg_corrupted()
{
	printf("ERROR: dmg image is corrupted\n");
	if (FIN != NULL)
		fclose(FIN);
	if (FDBG != NULL)
		fclose(FDBG);
	if (FOUT != NULL)
		fclose(FOUT);
	exit(-1);
}

void percentage()
{
	int i, s;
	char sp[128];

	if (verbose < 1)
		return;
	s = offset / 0x28;
	if (verbose >= 3)
		printf("[%d] %6.2f%%\n", s, percent);
	else if (verbose == 2) {
		sprintf(sp, "[%d] %6.2f%%", s, percent);
		for (i = 0; i < strlen(sp); i++)
			printf("\b");
		printf("%s", sp);
	} else {
		sprintf(sp, "%6.2f%%", percent);
		for (i = 0; i < strlen(sp); i++)
			printf("\b");
		printf("%s", sp);
	}
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	int i, err, partnum = 0, scb;
	Bytef *tmp = NULL, *otmp = NULL, *dtmp = NULL;
	char *input_file = NULL, *output_file = NULL;
	char *plist = NULL;
	char *blkx = NULL;
	unsigned int blkx_size;
	struct _mishblk *parts = NULL;
	char *data_begin = NULL, *data_end = NULL;
	char *partname_begin = NULL, *partname_end = NULL;
	char *mish_begin = NULL;
	char partname[255] = "";
	unsigned int *partlen = NULL;
	unsigned int data_size;
	uint64_t out_offs, out_size, in_offs, in_size, in_offs_add, add_offs, to_read,
	      to_write, chunk;
	char reserved[5] = "    ";
	char sztype[64] = "";
	unsigned int block_type, dw_reserved;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-s"))
			verbose = 0;
		else if (!strcmp(argv[i], "-v"))
			verbose = 2;
		else if (!strcmp(argv[i], "-V"))
			verbose = 3;
		else if (!strcmp(argv[i], "-d"))
			debug = 1;
		else if (!strcmp(argv[i], "-l"))
			listparts = 1;
		else if (!strcmp(argv[i], "-p"))
			sscanf(argv[++i], "%d", &extractpart);
		else if (!strcmp(argv[i], "-i") && i < argc - 1)
			input_file = argv[++i];
		else if (!strcmp(argv[i], "-o") && i < argc - 1)
			output_file = argv[++i];
		else if (!input_file)
			input_file = argv[i];
		else if (!output_file)
			output_file = argv[i];
	}

	if (!input_file) {
		printf("\n%s\n\n%s\n\n", VERSION, USAGE);
		return 0;
	}
	if (!output_file) {
		i = strlen(input_file);
		output_file = (char *)malloc(i + 6);
		if (output_file) {
			strcpy(output_file, input_file);
			if (strcasecmp(&output_file[i - 4], ".dmg"))
				strcat(output_file, ".img");
			else
				strcpy(&output_file[i - 4], ".img");
		}
	}
	if (verbose)
		printf("\n%s\n\n", VERSION);
	if (debug) {
		FDBG = fopen("dmg2img.log", "wb");
		if (FDBG == NULL) {
			debug = 0;
			printf("ERROR: Can't create dmg2img.log. No debug info will be written.\n");
		}
	}
	FIN = fopen(input_file, "rb");
	if (FIN == NULL) {
		printf("ERROR: Can't open input file %s\n", input_file);
		return 0;
	}
	if (output_file)
		FOUT = fopen(output_file, "wb");
	else
		FOUT = NULL;
	if (FOUT == NULL) {
		printf("ERROR: Can't create output file %s\n", output_file);
		fclose(FIN);
		return 0;
	}
	//parsing koly block
	fseeko(FIN, -0x200, SEEK_END);
	read_kolyblk(FIN, &kolyblk);
	if (kolyblk.Signature != 0x6b6f6c79) {
		fseeko(FIN, 0, SEEK_SET);
		read_kolyblk(FIN, &kolyblk);
	}
	char szSignature[5];
	szSignature[4] = '\0';
	int rSignature = convert_int(kolyblk.Signature);
	memcpy(szSignature, &rSignature, 4);

	if (debug) {
		fprintf(FDBG, "Signature:\t\t0x%08" PRIX32 " (%s)\n", kolyblk.Signature, szSignature);
		fprintf(FDBG, "Version:\t\t0x%08" PRIX32 "\n", kolyblk.Version);
		fprintf(FDBG, "HeaderSize:\t\t0x%08" PRIX32 "\n", kolyblk.HeaderSize);
		fprintf(FDBG, "Flags:\t\t\t0x%08" PRIX32 "\n", kolyblk.Flags);
		fprintf(FDBG, "RunningDataForkOffset:\t0x%016" PRIX64 "\n", kolyblk.RunningDataForkOffset);
		fprintf(FDBG, "DataForkOffset:\t\t0x%016" PRIX64 "\n", kolyblk.DataForkOffset);
		fprintf(FDBG, "DataForkLength:\t\t0x%016" PRIX64 "\n", kolyblk.DataForkLength);
		fprintf(FDBG, "RsrcForkOffset:\t\t0x%016" PRIX64 "\n", kolyblk.RsrcForkOffset);
		fprintf(FDBG, "RsrcForkLength:\t\t0x%016" PRIX64 "\n", kolyblk.RsrcForkLength);
		fprintf(FDBG, "SegmentNumber:\t\t0x%08" PRIX32 "\n", kolyblk.SegmentNumber);
		fprintf(FDBG, "SegmentCount:\t\t0x%08" PRIX32 "\n", kolyblk.SegmentCount);
		fprintf(FDBG, "SegmentID:\t\t0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", kolyblk.SegmentID1, kolyblk.SegmentID2, kolyblk.SegmentID3, kolyblk.SegmentID4);
		fprintf(FDBG, "DataForkChecksumType:\t0x%08" PRIX32 " %s\n", kolyblk.DataForkChecksumType, kolyblk.DataForkChecksumType == 0x02 ? "CRC-32" : "");
		fprintf(FDBG, "DataForkChecksum:\t0x%08" PRIX32 "\n", kolyblk.DataForkChecksum);
		fprintf(FDBG, "XMLOffset:\t\t0x%016" PRIX64 "\n", kolyblk.XMLOffset);
		fprintf(FDBG, "XMLLength:\t\t0x%016" PRIX64 "\n", kolyblk.XMLLength);
		fprintf(FDBG, "MasterChecksumType:\t0x%08" PRIX32 " %s\n", kolyblk.MasterChecksumType, kolyblk.MasterChecksumType == 0x02 ? "CRC-32" : "");
		fprintf(FDBG, "MasterChecksum:\t\t0x%08" PRIX32 "\n", kolyblk.MasterChecksum);
		fprintf(FDBG, "ImageVariant:\t\t0x%08" PRIX32 "\n", kolyblk.ImageVariant);
		fprintf(FDBG, "SectorCount:\t\t0x%016" PRIX64 "\n", kolyblk.SectorCount);

		fprintf(FDBG, "\n");
	}
	if (kolyblk.Signature != 0x6b6f6c79) {
		error_dmg_corrupted();
	}
	if (verbose) {
		if (input_file && output_file)
			printf("%s --> %s\n\n", input_file, listparts ? "(partition list)" : output_file);
	}
	if (debug)
		printf("Debug info will be written to dmg2img.log\n\n");

	if (kolyblk.XMLOffset != 0 && kolyblk.XMLLength != 0) {
		//We have a plist to parse
			if (verbose > 1)
			printf("reading property list, %llu bytes from address %llu ...\n", (unsigned long long)kolyblk.XMLLength, (unsigned long long)kolyblk.XMLOffset);

		plist = (char *)malloc(kolyblk.XMLLength + 1);

		if (!plist)
			mem_overflow();

		fseeko(FIN, kolyblk.XMLOffset, SEEK_SET);
		fread(plist, kolyblk.XMLLength, 1, FIN);
		plist[kolyblk.XMLLength] = '\0';

		if (debug && verbose >= 3) {
			fprintf(FDBG, "%s\n", plist);
		}
		char *_blkx_begin = strstr(plist, blkx_begin);
		blkx_size = strstr(_blkx_begin, list_end) - _blkx_begin;
		blkx = (char *)malloc(blkx_size + 1);
		memcpy(blkx, _blkx_begin, blkx_size);
		blkx[blkx_size] = '\0';

		if (!strstr(plist, plist_begin) ||
		    !strstr(&plist[kolyblk.XMLLength - 20], plist_end)) {
			printf("ERROR: Property list is corrupted.\n");
			exit(-1);
		}
		data_begin = blkx;
		partnum = 0;
		scb = strlen(chunk_begin);
		while (1) {
			unsigned int tmplen;
			data_begin = strstr(data_begin, chunk_begin);
			if (!data_begin)
				break;
			data_begin += scb;
			data_end = strstr(data_begin, chunk_end);
			if (!data_end)
				break;
			data_size = data_end - data_begin;
			i = partnum;
			++partnum;
			parts = (struct _mishblk *)realloc(parts, partnum * sizeof(struct _mishblk));
			if (!parts)
				mem_overflow();

			char *base64data = (char *)malloc(data_size + 1);
			if (!base64data)
				mem_overflow();
			base64data[data_size] = '\0';
			memcpy(base64data, data_begin, data_size);
			if (verbose >= 3)
				printf("%s\n", base64data);
			cleanup_base64(base64data, data_size);
			decode_base64(base64data, strlen(base64data), base64data, &tmplen);
			fill_mishblk(base64data, &parts[i]);
			if (parts[i].BlocksSignature != 0x6D697368)
				break;

			parts[i].Data = (char *)malloc(parts[i].BlocksRunCount * 0x28);
			if (!parts[i].Data)
				mem_overflow();
			memcpy(parts[i].Data, base64data + 0xCC, parts[i].BlocksRunCount * 0x28);

			free(base64data);
	
			partname_begin = strstr(data_begin, name_key);
			partname_begin = strstr(partname_begin, name_begin) + strlen(name_begin);
			partname_end = strstr(partname_begin, name_end);
			memset(partname, 0, 255);
			memcpy(partname, partname_begin, partname_end - partname_begin);
			if (verbose >= 2) {
				printf("partition %d: begin=%d, size=%d, decoded=%d\n", i, (int)(data_begin - blkx), data_size, tmplen);
				if (listparts)
					printf("             %s\n", partname);
			} else if (listparts)
				printf("partition %d: %s\n", i, partname);
		}
	} else if (kolyblk.RsrcForkOffset != 0 && kolyblk.RsrcForkLength != 0) {
		//We have a binary resource fork to parse
			plist = (char *)malloc(kolyblk.RsrcForkLength);
		if (!plist)
			mem_overflow();
		fseeko(FIN, kolyblk.RsrcForkOffset, SEEK_SET);
		fread(plist, kolyblk.RsrcForkLength, 1, FIN);
		partnum = 0;
		struct _mishblk mishblk;
		int next_mishblk = 0;
		mish_begin = plist + 0x104;
		while (1) {
			mish_begin += next_mishblk;
			if (mish_begin - plist + 0xCC > kolyblk.RsrcForkLength)
				break;

			fill_mishblk(mish_begin, &mishblk);
			if (mishblk.BlocksSignature != 0x6D697368)
				break;

			next_mishblk = 0xCC + 0x28 * mishblk.BlocksRunCount + 0x04;
			i = partnum;
			++partnum;
			parts = (struct _mishblk *)realloc(parts, partnum * sizeof(struct _mishblk));
			if (!parts)
				mem_overflow();
			memcpy(&parts[i], &mishblk, sizeof(struct _mishblk));
			parts[i].Data = (char *)malloc(0x28 * mishblk.BlocksRunCount);
			if (!parts[i].Data)
				mem_overflow();
			memcpy(parts[i].Data, mish_begin + 0xCC, 0x28 * mishblk.BlocksRunCount);
			if (verbose >= 2)
				printf("partition %d: begin=%d, size=%" PRIu32 "\n", i, (int)(mish_begin - plist), 0xCC + mishblk.BlocksRunCount * 0x28);
		}
	} else {
		error_dmg_corrupted();
	}
	
	if (listparts || extractpart > partnum-1) {
		if (extractpart > partnum-1)
			printf("partition %d not found\n", extractpart);
		
		for (i = 0; i < partnum; i++)
			if (parts[i].Data != NULL)
				free(parts[i].Data);
		if (parts != NULL)
			free(parts);
		if (plist != NULL)
			free(plist);
		if (blkx != NULL)
			free(blkx);
		
		return 0;
	}
		
	if (verbose)
		printf("\ndecompressing:\n");

	tmp = (Bytef *) malloc(CHUNKSIZE);
	otmp = (Bytef *) malloc(CHUNKSIZE);
	dtmp = (Bytef *) malloc(DECODEDSIZE);
	if (!tmp || !otmp || !dtmp)
		mem_overflow();
	z.zalloc = (alloc_func) 0;
	z.zfree = (free_func) 0;
	z.opaque = (voidpf) 0;
	bz.bzalloc = NULL;
	bz.bzfree = NULL;
	bz.opaque = NULL;

	in_offs = add_offs = in_offs_add = kolyblk.DataForkOffset;

	for (i = extractpart==-1?0:extractpart; i < (extractpart==-1?partnum:extractpart+1) && in_offs < kolyblk.DataForkLength - kolyblk.DataForkOffset; i++) {
		if (verbose)
			printf("opening partition %d ...           ", i);
		if (verbose >= 3)
			printf("\n");
		else if (verbose)
			printf("         ");
		fflush(stdout);
		offset = 0;
		add_offs = in_offs_add;
		block_type = 0;
		if (debug) {
			fprintf(FDBG, "\n   run..... ..type.... ..reserved ..sectorStart..... ..sectorCount..... ..compOffset...... ..compLength......\n");
		}
		unsigned long bi = 0;
		while (block_type != BT_TERM && offset < parts[i].BlocksRunCount * 0x28) {
			block_type = convert_char4((unsigned char *)parts[i].Data + offset);
			dw_reserved = convert_char4((unsigned char *)parts[i].Data + offset + 4);
			memcpy(&reserved, parts[i].Data + offset + 4, 4);
			out_offs = convert_char8((unsigned char *)parts[i].Data + offset + 8) * 0x200;
			out_size = convert_char8((unsigned char *)parts[i].Data + offset + 16) * 0x200;
			in_offs = convert_char8((unsigned char *)parts[i].Data + offset + 24);
			in_size = convert_char8((unsigned char *)parts[i].Data + offset + 32);
			if (block_type != BT_TERM)
				in_offs_add = add_offs + in_offs + in_size;
			if (debug) {
				switch (block_type) {
				case BT_ADC:
					strcpy(sztype, "adc");
					break;
				case BT_ZLIB:
					strcpy(sztype, "zlib");
					break;
				case BT_BZLIB:
					strcpy(sztype, "bzlib");
					break;
				case BT_ZERO:
					strcpy(sztype, "zero");
					break;
				case BT_IGNORE:
					strcpy(sztype, "ignore");
					break;
				case BT_RAW:
					strcpy(sztype, "raw");
					break;
				case BT_COMMENT:
					strcpy(sztype, "comment ");
					strcat(sztype, reserved);
					break;
				case BT_TERM:
					strcpy(sztype, "terminator");
					break;
				default:
					sztype[0] = '\0';
				}
				fprintf(FDBG, " 0x%08lX 0x%08lX 0x%08lX 0x%016llX 0x%016llX 0x%016llX 0x%016llX %s\n",
					(unsigned long)bi,
					(unsigned long)block_type,
					(unsigned long)dw_reserved,
					(unsigned long long)out_offs / 0x200,
					(unsigned long long)out_size / 0x200,
					(unsigned long long)in_offs,
					(unsigned long long)in_size,
					sztype
					);
				fflush(FDBG);
				bi++;
			}
			if (verbose >= 3)
				printf("offset = %u  block_type = 0x%08x\n", offset, block_type);

			if (block_type == BT_ZLIB) {
				if (verbose >= 3)
					printf("zlib inflate (in_addr=%llu in_size=%llu out_addr=%llu out_size=%llu)\n", (unsigned long long)in_offs, (unsigned long long)in_size, (unsigned long long)out_offs, (unsigned long long)out_size);
				if (inflateInit(&z) != Z_OK) {
					printf("ERROR: Can't initialize inflate stream\n");
					return 0;
				}
				fseeko(FIN, in_offs + add_offs, SEEK_SET);
				to_read = in_size;
				do {
					if (!to_read)
						break;
					if (to_read > CHUNKSIZE)
						chunk = CHUNKSIZE;
					else
						chunk = to_read;
					z.avail_in = fread(tmp, 1, chunk, FIN);
					if (ferror(FIN)) {
						(void)inflateEnd(&z);
						printf("ERROR: reading file %s \n", input_file);
						return 0;
					}
					if (z.avail_in == 0)
						break;
					to_read -= z.avail_in;
					z.next_in = tmp;
					do {
						z.avail_out = CHUNKSIZE;
						z.next_out = otmp;
						err = inflate(&z, Z_NO_FLUSH);
						assert(err != Z_STREAM_ERROR);	/* state not clobbered */
						switch (err) {
						case Z_NEED_DICT:
							err = Z_DATA_ERROR;	/* and fall through */
						case Z_DATA_ERROR:
						case Z_MEM_ERROR:
							(void)inflateEnd(&z);
							printf("ERROR: Inflation failed\n");
							return 0;
						}
						to_write = CHUNKSIZE - z.avail_out;
						if (fwrite(otmp, 1, to_write, FOUT) != to_write || ferror(FOUT)) {
							(void)inflateEnd(&z);
							printf("ERROR: writing file %s \n", output_file);
							return 0;
						}
					} while (z.avail_out == 0);
				} while (err != Z_STREAM_END);

				(void)inflateEnd(&z);
			} else if (block_type == BT_BZLIB) {
				if (verbose >= 3)
					printf("bzip2 decompress (in_addr=%llu in_size=%llu out_addr=%llu out_size=%llu)\n", (unsigned long long)in_offs, (unsigned long long)in_size, (unsigned long long)out_offs, (unsigned long long)out_size);
				if (BZ2_bzDecompressInit(&bz, 0, 0) != BZ_OK) {
					printf("ERROR: Can't initialize inflate stream\n");
					return 0;
				}
				fseeko(FIN, in_offs + add_offs, SEEK_SET);
				to_read = in_size;
				do {
					if (!to_read)
						break;
					if (to_read > CHUNKSIZE)
						chunk = CHUNKSIZE;
					else
						chunk = to_read;
					bz.avail_in = fread(tmp, 1, chunk, FIN);
					if (ferror(FIN)) {
						(void)BZ2_bzCompressEnd(&bz);
						printf("ERROR: reading file %s \n", input_file);
						return 0;
					}
					if (bz.avail_in == 0)
						break;
					to_read -= bz.avail_in;
					bz.next_in = (char *)tmp;
					do {
						bz.avail_out = CHUNKSIZE;
						bz.next_out = (char *)otmp;
						err = BZ2_bzDecompress(&bz);
						switch (err) {
						case BZ_PARAM_ERROR:
						case BZ_DATA_ERROR:
						case BZ_DATA_ERROR_MAGIC:
						case BZ_MEM_ERROR:
							(void)BZ2_bzDecompressEnd(&bz);
							printf("ERROR: Inflation failed\n");
							return 0;
						}
						to_write = CHUNKSIZE - bz.avail_out;
						if (fwrite(otmp, 1, to_write, FOUT) != to_write || ferror(FOUT)) {
							(void)BZ2_bzDecompressEnd(&bz);
							printf("ERROR: writing file %s \n", output_file);
							return 0;
						}
					} while (bz.avail_out == 0);
				} while (err != BZ_STREAM_END);

				(void)BZ2_bzDecompressEnd(&bz);
			} else if (block_type == BT_ADC) {
				if (verbose >= 3)
					printf("ADC decompress (in_addr=%llu in_size=%llu out_addr=%llu out_size=%llu)\n", (unsigned long long)in_offs, (unsigned long long)in_size, (unsigned long long)out_offs, (unsigned long long)out_size);
				fseeko(FIN, in_offs + add_offs, SEEK_SET);
				to_read = in_size;
				while (to_read > 0) {
					chunk = to_read > CHUNKSIZE ? CHUNKSIZE : to_read;
					to_write = fread(tmp, 1, chunk, FIN);
					if (ferror(FIN) || to_write < chunk) {
						printf("ERROR: reading file %s\n", input_file);
						return 0;
					}
					int bytes_written;
					int read_from_input = adc_decompress(to_write, tmp, DECODEDSIZE, dtmp, &bytes_written);
					fwrite(dtmp, 1, bytes_written, FOUT);
					to_read -= read_from_input;
				}
			} else if (block_type == BT_RAW) {
				fseeko(FIN, in_offs + add_offs, SEEK_SET);
				to_read = in_size;
				while (to_read > 0) {
					if (to_read > CHUNKSIZE)
						chunk = CHUNKSIZE;
					else
						chunk = to_read;
					to_write = fread(tmp, 1, chunk, FIN);
					if (ferror(FIN) || to_write < chunk) {
						printf("ERROR: reading file %s \n", input_file);
						return 0;
					}
					fwrite(tmp, 1, chunk, FOUT);
					//copy
						to_read -= chunk;
				}
				if (verbose >= 3)
					printf("copy data  (in_addr=%llu in_size=%llu out_size=%llu)\n", (unsigned long long)in_offs, (unsigned long long)in_size, (unsigned long long)out_size);
			} else if (block_type == BT_ZERO || block_type == BT_IGNORE) {
				memset(tmp, 0, CHUNKSIZE);
				to_write = out_size;
				while (to_write > 0) {
					if (to_write > CHUNKSIZE)
						chunk = CHUNKSIZE;
					else
						chunk = to_write;
					fwrite(tmp, 1, chunk, FOUT);
					to_write -= chunk;
				}
				if (verbose >= 3)
					printf("null bytes (out_size=%llu)\n",
						   (unsigned long long)out_size);
			} else if (block_type == BT_COMMENT) {
				if (verbose >= 3)
					printf("0x%08x (in_addr=%llu in_size=%llu out_addr=%llu out_size=%llu) comment %s\n", block_type, (unsigned long long)in_offs,
						   (unsigned long long)in_size,
						   (unsigned long long)out_offs,
						   (unsigned long long)out_size, reserved);
			} else if (block_type == BT_TERM) {
				if (in_offs == 0 && partnum > i+1) {
					if (convert_char8((unsigned char *)parts[i+1].Data + 24) != 0)
						in_offs_add = 0;
				} else
					in_offs_add = 0;

				if (verbose >= 3)
					printf("terminator\n");
			} else {
				if (verbose)
					printf("\n Unsupported or corrupted block found: %d\n", block_type);
			}
			offset += 0x28;
			if (verbose) {
				percent = 100 * (double)offset / ((double)parts[i].BlocksRunCount * 0x28);
				percentage();
			}
		}
		if (verbose)
			printf("  ok\n");
	}
	if (verbose)
		printf("\nArchive successfully decompressed as %s\n", output_file);

	if (tmp != NULL)
		free(tmp);
	if (otmp != NULL)
		free(otmp);
	if (dtmp != NULL)
		free(dtmp);
	for (i = 0; i < partnum; i++) {
		if (parts[i].Data != NULL)
			free(parts[i].Data);
	}
	if (parts != NULL)
		free(parts);
	if (partlen != NULL)
		free(partlen);
	if (plist != NULL)
		free(plist);
	if (blkx != NULL)
		free(blkx);
	if (FIN != NULL)
		fclose(FIN);
	if (FOUT != NULL)
		fclose(FOUT);
	if (FDBG != NULL)
		fclose(FDBG);

#if defined(__linux__)
	if (verbose && extractpart > -1)
		print_mountcmd(output_file);
#endif

	return 0;
}
