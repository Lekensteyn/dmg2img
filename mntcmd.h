#include <inttypes.h>
#include "gpt.h"

static struct _guid guid_hfsplus = GPT_ENT_TYPE_HFSPLUS;

#define EQGUID(a,b) (memcmp(a, b, sizeof(struct _guid)) == 0)

void read_gpt_header(FILE * F, struct _gpt_header *h)
{
	memset(h, 0, sizeof(struct _gpt_header));
	fread(h, sizeof(struct _gpt_header), 1, F);
}

void read_gpt_entry(FILE * F, struct _gpt_entry *e)
{
	memset(e, 0, sizeof(struct _gpt_entry));
	fread(e, sizeof(struct _gpt_entry), 1, F);
}

int print_mountcmd(char *filename)
{
	if (!filename)
		return (-1);

	unsigned int i, pn = 0;
	char tmp[128];
	struct _gpt_header gpt_header;
	struct _gpt_entry gpt_entry;
	struct _gpt_entry *gpt_ent_array;

	FILE *F = fopen(filename, "rb");
	fseeko(F, 0x200, SEEK_SET);
	read_gpt_header(F, &gpt_header);

	if (memcmp(gpt_header.hdr_sig, GPT_HDR_SIG, sizeof(gpt_header.hdr_sig)) == 0) {
		gpt_ent_array = (struct _gpt_entry *)malloc(gpt_header.hdr_entries * sizeof(struct _gpt_entry));
		if (!gpt_ent_array) {
			return (-1);
		}
		fseeko(F, 0x400, SEEK_SET);
		for (i = 0; i < gpt_header.hdr_entries; i++) {
			fseeko(F, 0x400 + i * gpt_header.hdr_entsz, SEEK_SET);
			read_gpt_entry(F, &gpt_entry);

			if (!EQGUID(&guid_hfsplus, &gpt_entry.ent_type))
				break;
			++pn;
			memcpy(&gpt_ent_array[i], &gpt_entry, sizeof(struct _gpt_entry));
		}

		fprintf(stderr, "\nImage appears to have GUID Partition Table with %d HFS+ partition%s.\n", pn, pn == 1 ? "" : "s");
		if (pn > 0) {
			fprintf(stderr, "You should be able to mount %s [as root] by:\n\n", pn == 1 ? "it" : "them");
			fprintf(stderr, "modprobe hfsplus\n");
			for (i = 0; i < pn; i++) {
				sprintf(tmp, " (for partition %d)", i + 1);
				fprintf(stderr, "mount -t hfsplus -o loop,offset=%" PRIu64 " %s /mnt%s\n", gpt_ent_array[i].ent_lba_start * 0x200, filename, pn > 1 ? tmp : "");
			}
		} else {
			fprintf(stderr, "\
But you might be able to mount the image [as root] by:\n\n\
modprobe hfsplus\n\
mount -t hfsplus -o loop %s /mnt\n\n", filename);
		}
		if (F != NULL)
			fclose(F);

		free(gpt_ent_array);
	} else {
		fprintf(stderr, "\n\
You should be able to mount the image [as root] by:\n\n\
modprobe hfsplus\n\
mount -t hfsplus -o loop %s /mnt\n\n", filename);
	}
	return (pn);
}
