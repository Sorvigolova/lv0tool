#include "aes.h"
#include "util.h"

#ifdef _WIN32
#include <direct.h>
#define make_dir(p) _mkdir(p)
#else
#include <sys/types.h>
#define make_dir(p) mkdir((p), 0755)
#endif

/*
 * Loader table layout inside lv0 (big-endian, 0x20 bytes per entry):
 *   +0x00  id (u32)   1..4 = first components, 0xF..0x12 = second components
 *   +0x04  padding
 *   +0x08  start (VA)
 *   +0x10  end   (VA)
 *   +0x18  size
 *
 * The table always has 8 entries: 4 first components (lv1ldr, lv2ldr,
 * isoldr, appldr) followed by 4 second components. A second component is
 * an alternate SCE header (its size equals header_len of the loader) that
 * is applied over the beginning of the matching first component.
 *
 * Test-stand lv0 contains only lv1ldr and lv1ldr.2; the other entries
 * point to zero-filled 0x10-byte stubs and are skipped.
 */

#define LDR_TAB_ENTRY_SIZE 0x20
#define LDR_MAX_ENTRIES    8
#define SCE_MAGIC          0x53434500
#define LDR_ID_FIRST_BASE  0x01
#define LDR_ID_SECOND_BASE 0x0F
#define SFC_BLOCK_SIZE     16


 /* lv1ldr scramble keys */
uint8_t lv1ldr_erk_365[0x10] = { 0x1A, 0x00, 0x84, 0xAC, 0x83, 0x84, 0x8A, 0x89, 0x46, 0x57, 0xD8, 0x10, 0x34, 0x5F, 0x77, 0x3A };
uint8_t lv1ldr_riv_365[0x10] = { 0x24, 0xB0, 0xAC, 0xC6, 0x55, 0x57, 0x91, 0x60, 0xB4, 0x1B, 0xF7, 0x79, 0x1C, 0xDE, 0x64, 0x5D };
uint8_t lv1ldr_erk_370[0x10] = { 0xB2, 0x61, 0xC5, 0x8C, 0x7E, 0xF0, 0x13, 0xDB, 0x15, 0xCC, 0xA6, 0x7E, 0x0F, 0xA9, 0x7D, 0x39 };
uint8_t lv1ldr_riv_370[0x10] = { 0x6E, 0x19, 0x82, 0x53, 0x89, 0x37, 0x55, 0x6B, 0x25, 0xB6, 0x9D, 0x8C, 0xAE, 0xFC, 0xC2, 0x37 };
uint8_t lv1ldr_erk_400[0x10] = { 0x59, 0xFB, 0xB8, 0xAE, 0x03, 0x2F, 0xF3, 0x48, 0x67, 0xFB, 0x82, 0x77, 0xFB, 0x67, 0x56, 0xC6 };
uint8_t lv1ldr_riv_400[0x10] = { 0x32, 0xD7, 0x36, 0x04, 0x5E, 0x28, 0x89, 0x91, 0x86, 0x14, 0x2C, 0xF9, 0x9A, 0x0D, 0xD4, 0xCC };
uint8_t lv1ldr_erk_420[0x10] = { 0xDA, 0xEC, 0x4A, 0x4F, 0xC9, 0x13, 0xB9, 0x81, 0xC4, 0x14, 0x61, 0x05, 0x5F, 0xF4, 0x9E, 0xBF };
uint8_t lv1ldr_riv_420[0x10] = { 0xB5, 0xF9, 0xF0, 0xE4, 0x63, 0x07, 0xDB, 0xFA, 0x5F, 0x54, 0xBE, 0x39, 0x74, 0x75, 0xE2, 0xBB };

/* Version gate: fw version is stored as major*100 + minor (e.g. 4.84 -> 484). */
#define LV0_VER_MIN  360   /* below 3.60: loaders are not handled          */
#define LV0_VER_SFC  365   /* from 3.65: lv1ldr/lv1ldr.2 gain the SFC layer */

static const char* ldr_base_name[4] = {
	"lv1ldr",
	"lv2ldr",
	"isoldr",
	"appldr",
};

typedef struct
{
	uint32_t id;
	uint64_t start;   /* VA */
	uint64_t end;     /* VA */
	uint64_t size;
	uint32_t ra;      /* file offset of the component */
} ldr_entry;

typedef struct
{
	uint32_t  count;  /* number of valid table entries (2 or 8) */
	uint32_t  pairs;  /* count / 2 */
	ldr_entry e[LDR_MAX_ENTRIES];
} ldr_table;

/* ------------------------------------------------------------------ */

static uint8_t* get_loaders_table(uint8_t* in, uint32_t size)
{
	uint32_t hdr_ptr = binsearch64(in, size, 0x1800000000ULL);
	if (hdr_ptr == 0)
		return NULL;

	uint32_t lv1ldr_ra = hdr_ptr + 0xC;
	uint32_t lv1ldr_va = ra_to_va(in, lv1ldr_ra);
	if (lv1ldr_va == 0)
		return NULL;

	/* The table entry's "start" field points to lv1ldr. */
	uint32_t start_field = binsearch64(in, size, lv1ldr_va);
	if (start_field < 8)
		return NULL;

	return in + start_field - 8;
}

static int read_entry(uint8_t* in, uint32_t size, const uint8_t* p, ldr_entry* e)
{
	e->id    = be32((uint8_t*)p + 0x00);
	e->start = be64((uint8_t*)p + 0x08);
	e->end   = be64((uint8_t*)p + 0x10);
	e->size  = be64((uint8_t*)p + 0x18);

	if (e->start == 0 || e->size == 0 || e->size >= size)
		return 0;
	if (e->start > 0xFFFFFFFFULL)
		return 0;

	e->ra = va_to_ra(in, (uint32_t)e->start);
	if (e->ra == 0)
		return 0;
	if ((uint64_t)e->ra + e->size > size)
		return 0;

	return 1;
}

static int parse_loaders_table(uint8_t* in, uint32_t size, ldr_table* t)
{
	uint8_t* tab = get_loaders_table(in, size);
	uint32_t i;

	memset(t, 0, sizeof(*t));

	if (tab == NULL) {
		printf("FAIL: loaders table not found\n");
		return -1;
	}

	for (i = 0; i < LDR_MAX_ENTRIES; i++) {
		const uint8_t* p = tab + i * LDR_TAB_ENTRY_SIZE;
		if ((uint32_t)(p - in) + LDR_TAB_ENTRY_SIZE > size)
			break;
		if (!read_entry(in, size, p, &t->e[i]))
			break;
		t->count++;
	}

	if (t->count != LDR_MAX_ENTRIES) {
		printf("FAIL: unexpected loaders table layout (%u valid entries at 0x%x)\n",
			t->count, (uint32_t)(tab - in));
		return -1;
	}

	t->pairs = t->count / 2;

	for (i = 0; i < t->pairs; i++) {
		if (t->e[i].id != LDR_ID_FIRST_BASE + i ||
		    t->e[t->pairs + i].id != LDR_ID_SECOND_BASE + i) {
			printf("FAIL: unexpected loader ids in table: 0x%x / 0x%x (slot %u)\n",
				t->e[i].id, t->e[t->pairs + i].id, i);
			return -1;
		}
		/* Second components are patches over first components. */
		if (t->e[t->pairs + i].size > t->e[i].size) {
			printf("FAIL: %s.2 (0x%llx bytes) is larger than %s (0x%llx bytes)\n",
				ldr_base_name[i], (unsigned long long)t->e[t->pairs + i].size,
				ldr_base_name[i], (unsigned long long)t->e[i].size);
			return -1;
		}
	}

	printf("loaders table at 0x%x: %u entries\n", (uint32_t)(tab - in), t->count);

	return 0;
}

static int get_key_by_version(uint8_t** erk, uint8_t** riv, int lv0_vesion)
{
	if (!erk || !riv)
		return -1;

	if (lv0_vesion < 365)
		return -1;

	if (lv0_vesion < 370)
	{
		*erk = (uint8_t*)lv1ldr_erk_365;
		*riv = (uint8_t*)lv1ldr_riv_365;
		return 0;
	}

	if (lv0_vesion < 400)
	{
		*erk = (uint8_t*)lv1ldr_erk_370;
		*riv = (uint8_t*)lv1ldr_riv_370;
		return 0;
	}
	if (lv0_vesion < 420)
	{
		*erk = (uint8_t*)lv1ldr_erk_400;
		*riv = (uint8_t*)lv1ldr_riv_400;
		return 0;
	}

	*erk = (uint8_t*)lv1ldr_erk_420;
	*riv = (uint8_t*)lv1ldr_riv_420;
	return 0;
}

void hexdump(FILE* fp, const char* name, unsigned int offset, uint8_t* buf, int len)
{
	int i, j, align = strlen(name) + 1;

	fprintf(fp, "%s ", name);
	for (i = 0; i < len; i++)
	{
		if (i % 16 == 0 && i != 0)
		{
			fprintf(fp, "\n");
			for (j = 0; j < align; j++)
				putchar(' ');
		}
		fprintf(fp, "%02X ", buf[i]);
	}
	fprintf(fp, "\n");
}

static void crypt_lv1ldr(uint8_t* data, uint32_t size, int lv0_vesion)
{
	uint8_t* erk = NULL;
	uint8_t* riv = NULL;

	if (get_key_by_version(&erk, &riv, lv0_vesion))
	{
		printf("FAIL: get_key_by_version() failed\n");
		return;
	}

	if (!erk || !riv || !data)
		return;

	aes_context aes_ctx;
	size_t nc_off = 0;
	aes_setkey_enc(&aes_ctx, erk, 128);
	unsigned char sblk[0x10];
	memset(sblk, 0, sizeof(sblk));
	unsigned char tmp_riv[0x10];
	memcpy(tmp_riv, riv, 0x10);
	aes_crypt_ctr(&aes_ctx, size, &nc_off, tmp_riv, sblk, data, data);
}

/*
 * Decrypt lv1ldr (entry 0) and lv1ldr.2 (entry `pairs`) in place.
 * Each component is handled independently; enc[k] remembers whether it
 * was encrypted so that import restores exactly the same state.
 */
static int decrypt_lv1ldr(uint8_t* in, const ldr_table* t, int enc[2], int lv0_vesion)
{
	const ldr_entry* c[2] = { &t->e[0], &t->e[t->pairs] };
	static const char* name[2] = { "lv1ldr", "lv1ldr.2" };
	int k;

	for (k = 0; k < 2; k++) {
		enc[k] = 0;
		if (be32(in + c[k]->ra) != SCE_MAGIC) {
			crypt_lv1ldr(in + c[k]->ra, (uint32_t)c[k]->size, lv0_vesion);
			enc[k] = 1;
		}
		if (be32(in + c[k]->ra) != SCE_MAGIC) {
			printf("FAIL: %s decryption failed\n", name[k]);
			return -1;
		}
	}

	return 0;
}

static void encrypt_lv1ldr(uint8_t* in, const ldr_table* t, const int enc[2], int lv0_vesion)
{
	if (enc[0])
		crypt_lv1ldr(in + t->e[0].ra,        (uint32_t)t->e[0].size,        lv0_vesion);
	if (enc[1])
		crypt_lv1ldr(in + t->e[t->pairs].ra, (uint32_t)t->e[t->pairs].size, lv0_vesion);
}

/* ------------------------------------------------------------------ */

static void make_path(char* out, size_t out_size, const char* dir, const char* name)
{
	if (dir && dir[0]) {
		size_t len = strlen(dir);
		char last = dir[len - 1];
		if (last == '/' || last == '\\')
			snprintf(out, out_size, "%s%s", dir, name);
		else
			snprintf(out, out_size, "%s/%s", dir, name);
	} else {
		snprintf(out, out_size, "%s", name);
	}
}

/* Create directory (and missing parents). Existing directory is fine. */
static int ensure_dir(const char* dir)
{
	char path[1024];
	size_t i, len;
	struct stat st;

	if (dir == NULL || dir[0] == 0)
		return 0;

	len = strlen(dir);
	if (len >= sizeof(path))
		return -1;
	memcpy(path, dir, len + 1);

	for (i = 1; i <= len; i++) {
		if (path[i] == '/' || path[i] == '\\' || path[i] == 0) {
			char c = path[i];
			/* skip drive root like "C:" */
			if (i == 2 && path[1] == ':')
				continue;
			path[i] = 0;
			if (stat(path, &st) != 0) {
				if (make_dir(path) != 0 && errno != EEXIST) {
					printf("FAIL: cannot create directory %s\n", path);
					return -1;
				}
			} else if ((st.st_mode & S_IFMT) != S_IFDIR) {
				printf("FAIL: %s exists and is not a directory\n", path);
				return -1;
			}
			path[i] = c;
		}
	}
	return 0;
}

static int save(const char* dir, const char* name, const uint8_t* data, uint32_t size)
{
	char path[1024];
	make_path(path, sizeof(path), dir, name);
	if (write_file(path, data, size) < 0) {
		printf("FAIL: cannot write %s\n", path);
		return -1;
	}
	return 0;
}

static int extract_ldrs(uint8_t* in, const ldr_table* t, const char* out_dir)
{
	uint32_t i, extracted = 0;
	char name[64];

	if (ensure_dir(out_dir) < 0)
		return -1;

	for (i = 0; i < t->pairs; i++) {
		const ldr_entry* first  = &t->e[i];
		const ldr_entry* second = &t->e[t->pairs + i];
		uint32_t first_size  = (uint32_t)first->size;
		uint32_t second_size = (uint32_t)second->size;

		/* Absent loader (test-bench lv0): stub entry without an SCE header. */
		if (be32(in + first->ra) != SCE_MAGIC) {
			printf("skipping   %-9s at 0x%06x size: 0x%x bytes (not present)\n",
				ldr_base_name[i], first->ra, first_size);
			continue;
		}
		if (be32(in + second->ra) != SCE_MAGIC) {
			printf("FAIL: %s present but %s.2 has no SCE header\n",
				ldr_base_name[i], ldr_base_name[i]);
			return -1;
		}

		/* Both components are written exactly as they sit in their slots. */
		uint8_t* first_comp = in + first->ra;
		uint32_t save_size = first_size;
		uint64_t decsize = be64(first_comp + 0x10) + be64(first_comp + 0x18);   /* header_len + data_len */
		save_size = (decsize <= first_size) ? (uint32_t)decsize : first_size;
		printf("extracting %-9s at 0x%06x size: 0x%x bytes (id 0x%x)%s\n",
			ldr_base_name[i], first->ra, save_size, first->id, save_size != first_size ? " [stripped pad]" : "");
		if (save(out_dir, ldr_base_name[i], first_comp, save_size) < 0)
			return -1;

		uint8_t* second_comp = in + second->ra;
		uint32_t save2_size = second_size;
		uint64_t hlen = be64(second_comp + 0x10);   /* header_len only */
		save2_size = (hlen <= second_size) ? (uint32_t)hlen : second_size;
		snprintf(name, sizeof(name), "%s.2", ldr_base_name[i]);
		printf("extracting %-9s at 0x%06x size: 0x%x bytes (id 0x%x)%s\n",
			name, second->ra, save2_size, second->id, save2_size != second_size ? " [stripped pad]" : "");
		if (save(out_dir, name, second_comp, save2_size) < 0)
			return -1;

		extracted += 2; /* first component + second component */
	}

	printf("%u component(s) extracted\n", extracted);
	return 0;
}

/*
 * Import.
 *
 * Input files are decrypted components with the same names that -extract
 * produces (<name> and <name>.2), each the exact raw contents of its slot.
 * The slot is selected by file name; the loaders table itself is never
 * modified. Each file is optional and is written verbatim: the target slot
 * is zero-filled and the file's bytes are copied in as-is (no merging of the
 * first component into the second). A slot without an input file is left
 * untouched. All checks are done before anything is written to the image.
 */

typedef struct
{
	int      has_first;
	int      has_second;
	uint8_t* first;        /* decrypted first component file  */
	uint8_t* second;       /* decrypted second component file */
	uint32_t first_size;
	uint32_t second_size;
} ldr_import;

static int file_exists(const char* path)
{
	FILE* fp = fopen(path, "rb");
	if (fp == NULL)
		return 0;
	fclose(fp);
	return 1;
}

static int load_input(const char* path, uint8_t** data, uint32_t* size)
{
	if (read_entire_file(path, (void**)data, size, SFC_BLOCK_SIZE) < 0) {
		printf("FAIL: cannot read %s\n", path);
		return -1;
	}
	if (*size < 0x90 || be32(*data) != SCE_MAGIC) {
		printf("FAIL: %s is not a decrypted SCE loader (no SCE header)\n", path);
		return -1;
	}
	return 0;
}

static int check_authid(const char* name, const uint8_t* data, const uint8_t* cur)
{
	if (be64((uint8_t*)data + 0x70) != be64((uint8_t*)cur + 0x70)) {
		printf("FAIL: %s: auth id 0x%016llx does not match slot auth id 0x%016llx\n", name,
			(unsigned long long)be64((uint8_t*)data + 0x70),
			(unsigned long long)be64((uint8_t*)cur + 0x70));
		return -1;
	}
	return 0;
}

/* Firmware version from a decrypted component's app_info (@0x80, BCD). */
static int comp_version(const uint8_t* data)
{
	uint8_t maj = data[0x81], min_ = data[0x83];
	return ((maj >> 4) * 10 + (maj & 0xf)) * 100 + ((min_ >> 4) * 10 + (min_ & 0xf));
}

/* Validate one input file against its target slot and load it. */
static int check_one(const char* name, const char* path, const ldr_entry* slot,
	int round16, uint8_t* in, uint8_t** data, uint32_t* size, int lv0_fw)
{
	const uint8_t* cur = in + slot->ra;
	uint32_t cap = (uint32_t)slot->size;
	uint32_t need;
	int cv;

	/* Target slot must hold a real component (not a test-stand stub). */
	if (be32((uint8_t*)cur) != SCE_MAGIC) {
		printf("FAIL: %s slot in this lv0 is a stub (0x%x bytes), component not present\n", name, cap);
		return -1;
	}
	if (load_input(path, data, size) < 0)
		return -1;

	/* Must fit the slot. lv1ldr slots are SFC-processed in whole 16-byte blocks. */
	need = round16 ? round_up(*size, SFC_BLOCK_SIZE) : *size;
	if (need > cap) {
		printf("FAIL: %s: 0x%x bytes do not fit into slot of 0x%x bytes\n", name, need, cap);
		return -1;
	}
	if (check_authid(name, *data, cur) < 0)
		return -1;

	/* Component version must match the target lv0: auth id does not
	 * distinguish firmware versions, so a wrong-version loader would pass it
	 * and brick the console. */
	cv = comp_version(*data);
	if (cv != lv0_fw) {
		printf("FAIL: %s: component version %d.%d%d does not match lv0 version %d.%d%d\n",
			name, cv / 100, (cv / 10) % 10, cv % 10,
			lv0_fw / 100, (lv0_fw / 10) % 10, lv0_fw % 10);
		return -1;
	}
	return 0;
}

static int check_pair(uint8_t* in, const ldr_table* t, uint32_t i, const char* in_dir,
	ldr_import* imp, int need_sfc, int lv0_fw)
{
	const char* name = ldr_base_name[i];
	const ldr_entry* slot1 = &t->e[i];
	const ldr_entry* slot2 = &t->e[t->pairs + i];
	int round16 = (i == 0) && need_sfc;   /* lv1ldr slots are SFC 16-byte blocks */
	char path1[1024], path2[1024], name2[64];

	snprintf(name2, sizeof(name2), "%s.2", name);
	make_path(path1, sizeof(path1), in_dir, name);
	make_path(path2, sizeof(path2), in_dir, name2);

	memset(imp, 0, sizeof(*imp));
	imp->has_first  = file_exists(path1);
	imp->has_second = file_exists(path2);
	if (!imp->has_first && !imp->has_second)
		return 0; /* nothing to import for this slot */

	if (imp->has_first &&
	    check_one(name, path1, slot1, round16, in, &imp->first, &imp->first_size, lv0_fw) < 0)
		return -1;
	if (imp->has_second &&
	    check_one(name2, path2, slot2, round16, in, &imp->second, &imp->second_size, lv0_fw) < 0)
		return -1;

	return 1;
}

static void free_imports(ldr_import* imp, uint32_t n)
{
	uint32_t i;
	for (i = 0; i < n; i++) {
		free(imp[i].first);
		free(imp[i].second);
	}
}

static int import_ldrs(uint8_t* in, const ldr_table* t, const char* in_dir, int need_sfc, int lv0_fw)
{
	ldr_import imp[LDR_MAX_ENTRIES / 2];
	int present[LDR_MAX_ENTRIES / 2];
	uint32_t i, imported = 0;

	memset(imp, 0, sizeof(imp));

	/* Pass 1: validate everything. */
	for (i = 0; i < t->pairs; i++) {
		present[i] = check_pair(in, t, i, in_dir, &imp[i], need_sfc, lv0_fw);
		if (present[i] < 0) {
			free_imports(imp, t->pairs);
			printf("nothing written\n");
			return -1;
		}
	}

	/* Pass 2: zero-fill slots and write useful bytes. */
	for (i = 0; i < t->pairs; i++) {
		const ldr_entry* slot1 = &t->e[i];
		const ldr_entry* slot2 = &t->e[t->pairs + i];
		const char* name = ldr_base_name[i];
		int pad = (int)(7 - strlen(name));

		if (!present[i]) {
			if (be32(in + slot1->ra) == SCE_MAGIC)
				printf("keeping    %-9s and %s.2 (no input files)\n", name, name);
			continue;
		}

		if (imp[i].has_first) {
			memset(in + slot1->ra, 0, (size_t)slot1->size);
			memcpy(in + slot1->ra, imp[i].first, imp[i].first_size);
			printf("importing  %-9s at 0x%06x: 0x%x of 0x%llx bytes\n", name,
				slot1->ra, imp[i].first_size, (unsigned long long)slot1->size);
			imported++;
		} else {
			printf("keeping    %-9s (no input file)\n", name);
		}

		if (imp[i].has_second) {
			memset(in + slot2->ra, 0, (size_t)slot2->size);
			memcpy(in + slot2->ra, imp[i].second, imp[i].second_size);
			printf("importing  %s.2%*s at 0x%06x: 0x%x of 0x%llx bytes\n", name, pad, "",
				slot2->ra, imp[i].second_size, (unsigned long long)slot2->size);
			imported++;
		} else {
			printf("keeping    %s.2%*s (no input file)\n", name, pad, "");
		}
	}

	free_imports(imp, t->pairs);

	if (imported == 0) {
		printf("FAIL: no loaders found in %s\n", in_dir);
		return -1;
	}
	printf("%u component(s) imported\n", imported);
	return 0;
}

/* ------------------------------------------------------------------ */

static void usage(void)
{
	printf("usage:\n"
	       "\tlv0tool -extract lv0.elf [out_dir]        extract decrypted loaders\n"
	       "\tlv0tool -import lv0.elf in_dir out.elf    import decrypted loaders from in_dir\n\n"
	       "loader file names: lv1ldr lv2ldr isoldr appldr and lv1ldr.2 lv2ldr.2 isoldr.2 appldr.2\n"
	       "out_dir is created if it does not exist (default: current directory)\n");
}

/*
 * lv0 firmware version, read from the clear-text parameter string
 * "sys.lv0.version" (whose value "A.B.C" sits in the record just before the
 * key). Returned as major*100 + minor, e.g. "4.8.4" -> 484; -1 if not found.
 */
static int lv0_version(const uint8_t* in, uint32_t size)
{
	static const char key[] = "sys.lv0.version";
	uint32_t klen = (uint32_t)sizeof(key);   /* includes the trailing NUL */
	uint32_t i, j, lo;

	if (size < klen)
		return -1;

	for (i = 0; i + klen <= size; i++) {
		if (memcmp(in + i, key, klen) != 0)
			continue;
		lo = (i > 0x40) ? i - 0x40 : 0;
		for (j = i; j > lo; ) {
			const uint8_t* p = in + --j;
			if ((uint64_t)j + 5 <= size &&
			    p[0] >= '0' && p[0] <= '9' && p[1] == '.' &&
			    p[2] >= '0' && p[2] <= '9' && p[3] == '.' &&
			    p[4] >= '0' && p[4] <= '9')
				return (p[0] - '0') * 100 + (p[2] - '0') * 10 + (p[4] - '0');
		}
		return -1;
	}
	return -1;
}

int main(int argc, char* argv[])
{
	uint8_t* in;
	uint32_t size;
	ldr_table table;
	int was_encrypted[2];
	int fwnum;
	int need_sfc;
	int do_import = 0;
	const char* lv0_path;
	const char* dir_arg = NULL;
	const char* out_path = NULL;

	if (argc < 2) {
		usage();
		return 1;
	}

	if (strcmp(argv[1], "-import") == 0) {
		if (argc != 5) {
			printf("FAIL: -import needs lv0.elf, input directory and output file\n\n");
			usage();
			return 1;
		}
		do_import = 1;
		lv0_path = argv[2];
		dir_arg  = argv[3];
		out_path = argv[4];
	} else if (strcmp(argv[1], "-extract") == 0) {
		if (argc < 3 || argc > 4) {
			printf("FAIL: -extract needs lv0.elf and optional output directory\n\n");
			usage();
			return 1;
		}
		lv0_path = argv[2];
		dir_arg  = argc > 3 ? argv[3] : NULL;
	} else {
		if (argv[1][0] == '-')
			printf("FAIL: unknown option %s\n\n", argv[1]);
		else
			printf("FAIL: option required (-extract or -import)\n\n");
		usage();
		return 1;
	}

	/* Load lv0.elf */
	if (read_entire_file(lv0_path, (void**)&in, &size, SFC_BLOCK_SIZE) < 0) {
		perror(lv0_path);
		return 1;
	}
	if (elf_validate(in, size) < 0) {
		printf("FAIL: %s is not a valid lv0 elf file\n", lv0_path);
		return 1;
	}

	/* Firmware version gate (version string lives in the clear in lv0). */
	fwnum = lv0_version(in, size);
	if (fwnum < 0) {
		printf("FAIL: cannot determine lv0 version\n");
		return 1;
	}
	printf("lv0 version: %d.%d%d\n", fwnum / 100, (fwnum / 10) % 10, fwnum % 10);
	if (fwnum < LV0_VER_MIN) {
		printf("FAIL: version %d.%d%d is below %d.%d%d, loaders are not handled\n",
			fwnum / 100, (fwnum / 10) % 10, fwnum % 10,
			LV0_VER_MIN / 100, (LV0_VER_MIN / 10) % 10, LV0_VER_MIN % 10);
		return 1;
	}

	/* Loaders table */
	if (parse_loaders_table(in, size, &table) < 0)
		return 1;

	/* lv1ldr/lv1ldr.2 carry the extra SFC layer only from 3.65 on; detect it
	 * by the absence of the SCE header. Crypto tables are loaded only then. */
	need_sfc = (be32(in + table.e[0].ra) != SCE_MAGIC) ||
	           (be32(in + table.e[table.pairs].ra) != SCE_MAGIC);
	if (need_sfc && fwnum < LV0_VER_SFC)
		printf("  NOTE: SFC layer present but version %d.%d%d is below %d.%d%d\n",
			fwnum / 100, (fwnum / 10) % 10, fwnum % 10,
			LV0_VER_SFC / 100, (LV0_VER_SFC / 10) % 10, LV0_VER_SFC % 10);

	memset(was_encrypted, 0, sizeof(was_encrypted));
	if (need_sfc) {
		/* SFC processes lv1ldr/lv1ldr.2 in whole 16-byte blocks. */
		if ((table.e[0].size % SFC_BLOCK_SIZE) ||
		    (table.e[table.pairs].size % SFC_BLOCK_SIZE)) {
			printf("FAIL: lv1ldr slots are not 16-byte aligned (0x%llx / 0x%llx)\n",
				(unsigned long long)table.e[0].size,
				(unsigned long long)table.e[table.pairs].size);
			return 1;
		}

		/* Decrypt lv1ldr. */
		if (decrypt_lv1ldr(in, &table, was_encrypted, fwnum) < 0)
			return 1;
	}

	if (!do_import) {
		if (extract_ldrs(in, &table, dir_arg) < 0)
			return 1;
	} else {
		if (import_ldrs(in, &table, dir_arg, need_sfc, fwnum) < 0)
			return 1;
		if (need_sfc)
			encrypt_lv1ldr(in, &table, was_encrypted, fwnum);
		if (write_file(out_path, in, size) < 0) {
			printf("FAIL: cannot write %s\n", out_path);
			return 1;
		}
	}

	free(in);
	return 0;
}
