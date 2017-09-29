/*
 * Copyright (C) 2015  Antoine Busque <abusque@efficios.com>
 * Copyright (C) 2017  Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright (C) 2017  Erica Bugden <erica.bugden@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <byteswap.h>
#include <common/error.h>
#include <common/macros.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <elf.h>

#include "elf.h"

#define BUF_LEN	4096
#define TEXT_SECTION_NAME 	".text"
#define SYMBOL_TAB_SECTION_NAME ".symtab"
#define STRING_TAB_SECTION_NAME ".strtab"

#if BYTE_ORDER == LITTLE_ENDIAN
#define NATIVE_ELF_ENDIANNESS ELFDATA2LSB
#else
#define NATIVE_ELF_ENDIANNESS ELFDATA2MSB
#endif

#define bswap(x)				\
	do {					\
		switch (sizeof(x)) {		\
		case 8:				\
			x = bswap_64(x);	\
			break;			\
		case 4:				\
			x = bswap_32(x);	\
			break;			\
		case 2:				\
			x = bswap_16(x);	\
			break;			\
		case 1:				\
			break;			\
		default:			\
			abort();		\
		}				\
	} while (0)

#define bswap_shdr(shdr)	    \
	do {				    \
		bswap((shdr).sh_name);	    \
		bswap((shdr).sh_type);	    \
		bswap((shdr).sh_flags);	    \
		bswap((shdr).sh_addr);	    \
		bswap((shdr).sh_offset);    \
		bswap((shdr).sh_size);	    \
		bswap((shdr).sh_link);	    \
		bswap((shdr).sh_info);	    \
		bswap((shdr).sh_addralign); \
		bswap((shdr).sh_entsize);   \
	} while (0)

#define bswap_ehdr(ehdr)				\
	do {						\
		bswap((ehdr).e_type);			\
		bswap((ehdr).e_machine);		\
		bswap((ehdr).e_version);		\
		bswap((ehdr).e_entry);			\
		bswap((ehdr).e_phoff);			\
		bswap((ehdr).e_shoff);			\
		bswap((ehdr).e_flags);			\
		bswap((ehdr).e_ehsize);			\
		bswap((ehdr).e_phentsize);		\
		bswap((ehdr).e_phnum);			\
		bswap((ehdr).e_shentsize);		\
		bswap((ehdr).e_shnum);			\
		bswap((ehdr).e_shstrndx);		\
	} while (0)

#define copy_shdr(src_shdr, dst_shdr)					\
	do {								\
		(dst_shdr).sh_name = (src_shdr).sh_name;		\
		(dst_shdr).sh_type = (src_shdr).sh_type;		\
		(dst_shdr).sh_flags = (src_shdr).sh_flags;		\
		(dst_shdr).sh_addr = (src_shdr).sh_addr;		\
		(dst_shdr).sh_offset = (src_shdr).sh_offset;		\
		(dst_shdr).sh_size = (src_shdr).sh_size;		\
		(dst_shdr).sh_link = (src_shdr).sh_link;		\
		(dst_shdr).sh_info = (src_shdr).sh_info;		\
		(dst_shdr).sh_addralign = (src_shdr).sh_addralign;	\
		(dst_shdr).sh_entsize = (src_shdr).sh_entsize;		\
	} while (0)

#define copy_ehdr(src_ehdr, dst_ehdr)					\
	do {								\
		(dst_ehdr).e_type = (src_ehdr).e_type;			\
		(dst_ehdr).e_machine = (src_ehdr).e_machine;		\
		(dst_ehdr).e_version = (src_ehdr).e_version;		\
		(dst_ehdr).e_entry = (src_ehdr).e_entry;		\
		(dst_ehdr).e_phoff = (src_ehdr).e_phoff;		\
		(dst_ehdr).e_shoff = (src_ehdr).e_shoff;		\
		(dst_ehdr).e_flags = (src_ehdr).e_flags;		\
		(dst_ehdr).e_ehsize = (src_ehdr).e_ehsize;		\
		(dst_ehdr).e_phentsize = (src_ehdr).e_phentsize;	\
		(dst_ehdr).e_phnum = (src_ehdr).e_phnum;		\
		(dst_ehdr).e_shentsize = (src_ehdr).e_shentsize;	\
		(dst_ehdr).e_shnum = (src_ehdr).e_shnum;		\
		(dst_ehdr).e_shstrndx = (src_ehdr).e_shstrndx;		\
	} while (0)

struct lttng_elf_ehdr {
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct lttng_elf_shdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	uint64_t sh_entsize;
};

struct lttng_elf {
	int fd;
	uint8_t bitness;
	uint8_t endianness;
	/* Offset in bytes to start of section names string table. */
	off_t section_names_offset;
	/* Size in bytes of section names string table. */
	size_t section_names_size;
	struct lttng_elf_ehdr *ehdr;
};

static inline
int is_elf_32_bit(struct lttng_elf *elf)
{
	return elf->bitness == ELFCLASS32;
}

static inline
int is_elf_native_endian(struct lttng_elf *elf)
{
	return elf->endianness == NATIVE_ELF_ENDIANNESS;
}
/*
 * Retrieve the nth (where n is the `index` argument) shdr (section
 * header) from the given elf instance.
 *
 * A pointer to the shdr is returned on success, NULL on failure.
 */
static
struct lttng_elf_shdr *lttng_elf_get_shdr(struct lttng_elf *elf,
						uint16_t index)
{
	struct lttng_elf_shdr *shdr = NULL;
	off_t offset;

	if (!elf) {
		goto error;
	}

	if (index >= elf->ehdr->e_shnum) {
		goto error;
	}

	shdr = zmalloc(sizeof(struct lttng_elf_shdr));
	if (!shdr) {
		goto error;
	}

	offset = (off_t) elf->ehdr->e_shoff
			+ (off_t) index * elf->ehdr->e_shentsize;
	if (lseek(elf->fd, offset, SEEK_SET) < 0) {
		goto error;
	}

	if (is_elf_32_bit(elf)) {
		Elf32_Shdr elf_shdr;

		if (read(elf->fd, &elf_shdr, sizeof(elf_shdr))
				< sizeof(elf_shdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_shdr(elf_shdr);
		}
		copy_shdr(elf_shdr, *shdr);
	} else {
		Elf64_Shdr elf_shdr;

		if (read(elf->fd, &elf_shdr, sizeof(elf_shdr))
				< sizeof(elf_shdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_shdr(elf_shdr);
		}
		copy_shdr(elf_shdr, *shdr);
	}

	return shdr;

error:
	free(shdr);
	return NULL;
}

/*
 * Lookup a section's name from a given offset (usually from an shdr's
 * sh_name value) in bytes relative to the beginning of the section
 * names string table.
 *
 * If no name is found, NULL is returned.
 */
static
char *lttng_elf_get_section_name(struct lttng_elf *elf, off_t offset)
{
	char *name = NULL;
	size_t len = 0, to_read;	/* len does not include \0 */

	if (!elf) {
		goto error;
	}

	if (offset >= elf->section_names_size) {
		goto error;
	}

	if (lseek(elf->fd, elf->section_names_offset + offset, SEEK_SET) < 0) {
		goto error;
	}

	to_read = elf->section_names_size - offset;

	/* Find first \0 after or at current location, remember len. */
	for (;;) {
		char buf[BUF_LEN];
		ssize_t read_len;
		size_t i;

		if (!to_read) {
			goto error;
		}
		read_len = read(elf->fd, buf, min_t(size_t, BUF_LEN, to_read));
		if (read_len <= 0) {
			goto error;
		}
		for (i = 0; i < read_len; i++) {
			if (buf[i] == '\0') {
				len += i;
				goto end;
			}
		}
		len += read_len;
		to_read -= read_len;
	}
end:
	name = zmalloc(sizeof(char) * (len + 1));	/* + 1 for \0 */
	if (!name) {
		goto error;
	}
	if (lseek(elf->fd, elf->section_names_offset + offset,
		SEEK_SET) < 0) {
		goto error;
	}
	if (read(elf->fd, name, len + 1) < len + 1) {
		goto error;
	}

	return name;

error:
	free(name);
	return NULL;
}

static
int lttng_elf_validate_and_populate(struct lttng_elf *elf)
{
	uint8_t version;
	uint8_t e_ident[EI_NIDENT];
	uint8_t *magic_number = NULL;
	int ret = 0;

	if (elf->fd == -1) {
		ret = -1;
		goto error;
	}

	if (lseek(elf->fd, 0, SEEK_SET) < 0) {
		ret = -1;
		goto error;
	}

	if (read(elf->fd, e_ident, EI_NIDENT) < EI_NIDENT) {
		ret = -1;
		goto error;
	}

	elf->bitness = e_ident[EI_CLASS];
	elf->endianness = e_ident[EI_DATA];
	version = e_ident[EI_VERSION];
	magic_number = &e_ident[EI_MAG0];

	if (memcmp(magic_number, ELFMAG, SELFMAG) != 0) {
		ret = -1;
		goto error;
	}

	if (elf->bitness <= ELFCLASSNONE || elf->bitness >= ELFCLASSNUM) {
		ret = -1;
		goto error;
	}

	if (elf->endianness <= ELFDATANONE || elf->endianness >= ELFDATANUM) {
		ret = -1;
		goto error;
	}

	if (version <= EV_NONE || version >= EV_NUM) {
		ret = -1;
		goto error;
	}

error:
	return ret;
}

/*
 * Create an instance of lttng_elf for the ELF file located at
 * `path`.
 *
 * Return a pointer to the instance on success, NULL on failure.
 */
static
struct lttng_elf *lttng_elf_create(int fd)
{
	struct lttng_elf_shdr *section_names_shdr;
	struct lttng_elf *elf = NULL;
	int ret;

	if (fd < 0) {
		goto error;
	}

	elf = zmalloc(sizeof(struct lttng_elf));
	if (!elf) {
		goto error;
	}

	elf->fd = dup(fd);

	ret = lttng_elf_validate_and_populate(elf);
	if (!ret) {
		goto error;
	}

	elf->ehdr = zmalloc(sizeof(struct lttng_elf_ehdr));
	if (!elf->ehdr) {
		goto error;
	}

	if (is_elf_32_bit(elf)) {
		Elf32_Ehdr elf_ehdr;

		if (read(elf->fd, &elf_ehdr, sizeof(elf_ehdr))
				< sizeof(elf_ehdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_ehdr(elf_ehdr);
		}
		copy_ehdr(elf_ehdr, *(elf->ehdr));
	} else {
		Elf64_Ehdr elf_ehdr;

		if (read(elf->fd, &elf_ehdr, sizeof(elf_ehdr))
				< sizeof(elf_ehdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_ehdr(elf_ehdr);
		}
		copy_ehdr(elf_ehdr, *(elf->ehdr));
	}

	section_names_shdr = lttng_elf_get_shdr(elf, elf->ehdr->e_shstrndx);
	if (!section_names_shdr) {
		goto error;
	}

	elf->section_names_offset = section_names_shdr->sh_offset;
	elf->section_names_size = section_names_shdr->sh_size;

	free(section_names_shdr);
	return elf;

error:
	if (elf) {
		free(elf->ehdr);
		if (elf->fd >= 0) {
			if (close(elf->fd)) {
				abort();
			}
		}
		free(elf);
	}
	return NULL;
}

/*
 * Destroy the given lttng_elf instance.
 */
static
void lttng_elf_destroy(struct lttng_elf *elf)
{
	if (!elf) {
		return;
	}

	free(elf->ehdr);
	if (close(elf->fd)) {
		abort();
	}
	free(elf);
}

static
int lttng_elf_get_section_hdr_by_name(struct lttng_elf *elf,
									  const char *section_name,
									  struct lttng_elf_shdr **section_hdr)
{
	int i;
	char *curr_section_name;
	for (i = 0; i < elf->ehdr->e_shnum; ++i) {

		*section_hdr = lttng_elf_get_shdr(elf, i);
		curr_section_name = lttng_elf_get_section_name(elf,
												   (*section_hdr)->sh_name);

		if (!curr_section_name) {
			continue;
		}
		if (strcmp(curr_section_name, section_name) == 0) {
			return 0;
		}
	}
	return -1;
}

static
char *lttng_elf_get_section_data(struct lttng_elf *elf,
							 struct lttng_elf_shdr *shdr)
{
	int ret;
	off_t section_offset;
	char *data;

	if (!elf || !shdr) {
		goto error;
	}

	section_offset = shdr->sh_offset;
	if (lseek(elf->fd, section_offset, SEEK_SET) < 0) {
		goto error;
	}

	data = malloc(shdr->sh_size);
	ret = read(elf->fd, data, shdr->sh_size);
	if (ret < 0) {
		goto error;
	}

	return data;

error:
	return NULL;
}

/*
 * Convert the virtual address in a binary's mapping to the offset of
 * the corresponding instruction in the binary file.
 * This function assumes the address is in the text section
 *
 * Returns the offset on success or -1 in case of failure.
 */
static
int lttng_elf_convert_addr_in_text_to_offset(struct lttng_elf *elf_handle,
											 size_t addr, uint64_t *offset)
{
	int ret = 0;
	off_t text_section_offset;
	off_t text_section_addr_beg;
	off_t text_section_addr_end;
	off_t offset_in_section;
	struct lttng_elf_shdr *text_section_hdr = NULL;

	if (!elf_handle) {
		ERR("Invalid ELF handle.");
		ret = -1;
		goto error;
	}

	/* Get a pointer to the .text section header */
	ret = lttng_elf_get_section_hdr_by_name(elf_handle,
											TEXT_SECTION_NAME,
											&text_section_hdr);
	if (ret) {
		ERR("Text section not found in binary.");
		ret = -1;
		goto error;
	}

	text_section_offset = text_section_hdr->sh_offset;
	text_section_addr_beg = text_section_hdr->sh_addr;
	text_section_addr_end = text_section_addr_beg + text_section_hdr->sh_size;

	/*
	 * Verify that the address is within the .text section boundaries.
	 */
	if (addr < text_section_addr_beg || addr > text_section_addr_end) {
		ERR("Invalid address found: addr=%lu, "
			".text section=[%lu - %lu].", addr, text_section_addr_beg,
										text_section_addr_end);
		ret = -1;
		goto error;
	}

	offset_in_section = addr - text_section_addr_beg;

	/*
	 * Add the target offset in the text section to the offset of this text
	 * section from the beginning of the binary file.
	 */
	*offset = text_section_offset + offset_in_section;

error:
	return ret;
}

/*
 * Compute the offset of a symbol from the begining of the ELF binary.
 *
 * On success, returns 0 offset parameter is set to the computed value
 * On failure, returns -1.
 */
int lttng_elf_get_symbol_offset(int fd,
							 char *symbol,
							 uint64_t *offset)
{
	int ret = 0;
	int sym_found = 0;
	int sym_count = 0;
	int sym_idx = 0;
	uint64_t addr = 0;
	char *curr_sym_str = NULL;
	char *symbol_table_data = NULL;
	char *string_table_data = NULL;
	struct lttng_elf_shdr *symtab_hdr = NULL;
	struct lttng_elf_shdr *strtab_hdr = NULL;
	struct lttng_elf *elf;

	if (!symbol || !offset ) {
		goto error;
	}

	elf = lttng_elf_create(fd);
	if (!elf) {
		goto error;
	}

	/* Get the symbol table section header */
	ret = lttng_elf_get_section_hdr_by_name(elf,
											SYMBOL_TAB_SECTION_NAME,
											&symtab_hdr);
	if (ret) {
		goto error;
	}
	/* Get the data associated with the symbol table section */
	symbol_table_data = lttng_elf_get_section_data(elf, symtab_hdr);
	if (symbol_table_data == NULL) {
		goto error;
	}

	/* Get the string table section header */
	ret = lttng_elf_get_section_hdr_by_name(elf,
											STRING_TAB_SECTION_NAME,
											&strtab_hdr);
	if (ret) {
		goto error;
	}

	/* Get the data associated with the string table section */
	string_table_data = lttng_elf_get_section_data(elf, strtab_hdr);
	if (string_table_data == NULL) {
		goto error;
	}

	Elf64_Sym curr_sym;
	/* Get the number of symbol in the table for the iteration */
	sym_count = symtab_hdr->sh_size / symtab_hdr->sh_entsize;

	/* Loop over all symbol */
	for (sym_idx = 0; sym_idx < sym_count; sym_idx++) {
		/* Get the symbol at the current index */
		curr_sym = ((Elf64_Sym *) symbol_table_data)[sym_idx];

		/*
		 * If the st_name field is zero, there is no string name for
		 * this symbol; skip to the next symbol
		 */
		if (curr_sym.st_name == 0) {
			continue;
		}

		/*
		 * Use the st_name field in the Elf64_Sym struct to get offset of the
		 * symbol's name from the beginning of the string table
		 */
		curr_sym_str = string_table_data + curr_sym.st_name;

		/*
		 * Compare with the search symbol. If there is a match set the address
		 * output parameter and return success
		 */
		if (strcmp(symbol, curr_sym_str) == 0 ) {
			sym_found = 1;
			addr = curr_sym.st_value;
			break;
		}
	}

	if (!sym_found) {
		ret = -1;
		goto error;
	}

	/*
	 * Use the virtual address of the symbol to compute the offset of this
	 * symbol from the beginning of the executable file.
	 */
	ret = lttng_elf_convert_addr_in_text_to_offset(elf, addr, offset);
	if (ret) {
		goto error;
	}


error:
	lttng_elf_destroy(elf);
	free(symbol_table_data);
	free(string_table_data);
	return ret;
}
