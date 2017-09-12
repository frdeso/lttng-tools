/*
 * userspace-probe-offset.c
 *
 * Copyright (C) 2017 - Erica Bugden <erica.bugden@efficios.com>
 *                      Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <fcntl.h>
#include <stdio.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>
#include <unistd.h>
#include <common/common.h>
#include <stdbool.h>
#include "userspace-probe-offset.h"

#define TEXT_SECTION_NAME 	".text"
#define SYMTAB_SECTION_NAME ".symtab"
#define NOTE_STAPSDT_STR	".note.stapsdt"

/*
 * Default value of MAXSTRINGLEN in SystemTap is 128 but this value can be
 * changed by the user.
 * TODO Change value of MAX_STR_LEN from 128 to 256 to match value of
 * LTTNG_SYMBOL_NAME_LEN?
 */
#define MAX_STR_LEN	128
#define ARRAY_LEN(a)	(sizeof(a) / sizeof(a[0]))

#define init_elf_data(elf_data, buf, size)		\
	do {										\
		memset(&elf_data, 0, sizeof(elf_data)); \
		elf_data.d_buf = buf;					\
		elf_data.d_type = ELF_T_ADDR;			\
		elf_data.d_version = EV_CURRENT;		\
		elf_data.d_size = size;					\
	} while (0)
/*
 * Find the header of the section of the section name passed as argument if any.
 * On success, return zero and set the elf_section_hdr to the search section's
 * header.
 * Return error if ELF handle, section name and section header output parameter
 * are NULL;
 */
static Elf_Scn *
get_elf_section(Elf *elf_handle, const char *section_name)
{
	char *cur_section_name = NULL;
	Elf_Scn *elf_section = NULL;
	GElf_Shdr elf_section_hdr;
	size_t section_idx = 0;
	int ret = 0;

	if (!elf_handle || !section_name) {
		ERR("Invalid argument to find elf section");
		elf_section = NULL;
		goto error;
	}

	ret = elf_getshdrstrndx(elf_handle, &section_idx);
	if (ret) {
		ERR("ELF get header index failed: %s.", elf_errmsg(-1));
		elf_section = NULL;
		goto error;
	}

	while((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL) {
		/*
		 * Get the section header from the section object
		 */
		if (gelf_getshdr(elf_section, &elf_section_hdr) == NULL) {
			ERR("GELF get section header failed: %s.", elf_errmsg(-1));
			elf_section = NULL;
			goto error;
		}

		/*
		 * Get the name of the current section
		 */
		cur_section_name = elf_strptr(elf_handle, section_idx,
								  elf_section_hdr.sh_name);

		if (cur_section_name == NULL) {
			ERR("ELF retrieve string pointer failed: %s.", elf_errmsg(-1));
			elf_section = NULL;
			goto error;
		}

		/*
		 * Compare the name of the current section and the name of the target
		 * section. If there is a match return success directly.
		 */
		if (strncmp(cur_section_name, section_name, MAX_STR_LEN) == 0) {
			break;
		}
	}

error:
	return elf_section;
}

/*
 * Convert the virtual address in a binary's mapping to the offset of
 * the corresponding instruction in the binary file.
 *
 * Returns the offset on success or -1 in case of failure.
 */

static long convert_addr_to_offset(Elf *elf_handle, size_t addr)
{
	long ret;
	size_t text_section_offset, text_section_addr, offset_in_section;
	Elf_Scn *text_section = NULL;
	GElf_Shdr text_section_hdr;

	if (!elf_handle) {
		ERR("Invalid ELF handle.");
		ret = -1;
		goto error;
	}

	/* Get a pointer to the .text section */
	text_section = get_elf_section(elf_handle, TEXT_SECTION_NAME);
	if (text_section == NULL) {
		ERR("Text section not found in binary.");
		goto error;
	}

	/* Get the header of the .text section */
	if (gelf_getshdr(text_section, &text_section_hdr) == NULL) {
		ERR("GELF get section header failed: %s.", elf_errmsg(-1));
		ret = -1;
		goto error;
	}

	text_section_offset = text_section_hdr.sh_offset;
	text_section_addr = text_section_hdr.sh_addr;

	/*
	 * To find the offset of the addr from the beginning of the .text
	 * section.
	 */
	if (text_section_addr > addr) {
		ERR("Invalid section address found: addr=%zux, "
			"text_section_addr=%zux.", addr, text_section_addr);
		ret = -1;
		goto error;
	}
	offset_in_section = addr - text_section_addr;

	/*
	 * Add the offset in the section to the offset of the section from the
	 * beginning of the binary file.
	 */
	ret = text_section_offset + offset_in_section;

error:
	return ret;
}

static long
get_sdt_probe_addr(Elf *elf_handle, Elf_Scn *stap_note_section,
				   const char *probe_provider, const char *probe_name)
{
	/*
	 * System is assumed to be 64 bit.
	 * TODO Add support for 32 bit systems.
	 * TODO Change probe_data array to probe_addr and only translate
	 * the address. At the moment the array has 3 elements to have
	 * room for all the probe data but only the address is used.
	 * The probe data contains the address of the probe, the base address of the
	 * notes and the address of the semaphore for this probe
	 */
	Elf64_Addr probe_data[3];
	char *section_data_ptr = NULL;
	char *elf_format = NULL;
	char *note_probe_provider_name = NULL;
	char *note_probe_name = NULL;
	size_t next_note_offset;
	size_t curr_note_offset;
	size_t note_name_offset;
	size_t note_desc_offset;
	size_t probe_data_size;
	bool probe_found = false;
	int ret;
	GElf_Nhdr note_hdr;
	Elf_Data probe_data_in_file;
	Elf_Data probe_data_in_mem;
	Elf_Data *stap_note_section_data_desc = NULL;

	stap_note_section_data_desc = elf_getdata(stap_note_section, NULL);
	if (stap_note_section_data_desc == NULL) {
		ERR("ELF get data failed: %s.", elf_errmsg(-1));
		ret = -1;
		goto error;
	}

	/*
	 * Will contain the in-file and in-memory representations of the
	 * probe data.
	 */
	probe_data_size = gelf_fsize(elf_handle, ELF_T_ADDR, ARRAY_LEN(probe_data),
								 EV_CURRENT);

	init_elf_data(probe_data_in_mem, &probe_data, probe_data_size);
	init_elf_data(probe_data_in_file, NULL, probe_data_size);

	section_data_ptr = (char *) stap_note_section_data_desc->d_buf;

	curr_note_offset = 0;
	next_note_offset = gelf_getnote(stap_note_section_data_desc,
							 curr_note_offset,
							 &note_hdr,
							 &note_name_offset,
							 &note_desc_offset);

	/*
	 * Search in the stap note section for a probe description
	 * matching the requested probe provider and probe name.
	 */
	while (next_note_offset > 0) {
		/*
		 * Set source of data to be translated to the beginning
		 * of the current note's data.
		 */
		probe_data_in_file.d_buf = section_data_ptr + note_desc_offset;

		/*
		 * Translate ELF data to in-memory representation in
		 * order to respect byte ordering and data alignment
		 * restrictions of the host processor.
		 */
		elf_format = elf_getident(elf_handle, NULL);
		if (gelf_xlatetom(elf_handle, &probe_data_in_mem, &probe_data_in_file,
						  elf_format[EI_DATA]) == NULL) {
			ERR("GELF Translation from file to memory representation "
				"failed: %s.", elf_errmsg(-1));
			ret = -1;
			goto error;
		}

		/*
		 * Retrieve the provider and name of the probe in the
		 * note section. The structure of the data in the note
		 * is defined in the systemtap header (sdt.h).
		 */
		note_probe_provider_name = section_data_ptr + note_desc_offset +
									probe_data_in_mem.d_size;

		note_probe_name = note_probe_provider_name +
							strlen(note_probe_provider_name) + 1;

		/*
		 * Compare curr provider and probe name with requested ones
		 */
		if (strncmp(note_probe_provider_name, probe_provider, MAX_STR_LEN) == 0) {

			if (strncmp(note_probe_name, probe_name, MAX_STR_LEN) == 0) {
				probe_found = true;
				break;
			}
		}

		curr_note_offset = next_note_offset;
		/* Get the info for the next note/iteration*/
		next_note_offset = gelf_getnote(stap_note_section_data_desc,
								 		curr_note_offset,
								 		&note_hdr,
								 		&note_name_offset,
								 		&note_desc_offset);
	}

	if (!probe_found) {
		ERR("No probe with \"%s:%s\" found.", probe_name, probe_provider);
		ret = -1;
		goto error;
	}

	ret = probe_data[0];
error:
	return ret;
}


long userspace_probe_get_sdt_offset(int fd, const char *probe_provider,
		const char *probe_name)
{
	long ret;
	Elf *elf_handle;
	Elf_Scn *stap_note_section = NULL;

	if (probe_provider == NULL || probe_provider[0] == '\0') {
		ERR("Invalid probe provider.");
		ret = -1;
		goto error;
	}

	if (probe_name == NULL || probe_name[0] == '\0') {
		ERR("Invalid probe name.");
		ret = -1;
		goto error;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		ERR("ELF library initialization failed: %s.", elf_errmsg(-1));
		ret = -1;
		goto error;
	}

	elf_handle = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf_handle) {
		ERR("elf_begin() failed: %s.", elf_errmsg (-1));
		ret = -1;
		goto error;
	}

	/*
	 * Get ELF section for stap note section which contains probe
	 * descriptions.
	 */
	stap_note_section = get_elf_section(elf_handle, NOTE_STAPSDT_STR);
	if (stap_note_section == NULL) {
		ERR("Section \"%s\" not found in binary. No SDT probes.",
													NOTE_STAPSDT_STR);
		goto error;
	}

	long addr = get_sdt_probe_addr(elf_handle, stap_note_section,
								   probe_provider, probe_name);
	if (addr < 0) {
		ERR("Error retrieving probe from stap note in  binary.");
		ret = -1;
		goto error_free;
	}

	ret = convert_addr_to_offset(elf_handle, addr);
	if (ret == -1) {
		ERR("Conversion from address to offset in binary failed. "
			"Address: %lu\n", addr);
		ret = -1;
		goto error_free;
	}

error_free:
	elf_end(elf_handle);
error:
	return ret;
}

long userspace_probe_get_elf_function_offset(int fd, const char *func_name)
{
	long ret;
	char *sym_name;
	int sym_count;
	int sym_idx;
	bool sym_found;
	Elf *elf_handle;
	Elf_Scn *symtab_section = NULL;
	GElf_Shdr symtab_section_hdr;
	Elf_Data *symtab_section_data_desc = NULL;
	GElf_Sym sym;

	if (func_name == NULL || func_name[0] == '\0') {
		ERR("Invalid function name.");
		ret = -1;
		goto error;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		ERR("ELF library initialization failed: %s.", elf_errmsg(-1));
		ret = -1;
		goto error;
	}

	elf_handle = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf_handle) {
		ERR("elf_begin() failed: %s.", elf_errmsg (-1));
		ret = -1;
		goto error;
	}

	/* Get a pointer to the .text section */
	symtab_section = get_elf_section(elf_handle, SYMTAB_SECTION_NAME);
	if (symtab_section == NULL) {
		ERR("symtab section not found in binary.");
		goto error_free;
	}

	/* Get the header of the .text section */
	if (gelf_getshdr(symtab_section, &symtab_section_hdr) == NULL) {
		ERR("GELF get symtab section header failed: %s.", elf_errmsg(-1));
		ret = -1;
		goto error_free;
	}

	symtab_section_data_desc = elf_getdata(symtab_section, NULL);
	if (symtab_section_data_desc == NULL) {
		ERR("ELF get symtab data failed: %s.", elf_errmsg(-1));
		ret = -1;
		goto error_free;
	}

	sym_count = symtab_section_hdr.sh_size / symtab_section_hdr.sh_entsize;
	sym_name = NULL;
	sym_found = false;

	/*
	 * Loop over all symbols in symbol table and compare them
	 * against the requested symbol.
	 */
	for (sym_idx = 0; sym_idx < sym_count; sym_idx++) {
		if (gelf_getsym(symtab_section_data_desc, sym_idx, &sym) ==
			NULL) {
			ERR("GELF get symbol failed: %s.", elf_errmsg(-1));
			ret = -1;
			goto error_free;
		}

		/*
		 * Get the name of the symbol at this index
		 */
		sym_name = elf_strptr(elf_handle, symtab_section_hdr.sh_link,
							  sym.st_name);
		if (sym_name == NULL) {
			ERR("ELF retrieve string pointer failed: %s.", elf_errmsg(-1));
			ret = -1;
			goto error_free;
		}

		/*
		 * Compare the name of the symbol with the searched symbol
		 */
		if (strncmp(sym_name, func_name, MAX_STR_LEN) == 0) {
			sym_found = true;
			break;
		}
	}

	if (!sym_found) {
		ERR("Requested symbol \"%s\" does not exist in symbol table.", \
			func_name);
		ret = -1;
		goto error_free;
	}

	/*
	 * Check if the found symbol is a function
	 */
	if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) {
		ERR("Requested symbol \"%s\" does not refer to a function.", \
			func_name);
		ret = -1;
		goto error_free;
	}

	/*
	 * Convert the address of the symbol to the offset from the beginning of the
	 * file
	 */
	ret = convert_addr_to_offset(elf_handle, sym.st_value);
	if (ret == -1) {
		ERR("Conversion from address to offset in binary file failed. "
			"Address: %lu", sym.st_value);
		ret = -1;
		goto error_free;
	}

error_free:
	elf_end(elf_handle);
error:
	return ret;
}
