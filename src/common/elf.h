#ifndef _lttng_ELF_H
#define _lttng_ELF_H
/*
 * Copyright (C) 2017  Francis Deslauriers <francis.deslauriers@efficios.com>
 *                     Erica Bugden <erica.bugden@efficios.com>
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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <byteswap.h>
#include <assert.h>
#include <elf.h>

struct lttng_elf {
	/* Offset in bytes to start of section names string table. */
	off_t section_names_offset;
	/* Size in bytes of section names string table. */
	size_t section_names_size;
	int fd;
	struct lttng_elf_ehdr *ehdr;
	uint8_t bitness;
	uint8_t endianness;
	uint8_t version;
};


struct lttng_elf *lttng_elf_create(int fd);
void lttng_elf_destroy(struct lttng_elf *elf);
char *lttng_elf_get_section_name(struct lttng_elf *elf, off_t offset);
int lttng_elf_get_symbol_offset(struct lttng_elf *elf,
							 char *symbol,
							 uint64_t *offset);
#endif	/* _lttng_ELF_H */
