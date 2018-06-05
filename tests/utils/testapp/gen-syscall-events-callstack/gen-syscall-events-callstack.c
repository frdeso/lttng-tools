/*
 * Copyright (C) - 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

/**
 * The process waits for the creation of a file passed as argument from an
 * external processes to execute a syscall and exiting. This is useful for tests
 * in combinaison with LTTng's PID tracker feature where we can trace the kernel
 * events generated by our test process only.
 */

volatile int val = 0;

long __attribute__ ((noinline))
my_gettid(void)
{
    long ret;
    asm volatile
    (
        "syscall"
        : "=a" (ret)
        : "0"(__NR_gettid)
        : "cc", "rcx", "r11", "memory"
    );
    return ret;
}

int __attribute__ ((noinline))
fct_c(void)
{
	return my_gettid();
}

int __attribute__ ((noinline))
fct_b(void)
{
	val += fct_c();
	return val;
}

int __attribute__ ((noinline))
fct_a(void)
{
	val += fct_b();
	return val;
}

int main(int argc, char **argv)
{
	int ret = 0;
	char *start_file;

	if (argc != 2) {
		fprintf(stderr, "Error: Missing argument\n");
		fprintf(stderr, "USAGE: %s PATH_WAIT_FILE\n", argv[0]);
		ret = -1;
		goto error;
	}

	start_file = argv[1];

	/*
	 * Wait for the start_file to be created by an external process
	 * (typically the test script) before executing the syscall
	 */
	ret = wait_on_file(start_file);
	if (ret != 0) {
		goto error;
	}

	/* Start the callchain to the syscall */
	ret = fct_a();

	/* Return success */
	if (ret >= 0) {
		ret = 0;
	}

error:
	return ret;
}