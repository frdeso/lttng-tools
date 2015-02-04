/*
 * Copyright (c) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/signal.h>

#include <common/common.h>
#include <common/utils.h>
#include <lttng/handle.h>
#include <lttng/session.h>

#define NR_HANDLES	2

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP	128
#endif

static
long ptrace_setup(pid_t pid)
{
	long ptrace_ret;
	unsigned long flags;

	flags = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT
		| PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
		| PTRACE_O_TRACEEXEC;
	//ptrace_ret = ptrace(PTRACE_SETOPTIONS, pid,
	ptrace_ret = ptrace(PTRACE_SEIZE, pid,
		NULL, (void *) flags);
	if (ptrace_ret) {
		//PERROR("ptrace setoptions");
		PERROR("ptrace seize");
		return -1;
	}
	return 0;
}

static
int wait_on_children(pid_t top_pid, struct lttng_handle **handle,
		size_t nr_handles)
{
	pid_t pid;
	long ptrace_ret;
	int ret, i;

	pid = top_pid;
	DBG("Setup ptrace options on top child pid %d", pid);
	ret = ptrace_setup(pid);
	if (ret) {
		return ret;
	}
	for (i = 0; i < NR_HANDLES; i++) {
		ret = lttng_track_pid(handle[i], pid);
		if (ret && ret != -LTTNG_ERR_INVALID) {
			ERR("Error %d tracking pid %d", ret, pid);
		}
	}
	top_pid = -1;
	/* Restart initial raise(SIGSTOP) */
	//ptrace_ret = ptrace(PTRACE_CONT, pid, 0, restartsig);
	//TODO wait for child to have stopped....
	ret = kill(pid, SIGCONT);
	if (ret) {
	//if (ptrace_ret) {
		PERROR("kill");
		abort();
	}

	for (;;) {
		int status;

		pid = waitpid(-1, &status, __WALL);
		DBG("Activity on child pid %d", pid);
		if (pid < 0) {
			if (errno == ECHILD) {
				/* No more children to possibly wait for. */
				return 0;
			} else {
				PERROR("waitpid");
				return -1;
			}
		} else if (pid == 0) {
			ERR("Unexpected PID 0");
			abort();
		} else {
			if (WIFSTOPPED(status)) {
				int shiftstatus, restartsig;

				DBG("Child pid %d is stopped", pid);
				shiftstatus = status >> 8;
				if (shiftstatus == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
					DBG("Child pid %d is exiting", pid);
					for (i = 0; i < NR_HANDLES; i++) {
						ret = lttng_untrack_pid(handle[i], pid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d untracking pid %d", ret, pid);
						}
					}
				} else if (shiftstatus == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
					long newpid;

					ptrace_ret = ptrace(PTRACE_GETEVENTMSG, pid, 0, &newpid);
					if (ptrace_ret) {
						PERROR("ptrace");
						abort();
					}
					DBG("Child pid %d is forking, child pid %ld", pid, newpid);
					for (i = 0; i < NR_HANDLES; i++) {
						ret = lttng_track_pid(handle[i], newpid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d tracking pid %ld", ret, newpid);
						}
					}
				} else if (shiftstatus == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
					long newpid;

					ptrace_ret = ptrace(PTRACE_GETEVENTMSG, pid, 0, &newpid);
					if (ptrace_ret) {
						PERROR("ptrace");
						abort();
					}
					DBG("Child pid %d issuing vfork, child pid %ld", pid, newpid);
					for (i = 0; i < NR_HANDLES; i++) {
						ret = lttng_track_pid(handle[i], newpid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d tracking pid %ld", ret, newpid);
						}
					}
				} else if (shiftstatus == (SIGTRAP | PTRACE_EVENT_CLONE << 8)) {
					long newpid;

					ptrace_ret = ptrace(PTRACE_GETEVENTMSG, pid, 0, &newpid);
					if (ptrace_ret) {
						PERROR("ptrace");
						abort();
					}
					DBG("Child pid %d issuing clone, child pid %ld", pid, newpid);
					for (i = 0; i < NR_HANDLES; i++) {
						ret = lttng_track_pid(handle[i], newpid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d tracking pid %ld", ret, newpid);
						}
					}
				} else if (shiftstatus == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
					long oldpid;

					ptrace_ret = ptrace(PTRACE_GETEVENTMSG, pid, 0, &oldpid);
					if (ptrace_ret) {
						PERROR("ptrace");
						abort();
					}
					DBG("Child pid (old: %ld, new: %d) is issuing exec",
							oldpid, pid);
					for (i = 0; i < NR_HANDLES; i++) {
						ret = lttng_untrack_pid(handle[i], oldpid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d untracking pid %ld", ret, oldpid);
						}
						ret = lttng_track_pid(handle[i], pid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d tracking pid %d", ret, pid);
						}
					}
				} else if (shiftstatus == SIGTRAP) {
					DBG("Received SIGTRAP from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGSTOP) {
					DBG("Received SIGSTOP from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGSEGV) {
					DBG("Received SIGSEGV from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGTTIN) {
					DBG("Received SIGTTIN from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGTTOU) {
					DBG("Received SIGTTOU from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGTSTP) {
					DBG("Received SIGTSTP from pid %d without event of interest", pid);
				} else {
					DBG("Ignoring signal %d (status %d) from pid %d (eventcode = %u)",
						WSTOPSIG(status), status, pid,
						(shiftstatus & ~WSTOPSIG(status)) >> 8);
				}

				restartsig = WSTOPSIG(status);
				switch (restartsig) {
				case SIGTSTP:
				case SIGTTIN:
				case SIGTTOU:
				case SIGSTOP:
				{
					siginfo_t siginfo;

					errno = 0;
					//ptrace_ret = ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
					//if (ptrace_ret < 0 && errno == EINVAL) {
					if (restartsig == SIGTTIN) {
						ret = kill(pid, SIGTTIN);
						if (ret) {
							PERROR("kill");
							abort();
						}
					} else if (status >> 16 == PTRACE_EVENT_STOP) {
						DBG("ptrace stop");
						//ptrace_ret = ptrace(PTRACE_LISTEN, pid, 0, 0);
						ptrace_ret = ptrace(PTRACE_CONT, pid, 0, 0);
						if (ptrace_ret) {
							PERROR("ptrace listen");
							abort();
						}
					} else {
						DBG("job control stop ret %ld errno %d", ptrace_ret, errno);
						/*
						 * It's not a group-stop, so restart process,
						 * skipping the signal.
						 */
						//ptrace_ret = ptrace(PTRACE_CONT, pid, 0, 0);
						//if (ptrace_ret) {
						//	PERROR("ptrace cont");
						//	abort();
						//}
					}
					break;
				}
				case SIGTRAP:
				{
					unsigned long data;

					//if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data) == 0) {
						/*
						 * Restart process skipping the signal when
						 * receiving a message.
						 */
						ptrace_ret = ptrace(PTRACE_CONT, pid, 0, 0);
						if (ptrace_ret) {
							PERROR("ptrace");
							abort();
						}
						break;
					//}
				}
					/* Fall-through */
				default:
					/* Restart with original signal. */
					ptrace_ret = ptrace(PTRACE_CONT, pid, 0, restartsig);
					if (ptrace_ret) {
						PERROR("ptrace");
						abort();
					}
				}
			} else if (WIFEXITED(status)) {
				DBG("Child pid %d has exited", pid);
				for (i = 0; i < NR_HANDLES; i++) {
					ret = lttng_untrack_pid(handle[i], pid);
					if (ret && ret != -LTTNG_ERR_INVALID) {
						ERR("Error %d tracking pid %d", ret, pid);
					}
				}
			}
		}
	}
}

static
int run_child(int argc, char **argv)
{
	pid_t pid;
	int ret;

	if (argc < 2) {
		ERR("Please provide executable name as first argument.");
		return -1;
	}

	pid = fork();
	if (pid > 0) {
		/* In parent */
		DBG("Child process created (pid: %d)", pid);
	} else if (pid == 0) {
		/* In child */
		long ptraceret;
#if 0
		ptraceret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if (ptraceret) {
			PERROR("ptrace");
			exit(EXIT_FAILURE);
		}
#endif
		ret = raise(SIGSTOP);
		if (ret) {
			PERROR("raise");
			exit(EXIT_FAILURE);
		}
		ret = execvp(argv[1], &argv[1]);
		if (ret) {
			PERROR("execvp");
			exit(EXIT_FAILURE);
		}
	} else {
		PERROR("fork");
		return -1;
	}
	return pid;
}


static
struct lttng_handle *create_kernel_handle(void)
{
	struct lttng_domain domain;
	char *session_name = "TEST-PTRACE";

	memset(&domain, 0, sizeof(domain));
	domain.type = LTTNG_DOMAIN_KERNEL;
	domain.buf_type = LTTNG_BUFFER_GLOBAL;
	return lttng_create_handle(session_name, &domain);
}

static
struct lttng_handle *create_ust_handle(void)
{
	struct lttng_domain domain;
	char *session_name = "TEST-PTRACE";

	memset(&domain, 0, sizeof(domain));
	domain.type = LTTNG_DOMAIN_UST;
	domain.buf_type = LTTNG_BUFFER_PER_UID;
	return lttng_create_handle(session_name, &domain);
}

int main(int argc, char **argv)
{
	int retval = 0, ret;
	pid_t pid;
	struct lttng_handle *handle[NR_HANDLES];

	//TODO: parse args.
	lttng_opt_verbose = 3;

	pid = run_child(argc, argv);
	if (pid <= 0) {
		retval = -1;
		goto end;
	}

	handle[0] = create_kernel_handle();
	if (!handle[0]) {
		retval = -1;
		goto end;
	}
	handle[1] = create_ust_handle();
	if (!handle[1]) {
		retval = -1;
		goto end_ust_handle;
	}

	ret = wait_on_children(pid, handle, NR_HANDLES);
	if (ret) {
		retval = -1;
		goto end_wait_on_children;
	}


end_wait_on_children:
	lttng_destroy_handle(handle[1]);
end_ust_handle:
	lttng_destroy_handle(handle[0]);
end:
	if (retval) {
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
	return 0;
}
