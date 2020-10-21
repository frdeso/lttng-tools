
#include <lttng/map/map.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include "trace-kernel.h"

#include "map.h"

int map_kernel_add(struct ltt_kernel_session *ksession,
		const struct lttng_map *map)
{
	int ret = 0;
	struct ltt_kernel_counter *kernel_counter;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_KERNEL);

	kernel_counter = trace_kernel_create_counter(map);

	ret = kernctl_create_session_counter(ksession->fd, &kernel_counter->counter_conf);
	if (ret < 0) {
		PERROR("ioctl kernel create session counter");
		goto error;
	}

	 kernel_counter->fd = ret;

	/* Prevent fd duplication after execlp() */
	ret = fcntl(kernel_counter->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session counter fd");
		goto error;
	}


	cds_list_add(&kernel_counter->list, &ksession->counter_list.head);

	DBG("Kernel session counter created (fd: %d)", kernel_counter->fd);

error:
	return ret;
}
