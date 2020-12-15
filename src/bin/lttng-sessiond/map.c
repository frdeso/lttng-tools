#include <lttng/map/map.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include "trace-kernel.h"

#include "map.h"

int map_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_map *map)
{
	int ret = 0;
	struct ltt_kernel_map *kernel_map;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_KERNEL);

	kernel_map = trace_kernel_create_map(map);

	ret = kernctl_create_session_counter(ksession->fd, &kernel_map->counter_conf);
	if (ret < 0) {
		PERROR("ioctl kernel create session counter");
		goto error;
	}

	kernel_map->fd = ret;

	/* Prevent fd duplication after execlp() */
	ret = fcntl(kernel_map->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session counter fd");
		goto error;
	}

	kernel_map->map = map;
	cds_list_add(&kernel_map->list, &ksession->map_list.head);
	ksession->map_count++;

	DBG("Kernel session counter created (fd: %d)", kernel_map->fd);

	ret = kernctl_enable(kernel_map->fd);
	if (ret < 0) {
		PERROR("enable kernel event");
	}

error:
	return ret;
}