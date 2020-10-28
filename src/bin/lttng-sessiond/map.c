/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */


#include "lttng/domain.h"
#include <common/kernel-ctl/kernel-ctl.h>
#include <lttng/map/map.h>
#include <lttng/map/map-internal.h>

#include "lttng-sessiond.h"
#include "lttng-ust-error.h"
#include "notification-thread-commands.h"
#include "trace-kernel.h"
#include "trace-ust.h"

#include "map.h"

enum lttng_error_code map_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_map *map)
{
	enum lttng_error_code ret;
	struct ltt_kernel_map *kmap;
	enum lttng_map_status map_status;
	const char *map_name;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_KERNEL);

	map_status = lttng_map_get_name(map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Can't get map name");
		ret = -1;
		goto error;
	}

	kmap = trace_kernel_get_map_by_name(map_name, ksession);
	if (kmap) {
		DBG("Kernel map named \"%s\" already present", map_name);
		ret = -1;
		goto error;
	}

	kmap = trace_kernel_create_map(map);
	assert(kmap);

	ret = kernctl_create_session_counter(ksession->fd,
			&kmap->counter_conf);
	if (ret < 0) {
		PERROR("ioctl kernel create session counter");
		goto error;
	}

	kmap->fd = ret;

	/* Prevent fd duplication after execlp() */
	ret = fcntl(kmap->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session counter fd");
		goto error;
	}

	kmap->map = map;
	lttng_map_get(map);
	cds_list_add(&kmap->list, &ksession->map_list.head);
	ksession->map_count++;

	DBG("Kernel session counter created (fd: %d)", kmap->fd);

	ret = kernctl_enable(kmap->fd);
	if (ret < 0) {
		PERROR("Enable kernel map");
	}

	ret = LTTNG_OK;
error:
	return ret;
}

enum lttng_error_code map_kernel_enable(struct ltt_kernel_session *ksess,
		struct ltt_kernel_map *kmap)
{
	enum lttng_error_code ret = LTTNG_OK;
	const char *map_name;
	enum lttng_map_status map_status;


	assert(ksess);
	assert(kmap);

	map_status = lttng_map_get_name(kmap->map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Error getting kernel map name");
		ret = -1;
		goto end;
	}

	/* If already enabled, everything is OK */
	if (kmap->enabled) {
		DBG3("Map %s already enabled. Skipping", map_name);
		ret = LTTNG_ERR_UST_MAP_EXIST;
		goto end;
	} else {
		kmap->enabled = 1;
		lttng_map_set_is_enabled(kmap->map, true);
		DBG2("Map %s enabled successfully", map_name);
	}

	DBG2("Map %s being enabled in kernel domain", map_name);

	/*
	 * Enable map for UST global domain on all applications. Ignore return
	 * value here since whatever error we got, it means that the map was
	 * not created on one or many registered applications and we can not report
	 * this to the user yet. However, at this stage, the map was
	 * successfully created on the session daemon side so the enable-map
	 * command is a success.
	 */

	ret = kernctl_enable(kmap->fd);
	if (ret < 0) {
		PERROR("Enable kernel map");
	}

	ret = LTTNG_OK;
end:
	return ret;
}

enum lttng_error_code map_kernel_disable(struct ltt_kernel_session *usess,
		struct ltt_kernel_map *kmap)
{
	enum lttng_error_code ret = LTTNG_OK;
	enum lttng_map_status map_status;
	const char *map_name = NULL;

	assert(usess);
	assert(kmap);

	map_status = lttng_map_get_name(kmap->map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Error getting kernel map name");
		ret = -1;
		goto end;
	}

	/* Already disabled */
	if (kmap->enabled == 0) {
		DBG2("Map kernel %s already disabled", map_name);
		ret = LTTNG_ERR_KERNEL_MAP_EXIST;
		goto end;
	}

	kmap->enabled = 0;
	lttng_map_set_is_enabled(kmap->map, false);

	DBG2("Map %s being disabled in kernel global domain", map_name);

	/* Disable map for global domain */
	ret = kernctl_disable(kmap->fd);
	if (ret < 0) {
		ret = LTTNG_ERR_KERNEL_MAP_DISABLE_FAIL;
		goto error;
	}


	DBG2("Map %s disabled successfully", map_name);

	return LTTNG_OK;

end:
error:
	return ret;
}

int map_ust_add(struct ltt_ust_session *usession, struct lttng_map *map)
{
	int ret = 0;
	struct ltt_ust_map *umap;
	enum lttng_map_status map_status;
	const char *map_name;
	enum lttng_buffer_type buffer_type;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_UST);

	map_status = lttng_map_get_name(map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Can't get map name");
		ret = -1;
		goto end;
	}

	buffer_type = lttng_map_get_buffer_type(map);

	umap = trace_ust_create_map(map);
	assert(umap);

	umap->enabled = 1;
	umap->id = trace_ust_get_next_chan_id(usession);
	umap->map = map;
	lttng_map_get(map);

	lttng_map_set_is_enabled(umap->map, true);

	DBG2("Map %s is being created for UST with buffer type %d and id %" PRIu64,
			umap->name, buffer_type, umap->id);

	/* Flag session buffer type. */
	if (!usession->buffer_type_changed) {
		usession->buffer_type = buffer_type;
		usession->buffer_type_changed = 1;
	} else if (usession->buffer_type != buffer_type) {
		/* Buffer type was already set. Refuse to create channel. */
		ret = LTTNG_ERR_BUFFER_TYPE_MISMATCH;
		goto error_free_map;
	}

	rcu_read_lock();

	/* Adding the map to the map hash table. */
	lttng_ht_add_unique_str(usession->domain_global.maps, &umap->node);

	rcu_read_unlock();

	DBG2("Map %s created successfully", umap->name);

	ret = 0;
	goto end;

error_free_map:
	trace_ust_destroy_map(umap);
end:
	return ret;
}

/*
 * Enable UST map for session and domain.
 */
int map_ust_enable(struct ltt_ust_session *usess,
		struct ltt_ust_map *umap)
{
	int ret = LTTNG_OK;

	assert(usess);
	assert(umap);

	/* If already enabled, everything is OK */
	if (umap->enabled) {
		DBG3("Map %s already enabled. Skipping", umap->name);
		ret = LTTNG_ERR_UST_MAP_EXIST;
		goto end;
	} else {
		umap->enabled = 1;
		lttng_map_set_is_enabled(umap->map, true);
		DBG2("Map %s enabled successfully", umap->name);
	}

	if (!usess->active) {
		/*
		 * The map will be activated against the apps
		 * when the session is started as part of the
		 * application map "synchronize" operation.
		 */
		goto end;
	}

	DBG2("Map %s being enabled in UST domain", umap->name);

	/*
	 * Enable map for UST global domain on all applications. Ignore return
	 * value here since whatever error we got, it means that the map was
	 * not created on one or many registered applications and we can not report
	 * this to the user yet. However, at this stage, the map was
	 * successfully created on the session daemon side so the enable-map
	 * command is a success.
	 */
	(void) ust_app_enable_map_glb(usess, umap);


end:
	return ret;
}

int map_ust_disable(struct ltt_ust_session *usess,
		struct ltt_ust_map *umap)
{
	int ret = LTTNG_OK;

	assert(usess);
	assert(umap);

	/* Already disabled */
	if (umap->enabled == 0) {
		DBG2("Map UST %s already disabled", umap->name);
		ret = LTTNG_ERR_UST_MAP_EXIST;
		goto end;
	}

	umap->enabled = 0;
	lttng_map_set_is_enabled(umap->map, false);

	/*
	 * If session is inactive we don't notify the tracer right away. We
	 * wait for the next synchronization.
	 */
	if (!usess->active) {
		goto end;
	}

	DBG2("Map %s being disabled in UST global domain", umap->name);

	/* Disable map for global domain */
	ret = ust_app_disable_map_glb(usess, umap);
	if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
		ret = LTTNG_ERR_UST_MAP_DISABLE_FAIL;
		goto error;
	}


	DBG2("Map %s disabled successfully", umap->name);

	return LTTNG_OK;

end:
error:
	return ret;
}
