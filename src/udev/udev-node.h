/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "sd-device.h"

#include "hashmap.h"

int udev_node_add(sd_device *dev, bool apply,
                  mode_t mode, uid_t uid, gid_t gid,
                  OrderedHashmap *seclabel_list);
int udev_node_remove(sd_device *dev);
int udev_node_update_old_links(sd_device *dev, sd_device *dev_old);

size_t udev_node_escape_path(const char *src, char *dest, size_t size);
