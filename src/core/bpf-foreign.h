/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include "unit.h"

int bpf_foreign_supported(void);
/*
 * Attach cgroup-bpf programs foreign to systemd, i.e. loaded to the kernel by an entity
 * external to systemd.
 */
int bpf_foreign_install(Unit *u);
