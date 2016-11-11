#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Daniel Mack

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "hosts-access-addr.h"

typedef struct CGroupContext CGroupContext;

int firewall_compile_for_cgroup_context(CGroupContext *cc);
int firewall_install_for_cgroup_context(CGroupContext *cc, const char *cg_path);

int firewall_read_accounting(int map_fd, uint64_t *ret_bytes, uint64_t *ret_packets);
