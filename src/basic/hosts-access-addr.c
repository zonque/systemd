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

#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "hosts-access-addr.h"
#include "parse-util.h"

int config_parse_hosts_access_address(const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        HostsAccessAddress **list = data;
        const char *p;

        assert(list);

        p = rvalue;

        for (;;) {
                _cleanup_free_ HostsAccessAddress *a = NULL;
                _cleanup_free_ char *word = NULL;
                const char *address, *e;
                int r;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        break;
                }

                a = new0(HostsAccessAddress, 1);
                if (!a)
                        return log_oom();

                e = strchr(word, '/');
                if (e) {
                        unsigned i;

                        r = safe_atou(e + 1, &i);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, r, "Prefix length is invalid, ignoring assignment: %s", e + 1);
                                return 0;
                        }

                        a->prefixlen = (unsigned char) i;

                        address = strndupa(word, e - word);
                } else
                        address = word;

                r = in_addr_from_string_auto(address, &a->family, &a->addr);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Address is invalid, ignoring assignment: %s", address);
                        return 0;
                }

                if (a->family == AF_UNSPEC) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Address is incompatible, ignoring assignment: %s", address);
                        return 0;
                }

                /* If no subnet is given, take the address as host address (ie, fully masked) */
                if (!e)
                        a->prefixlen = a->family == AF_INET ? 32 : 128;

                LIST_APPEND(address, *list, a);
                a = NULL;
        }

        return 0;
}
