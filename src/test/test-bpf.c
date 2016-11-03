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

#include <string.h>
#include <unistd.h>

#include "bpf-program.h"
#include "firewall.h"
#include "manager.h"
#include "service.h"
#include "unit.h"

int main(int argc, char *argv[]) {

        struct bpf_insn exit_insn[] = {
                BPF_MOV64_IMM(BPF_REG_0, 1),
                BPF_EXIT_INSN()
        };

        CGroupContext *cc = NULL;
        BPFProgram *p = NULL;
        Manager *m = NULL;
        Unit *u;

        char log_buf[65535];
        int r;

        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB, &p);
        assert(r == 0);

        r = bpf_program_add_instructions(p, exit_insn, ELEMENTSOF(exit_insn));
        assert(r == 0);

        if (getuid() != 0) {
                printf("Not running as root, skipping kernel related tests.\n");
                return 0;
        }

        r = bpf_program_load_kernel(p, log_buf, ELEMENTSOF(log_buf));
        if (r == -EINVAL) {
                printf("BPF load failed, kernel too old? Ignoring.\n");
                return 0;
        }

        bpf_program_free(p);

        /* The simple tests suceeded. Now let's try full unit-based use-case. */

        assert_se(manager_new(UNIT_FILE_USER, true, &m) >= 0);
        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, "foo.service") == 0);
        assert_se(cc = unit_get_cgroup_context(u));

        cc->ip_accounting = true;

        assert_se(config_parse_hosts_access_address(u->id, "filename", 1, "Service", 1, "HostsAllow", 0, "10.0.1.0/24", &cc->ip_hosts_allow, NULL) == 0);
        assert_se(config_parse_hosts_access_address(u->id, "filename", 1, "Service", 1, "HostsDeny", 0, "10.0.3.0/24", &cc->ip_hosts_deny, NULL) == 0);

        assert(cc->ip_hosts_allow != NULL);

        assert_se(firewall_compile_for_cgroup_context(cc) >= 0);
        assert(cc->ip_bpf_ingress != NULL);

        r = bpf_program_load_kernel(cc->ip_bpf_ingress, log_buf, ELEMENTSOF(log_buf));

        printf("log:\n");
        printf("-------\n");
        printf("%s", log_buf);
        printf("-------\n");

        assert(r >= 0);

        return 0;
}
