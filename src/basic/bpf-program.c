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

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "bpf-program.h"
#include "log.h"
#include "missing.h"

/* Work around outdated kernel headers. Can be removed once we bump the minimum build requirements. */

#ifndef HAVE_UNION_BPF_ATTR_ATTACH_TYPE
union __bpf_attr {
        struct { /* anonymous struct used by BPF_MAP_CREATE command */
                __u32   map_type;	/* one of enum bpf_map_type */
                __u32   key_size;	/* size of key in bytes */
                __u32   value_size;	/* size of value in bytes */
                __u32   max_entries;	/* max number of entries in a map */
                __u32   map_flags;	/* prealloc or not */
        };

        struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
                __u32           map_fd;
                __aligned_u64   key;
                union {
                        __aligned_u64 value;
                        __aligned_u64 next_key;
                };
                __u64           flags;
        };

        struct { /* anonymous struct used by BPF_PROG_LOAD command */
                __u32           prog_type;	/* one of enum bpf_prog_type */
                __u32           insn_cnt;
                __aligned_u64   insns;
                __aligned_u64   license;
                __u32           log_level;	/* verbosity level of verifier */
                __u32           log_size;	/* size of user buffer */
                __aligned_u64   log_buf;	/* user supplied buffer */
                __u32           kern_version;	/* checked when prog_type=kprobe */
        };

        struct { /* anonymous struct used by BPF_OBJ_* commands */
                __aligned_u64   pathname;
                __u32           bpf_fd;
        };

        struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
                __u32           target_fd;	/* container object to attach to */
                __u32           attach_bpf_fd;	/* eBPF program to attach */
                __u32           attach_type;
        };
} __attribute__((aligned(8)));
#define bpf_attr __bpf_attr
#endif

static uint64_t ptr_to_u64(const void *ptr)
{
        return (uint64_t) (unsigned long) ptr;
}

int bpf_program_new(uint32_t prog_type, BPFProgram **ret) {
        _cleanup_(bpf_program_freep) BPFProgram *p = NULL;

        p = new0(BPFProgram, 1);
        if (!p)
                return log_oom();

        p->prog_type = prog_type;
        p->kernel_id = -1;

        *ret = p;
        p = NULL;
        return 0;
}

int bpf_program_add_instructions(BPFProgram *p, struct bpf_insn *instructions, unsigned count) {

        assert(p);

        if (!GREEDY_REALLOC(p->instructions, p->allocated, (p->n_instructions + count) * sizeof(struct bpf_insn)))
                return log_oom();

        memcpy(p->instructions + p->n_instructions, instructions, sizeof(struct bpf_insn) * count);
        p->n_instructions += count;

        return 0;
}

int bpf_program_load_kernel(BPFProgram *p, char *log_buf, size_t log_size) {

        int r;
        union bpf_attr attr = {
                .prog_type = p->prog_type,
                .insns = ptr_to_u64((void *) p->instructions),
                .insn_cnt = p->n_instructions,
                .license = ptr_to_u64((void *) "GPL"),
                .log_buf = ptr_to_u64(log_buf),
                .log_size = log_size,
                .kern_version = 0,
        };

        assert(p);

	/*
         * Assign one field outside of struct init to make sure any
         * padding is zero initialized
         */
        attr.log_level = log_buf ? 1 : 0;

        r = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
        if (r < 0)
                return -errno;

        p->kernel_id = r;

        return 0;
}

int bpf_program_cgroup_attach(BPFProgram *p, int type, const char *cg_path) {

        int r, cg_fd;
        union bpf_attr attr;

        assert(p);
        assert(type >= 0);
        assert(cg_path);

        cg_fd = open(cg_path, O_DIRECTORY | O_RDONLY);
        if (cg_fd < 0)
                return -errno;

        bzero(&attr, sizeof(attr));
        attr.attach_type = type;
        attr.target_fd = cg_fd;
        attr.attach_bpf_fd = p->kernel_id;

        r = syscall(__NR_bpf, BPF_PROG_ATTACH, &attr, sizeof(attr));
        if (r < 0)
                r = -errno;

        close(cg_fd);

        return r;
}

int bpf_program_cgroup_detach(const char *cg_path) {

        int r, cg_fd;
        union bpf_attr attr;

        assert(cg_path);

        cg_fd = open(cg_path, O_DIRECTORY | O_RDONLY);
        if (cg_fd < 0)
                return -errno;

        bzero(&attr, sizeof(attr));
        attr.target_fd = cg_fd;

        r = syscall(__NR_bpf, BPF_PROG_DETACH, &attr, sizeof(attr));
        if (r < 0)
                r = -errno;

        close(cg_fd);

        return r;
}

BPFProgram *bpf_program_free(BPFProgram *p) {
        if (!p)
                return NULL;

        if (p->kernel_id >= 0)
                close(p->kernel_id);

        free(p->instructions);
        free(p);

        return NULL;
}

/* BPF map helpers */

int bpf_map_create(enum bpf_map_type type, size_t key_size, size_t value_size, size_t max_entries) {

        int r;
        union bpf_attr attr = {
                .map_type = type,
                .key_size = key_size,
                .value_size = value_size,
                .max_entries = max_entries,
                .map_flags = 0,
        };

        r = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
        return (r < 0) ? -errno : r;
}

int bpf_update_elem(int fd, void *key, void *value) {

        int r;
        union bpf_attr attr = {
                .map_fd = fd,
                .key = ptr_to_u64(key),
                .value = ptr_to_u64(value),
                .flags = 0,
        };

        r = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
        return (r < 0) ? -errno : 0;
}

int bpf_map_lookup_elem(int fd, void *key, void *value) {

        int r;
        union bpf_attr attr = {
                .map_fd = fd,
                .key = ptr_to_u64(key),
                .value = ptr_to_u64(value),
        };

        r = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
        return (r < 0) ? -errno : 0;
}
