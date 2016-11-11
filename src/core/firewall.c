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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ethernet.h>
#include <net/if.h>

#include "alloc-util.h"
#include "bpf-program.h"
#include "firewall.h"
#include "hosts-access-addr.h"
#include "unit.h"

enum {
        MAP_KEY_PACKETS,
        MAP_KEY_BYTES,
};

enum {
        ACCESS_ALLOWED = 1,
        ACCESS_DENIED  = 2,
};

/* Compile instructions for one list of addresses, one direction and one specific verdict on matches. */

static int add_lookup_instructions(
                BPFProgram *p,
                int map_fd,
                int protocol,
                bool is_ingress,
                int verdict) {

        int r, addr_offset, addr_size;

        assert(p);
        assert(map_fd >= 0);

        switch (protocol) {
        case ETH_P_IP:
                addr_size = sizeof(uint32_t);
                addr_offset = is_ingress ?
                        offsetof(struct iphdr, saddr) :
                        offsetof(struct iphdr, daddr);
                break;

        case ETH_P_IPV6:
                addr_size = 2 * sizeof(uint64_t);
                addr_offset = is_ingress ?
                        offsetof(struct ipv6hdr, saddr.s6_addr) :
                        offsetof(struct ipv6hdr, daddr.s6_addr);
                break;

        default:
                return -EINVAL;
        }

        do {
                /* Compare IPv4 with one word instruction (32bit) */
                struct bpf_insn insn[] = {
                        /* If skb->protocol != ETH_P_IP, skip this whole block. The offset will be set later. */
                        BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htons(protocol), 0),

                        /*
                         * Call into BPF_FUNC_skb_load_bytes to load the dst/src IP address
                         *
                         * R1: Pointer to the skb
                         * R2: Data offset
                         * R3: Destination buffer on the stack (r10 - 4)
                         * R4: Number of bytes to read (4)
                         */

                        BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
                        BPF_MOV32_IMM(BPF_REG_2, addr_offset),

                        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -addr_size),

                        BPF_MOV32_IMM(BPF_REG_4, addr_size),
                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),

                        /*
                         * Call into BPF_FUNC_map_lookup_elem to see if the address matches any entry in the
                         * LPM trie map. For this to work, the prefixlen field of 'struct bpf_lpm_trie_key'
                         * has to be set to the maximum possible value.
                         *
                         * On success, the looked up value is stored in R0. For this application, the actual
                         * value doesn't matter, however; we just set the bit in @verdict in R8 if we found any
                         * matching value.
                         */

                        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
                        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -addr_size - sizeof(uint32_t)),
                        BPF_ST_MEM(BPF_W, BPF_REG_2, 0, addr_size * 8),

                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
                        BPF_ALU32_IMM(BPF_OR, BPF_REG_8, verdict),
                };

                /* Jump label fixup */
                insn[0].off = ELEMENTSOF(insn) - 1;

                r = bpf_program_add_instructions(p, insn, ELEMENTSOF(insn));
                if (r < 0)
                        return r;

                break;
        } while (0);

        return 0;
}

static int firewall_compile_bpf(
                const CGroupContext *cc,
                bool is_ingress,
                BPFProgram **ret) {

        _cleanup_(bpf_program_freep) BPFProgram *p = NULL;
        int accounting_map_fd, r;
        bool access_enabled =
                cc->ipv4_allow_map_fd >= 0 ||
                cc->ipv6_allow_map_fd >= 0 ||
                cc->ipv4_deny_map_fd >= 0 ||
                cc->ipv6_deny_map_fd >= 0;

        accounting_map_fd = is_ingress ?
                cc->ip_accounting_ingress_map_fd :
                cc->ip_accounting_egress_map_fd;

        assert(cc);
        assert(ret);

        if (accounting_map_fd < 0 && !access_enabled) {
                *ret = NULL;
                return 0;
        }

        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB, &p);
        if (r < 0)
                return r;

        if (access_enabled) {
                /*
                 * The simple rule this function translates into eBPF instructions is:
                 *
                 * - Access will be granted when an address matches an entry in @list_allow
                 * - Otherwise, access will be denied when an address matches an entry in @list_deny
                 * - Otherwise, access will be granted
                 */

                struct bpf_insn pre_insn[] = {
                        /*
                         * When the eBPF program is entered, R1 contains the address of the skb.
                         * However, R1-R5 are scratch registers that are not preserved when calling
                         * into kernel functions, so we need to save anything that's supposed to
                         * stay around to R6-R9. Save the skb to R6.
                         */
                        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),

                        /*
                         * Although we cannot access the skb data directly from eBPF programs used in this
                         * scenario, the kernel has prepared some fields for us to access through struct __sk_buff.
                         * Load the protocol (IPv4, IPv6) used by the packet in flight once and cache it in R7
                         * for later use.
                         */
                        BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct __sk_buff, protocol)),

                        /*
                         * R8 is used to keep track of whether any address check has explicitly allowed or denied the packet
                         * through ACCESS_DENIED or ACCESS_ALLOWED bits. Reset them both to 0 in the beginning.
                         */
                        BPF_MOV32_IMM(BPF_REG_8, 0),
                };

                /*
                 * The access checkers compiled for the configured allowance and denial lists
                 * write to R8 at runtime. The following code prepares for an early exit that
                 * skip the accounting if the packet is denied.
                 *
                 * R0 = 1
                 * if (R8 == ACCESS_DENIED)
                 *     R0 = 0
                 *
                 * This means that if both ACCESS_DENIED and ACCESS_ALLOWED are set, the packet
                 * is allowed to pass.
                 */

                struct bpf_insn post_insn[] = {
                        BPF_MOV64_IMM(BPF_REG_0, 1),
                        BPF_JMP_IMM(BPF_JNE, BPF_REG_8, ACCESS_DENIED, 1),
                        BPF_MOV64_IMM(BPF_REG_0, 0),
                };

                r = bpf_program_add_instructions(p, pre_insn, ELEMENTSOF(pre_insn));
                if (r < 0)
                        return r;

                if (cc->ipv4_deny_map_fd >= 0) {
                        r = add_lookup_instructions(p, cc->ipv4_deny_map_fd, ETH_P_IP, is_ingress, ACCESS_DENIED);
                        if (r < 0)
                                return r;
                }

                if (cc->ipv6_deny_map_fd >= 0) {
                        r = add_lookup_instructions(p, cc->ipv6_deny_map_fd, ETH_P_IPV6, is_ingress, ACCESS_DENIED);
                        if (r < 0)
                                return r;
                }

                if (cc->ipv4_allow_map_fd >= 0) {
                        r = add_lookup_instructions(p, cc->ipv4_allow_map_fd, ETH_P_IP, is_ingress, ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                if (cc->ipv6_allow_map_fd >= 0) {
                        r = add_lookup_instructions(p, cc->ipv6_allow_map_fd, ETH_P_IPV6, is_ingress, ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                r = bpf_program_add_instructions(p, post_insn, ELEMENTSOF(post_insn));
                if (r < 0)
                        return r;
        }

        if (accounting_map_fd >= 0) {
                struct bpf_insn insn[] = {
                        /*
                         * If R0 == 0, the packet will be denied; skip the accounting instructions in this case.
                         * The jump label will be fixed up later.
                         */
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0),

                        /* Count packets */
                        BPF_MOV64_IMM(BPF_REG_0, MAP_KEY_PACKETS), /* r0 = 0 */
                        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
                        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
                        BPF_LD_MAP_FD(BPF_REG_1, accounting_map_fd), /* load map fd to r1 */
                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
                        BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
                        BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */

                        /* Count bytes */
                        BPF_MOV64_IMM(BPF_REG_0, MAP_KEY_BYTES), /* r0 = 1 */
                        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
                        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
                        BPF_LD_MAP_FD(BPF_REG_1, accounting_map_fd),
                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
                        BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, len)), /* r1 = skb->len */
                        BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */

                        /* Allow the packet to pass */
                        BPF_MOV64_IMM(BPF_REG_0, 1),
                };

                /* Jump label fixup */
                insn[0].off = ELEMENTSOF(insn) - 1;

                r = bpf_program_add_instructions(p, insn, ELEMENTSOF(insn));
                if (r < 0)
                        return r;
        }

        do {
                /*
                 * Exit from the eBPF program, R0 contains the verdict.
                 * 0 means the packet is denied, 1 means the packet may pass.
                 */
                struct bpf_insn insn[] = {
                        BPF_EXIT_INSN()
                };

                r = bpf_program_add_instructions(p, insn, ELEMENTSOF(insn));
                if (r < 0)
                        return r;
        } while(0);

        *ret = p;
        p = NULL;

        return 0;
}

static int firewall_prepare_access_maps(HostsAccessAddress *list, int *ipv4_map_fd, int *ipv6_map_fd, int verdict) {
        struct bpf_lpm_trie_key *key_ipv4;
        struct bpf_lpm_trie_key *key_ipv6;
        size_t key_size_ipv4 = sizeof(*key_ipv4) + sizeof(uint32_t);
        size_t key_size_ipv6 = sizeof(*key_ipv6) + sizeof(uint64_t) * 2;
        uint64_t value = verdict;
        HostsAccessAddress *a;
        int r;

        assert(ipv4_map_fd);
        assert(ipv6_map_fd);

        close(*ipv4_map_fd);
        *ipv4_map_fd = -1;

        close(*ipv6_map_fd);
        *ipv6_map_fd = -1;

        key_ipv4 = alloca(key_size_ipv4);
        key_ipv6 = alloca(key_size_ipv6);

        LIST_FOREACH(address, a, list) {
                switch (a->family) {
                case AF_INET:
                        if (*ipv4_map_fd < 0) {
                                *ipv4_map_fd = bpf_map_create(BPF_MAP_TYPE_LPM_TRIE, key_size_ipv4, sizeof(value), UINT16_MAX);
                                if (*ipv4_map_fd < 0)
                                        return -errno;
                        }

                        key_ipv4->prefixlen = a->prefixlen;
                        memcpy(key_ipv4->data, &a->addr.in.s_addr, sizeof(uint32_t));

                        r = bpf_update_elem(*ipv4_map_fd, &key_ipv4, &value);
                        if (r < 0)
                                return r;

                        break;

                case AF_INET6:
                        if (*ipv6_map_fd < 0) {
                                *ipv6_map_fd = bpf_map_create(BPF_MAP_TYPE_LPM_TRIE, key_size_ipv6, sizeof(value), UINT16_MAX);
                                if (*ipv6_map_fd < 0)
                                        return -errno;
                        }

                        key_ipv6->prefixlen = a->prefixlen;
                        memcpy(key_ipv6->data, &a->addr.in6.s6_addr32, 4 * sizeof(uint32_t));

                        r = bpf_update_elem(*ipv6_map_fd, &key_ipv6, &value);
                        if (r < 0)
                                return r;

                        break;

                default:
                        return -EINVAL;
                }
        }

        return 0;
}

static int firewall_prepare_accounting_maps(bool wanted, int *fd_ingress, int *fd_egress) {

        assert(fd_ingress);
        assert(fd_egress);

        if (wanted) {
                int r;

                r = bpf_map_create(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), 2);
                if (r < 0)
                        return r;

                *fd_ingress = r;

                r = bpf_map_create(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), 2);
                if (r < 0)
                        return r;

                *fd_egress = r;
        } else {
                close(*fd_ingress);
                close(*fd_egress);
                *fd_ingress = -1;
                *fd_egress = -1;
        }

        return 0;
}

int firewall_compile_for_cgroup_context(CGroupContext *cc) {
        _cleanup_(bpf_program_freep) BPFProgram *p_ingress = NULL;
        _cleanup_(bpf_program_freep) BPFProgram *p_egress = NULL;
        int r;

        assert(cc);

        r = firewall_prepare_access_maps(cc->ip_hosts_allow, &cc->ipv4_allow_map_fd, &cc->ipv6_allow_map_fd, ACCESS_ALLOWED);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF allow maps failed: %m");

        r = firewall_prepare_access_maps(cc->ip_hosts_deny, &cc->ipv4_deny_map_fd, &cc->ipv6_deny_map_fd, ACCESS_DENIED);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF deny maps failed: %m");

        r = firewall_prepare_accounting_maps(cc->ip_accounting, &cc->ip_accounting_ingress_map_fd, &cc->ip_accounting_egress_map_fd);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF accounting maps failed: %m");


        r = firewall_compile_bpf(cc, true, &p_ingress);
        if (r < 0)
                return log_error_errno(r, "Compilation for ingress BPF program failed: %m");

        if (cc->ip_bpf_ingress)
                bpf_program_free(cc->ip_bpf_ingress);

        cc->ip_bpf_ingress = p_ingress;
        p_ingress = NULL;


        r = firewall_compile_bpf(cc, false, &p_egress);
        if (r < 0)
                return log_error_errno(r, "Compilation for egress BPF program failed: %m");

        if (cc->ip_bpf_egress)
                bpf_program_free(cc->ip_bpf_egress);

        cc->ip_bpf_egress = p_egress;
        p_egress = NULL;

        return 0;
}

int firewall_install_for_cgroup_context(CGroupContext *cc, const char *cg_path) {

        int r;

        assert(cc);
        assert(cg_path);

        if (cc->ip_bpf_egress) {
                r = bpf_program_load_kernel(cc->ip_bpf_egress, NULL, 0);
                if (r < 0) {
                        log_error_errno(r, "Kernel upload of egress BPF program failed: %m");
                        return r;
                }

                r = bpf_program_cgroup_attach(cc->ip_bpf_egress, BPF_CGROUP_INET_EGRESS, cg_path);
                if (r < 0) {
                        log_error_errno(r, "Attaching egress BPF program to cgroup failed: %m");
                        return r;
                }
        }

        if (cc->ip_bpf_ingress) {
                r = bpf_program_load_kernel(cc->ip_bpf_ingress, NULL, 0);
                if (r < 0) {
                        log_error_errno(r, "Kernel upload of ingress BPF program failed: %m");
                        return r;
                }

                r = bpf_program_cgroup_attach(cc->ip_bpf_ingress, BPF_CGROUP_INET_INGRESS, cg_path);
                if (r < 0) {
                        log_error_errno(r, "Attaching ingress BPF program to cgroup failed: %m");
                        return r;
                }
        }

        return 0;
}

int firewall_read_accounting(int map_fd, uint64_t *ret_bytes, uint64_t *ret_packets) {

        uint64_t key, bytes, packets;
        int r;

        assert(ret_bytes);
        assert(ret_packets);

        if (map_fd < 0)
                return -EINVAL;

        key = MAP_KEY_PACKETS;
        r = bpf_map_lookup_elem(map_fd, &key, &packets);
        if (r < 0)
                return r;

        key = MAP_KEY_BYTES;
        r = bpf_map_lookup_elem(map_fd, &key, &bytes);
        if (r < 0)
                return r;

        *ret_bytes = bytes;
        *ret_packets = packets;

        return 0;
}
