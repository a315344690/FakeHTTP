/*
 * filter.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
 *
 * Copyright (C) 2025  MikeWang000000
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include "filter.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "globvar.h"
#include "logging.h"


int fh_filter_parse_cidr(const char *cidr_str, struct fh_cidr *cidr)
{
    char addr_buf[INET6_ADDRSTRLEN];
    const char *slash;
    int prefix_len, i;
    size_t addr_len;

    memset(cidr, 0, sizeof(*cidr));

    slash = strchr(cidr_str, '/');
    if (!slash) {
        E("ERROR: Invalid CIDR format (missing /): %s", cidr_str);
        return -1;
    }

    addr_len = slash - cidr_str;
    if (addr_len >= sizeof(addr_buf)) {
        E("ERROR: Address too long: %s", cidr_str);
        return -1;
    }

    memcpy(addr_buf, cidr_str, addr_len);
    addr_buf[addr_len] = '\0';

    prefix_len = atoi(slash + 1);
    if (prefix_len < 0) {
        E("ERROR: Invalid prefix length: %s", cidr_str);
        return -1;
    }

    /* Try IPv4 first */
    if (inet_pton(AF_INET, addr_buf, &cidr->network.v4) == 1) {
        cidr->family = AF_INET;

        if (prefix_len > 32) {
            E("ERROR: Invalid IPv4 prefix length: %d", prefix_len);
            return -1;
        }

        if (prefix_len == 0) {
            cidr->mask.v4 = 0;
        } else {
            cidr->mask.v4 = htonl(~((1U << (32 - prefix_len)) - 1));
        }

        /* Apply mask to network address */
        cidr->network.v4 &= cidr->mask.v4;

        return 0;
    }

    /* Try IPv6 */
    if (inet_pton(AF_INET6, addr_buf, &cidr->network.v6) == 1) {
        cidr->family = AF_INET6;

        if (prefix_len > 128) {
            E("ERROR: Invalid IPv6 prefix length: %d", prefix_len);
            return -1;
        }

        /* Generate mask */
        memset(cidr->mask.v6, 0, sizeof(cidr->mask.v6));
        for (i = 0; i < prefix_len / 8; i++) {
            cidr->mask.v6[i] = 0xff;
        }
        if (prefix_len % 8) {
            cidr->mask.v6[i] = (uint8_t) (0xff << (8 - (prefix_len % 8)));
        }

        /* Apply mask to network address */
        for (i = 0; i < 16; i++) {
            cidr->network.v6[i] &= cidr->mask.v6[i];
        }

        return 0;
    }

    E("ERROR: Invalid IP address: %s", addr_buf);
    return -1;
}


static int cidr_match_addr(struct fh_cidr *cidr, struct sockaddr *addr)
{
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    int i;

    if (cidr->family != addr->sa_family) {
        return 0;
    }

    if (cidr->family == AF_INET) {
        addr4 = (struct sockaddr_in *) addr;
        return (addr4->sin_addr.s_addr & cidr->mask.v4) == cidr->network.v4;
    } else if (cidr->family == AF_INET6) {
        addr6 = (struct sockaddr_in6 *) addr;
        for (i = 0; i < 16; i++) {
            if ((addr6->sin6_addr.s6_addr[i] & cidr->mask.v6[i]) !=
                cidr->network.v6[i]) {
                return 0;
            }
        }
        return 1;
    }

    return 0;
}


int fh_filter_match(struct sockaddr *saddr, struct sockaddr *daddr)
{
    size_t i;

    /* If no CIDR filters specified, match all */
    if (!g_ctx.cidrs || !g_ctx.cidrs[0].family) {
        return 1;
    }

    /* Check if source or destination matches any CIDR */
    for (i = 0; g_ctx.cidrs[i].family; i++) {
        if (cidr_match_addr(&g_ctx.cidrs[i], saddr) ||
            cidr_match_addr(&g_ctx.cidrs[i], daddr)) {
            return 1;
        }
    }

    return 0;
}
