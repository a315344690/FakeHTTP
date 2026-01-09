/*
 * filter.h - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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

#ifndef FH_FILTER_H
#define FH_FILTER_H

#include <stdint.h>
#include <sys/socket.h>

/* CIDR entry structure */
struct fh_cidr {
    int family;                    /* AF_INET or AF_INET6 */
    union {
        uint32_t v4;
        uint8_t v6[16];
    } network;
    union {
        uint32_t v4;
        uint8_t v6[16];
    } mask;
};

/* Parse CIDR string to structure */
int fh_filter_parse_cidr(const char *cidr_str, struct fh_cidr *cidr);

/* Initialize filter module */
int fh_filter_setup(void);

/* Cleanup filter module */
void fh_filter_cleanup(void);

/* Check if packet should be processed */
int fh_filter_match(uint32_t oifindex, struct sockaddr *saddr,
                    struct sockaddr *daddr);

#endif /* FH_FILTER_H */
