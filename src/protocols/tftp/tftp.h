#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file src/protocols/tftp/tftp.h
 * @brief Functions to encode/decode TFTP packets.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

RCSIDH(tftp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/protocol/tftp/freeradius.internal.h>
#include <freeradius-devel/protocol/tftp/rfc1350.h>

#define FR_TFTP_MAX_CODE 	(FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND+1)
#define FR_TFTP_HDR_LEN 	(4)	/* at least: 2-bytes opcode + 2-bytes */

/* tftp.c */
extern char const	*fr_tftp_codes[FR_TFTP_MAX_CODE];

int fr_tftp_decode(TALLOC_CTX *ctx, uint8_t const *data, size_t data_len, VALUE_PAIR **vps) CC_HINT(nonnull(2,4));
ssize_t fr_tftp_encode(uint8_t *buffer, size_t buflen, uint8_t const *original, VALUE_PAIR *vps) CC_HINT(nonnull(1,4));

/* base.c */
int fr_tftp_init(void);
void fr_tftp_free(void);

#ifdef __cplusplus
}
#endif
