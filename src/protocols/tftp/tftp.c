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
 * @file src/protocols/tftp/tftp.c
 * @brief Functions to encode/decode TFTP packets.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/udp.h>

#include <freeradius-devel/io/test_point.h>

#include "tftp.h"
#include "attrs.h"

/*
 *  https://tools.ietf.org/html/rfc1350
 *
 *  Order of Headers
 *
 *                                                 2 bytes
 *   ----------------------------------------------------------
 *  |  Local Medium  |  Internet  |  Datagram  |  TFTP Opcode  |
 *   ----------------------------------------------------------
 *
 *  TFTP Formats
 *
 *  Type   Op #     Format without header
 *
 *         2 bytes    string   1 byte     string   1 byte
 *         -----------------------------------------------
 *  RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
 *  WRQ    -----------------------------------------------
 *          2 bytes    2 bytes       n bytes
 *         ---------------------------------
 *  DATA  | 03    |   Block #  |    Data    |
 *         ---------------------------------
 *          2 bytes    2 bytes
 *         -------------------
 *  ACK   | 04    |   Block #  |
 *         --------------------
 *         2 bytes  2 bytes        string    1 byte
 *         ----------------------------------------
 *  ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
 *         ----------------------------------------
 *
 *  Initial Connection Protocol for reading a file
 *
 *  1. Host  A  sends  a  "RRQ"  to  host  B  with  source= A's TID,
 *     destination= 69.
 *
 *  2. Host B sends a "DATA" (with block number= 1) to host  A  with
 *     source= B's TID, destination= A's TID.
 */

char const *fr_tftp_codes[FR_TFTP_MAX_CODE] = {
	[FR_PACKET_TYPE_VALUE_READ_REQUEST] = "Read-Request",
	[FR_PACKET_TYPE_VALUE_WRITE_REQUEST] = "Write-Request",
	[FR_PACKET_TYPE_VALUE_DATA] = "Data",
	[FR_PACKET_TYPE_VALUE_ACKNOWLEDGEMENT] = "Acknowledgement",
	[FR_PACKET_TYPE_VALUE_ERROR] = "Error",
	[FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND] = "Do-Not-Respond"
};

char const *fr_tftp_error_codes[FR_TFTP_MAX_ERROR_CODE] = {
	[FR_TFTP_ERROR_CODE_VALUE_FILE_NOT_FOUND] = "File not found",
	[FR_TFTP_ERROR_CODE_VALUE_ACCESS_VIOLATION] = "Access violation",
	[FR_TFTP_ERROR_CODE_VALUE_DISK_FULL] = "Disk Full",
	[FR_TFTP_ERROR_CODE_VALUE_ILLEGAL_TFTP_OPERATION] = "Illegal TFTP operation",
	[FR_TFTP_ERROR_CODE_VALUE_UNKNOWN_TRANSFER_ID] = "Unknown transfer ID",
	[FR_TFTP_ERROR_CODE_VALUE_FILE_ALREADY_EXISTS] = "File already exists",
	[FR_TFTP_ERROR_CODE_VALUE_NO_SUCH_USER] = "No such user"
};

int fr_tftp_str2mode(char const *mode);
char const *fr_tftp_mode2str(int mode);

int fr_tftp_str2mode(char const *mode)
{
	if (!strcasecmp(mode, "ascii")) return FR_TFTP_MODE_VALUE_ASCII;
	if (!strcasecmp(mode, "octet")) return FR_TFTP_MODE_VALUE_OCTET;
	return FR_TFTP_MODE_VALUE_INVALID;
}

char const *fr_tftp_mode2str(int mode)
{
	switch(mode) {
	case FR_TFTP_MODE_VALUE_ASCII: return "ascii";
	case FR_TFTP_MODE_VALUE_OCTET: return "octet";
	default: return NULL;
	}
}

int fr_tftp_decode(TALLOC_CTX *ctx, uint8_t const *data, size_t data_len, VALUE_PAIR **vps)
{
	uint8_t const  	*q, *p, *end;
	uint16_t 	opcode;
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;

	if (data_len == 0) return -1;

	fr_cursor_init(&cursor, vps);

	if (data_len < FR_TFTP_HDR_LEN) {
		fr_strerror_printf("TFTP packet is too small. (%zu < %d)", data_len, FR_TFTP_HDR_LEN);

	error:
		fr_pair_list_free(vps);
		return -1;
	}

	p = data;
	end = (data + data_len);

	/* Opcode */
	opcode = ((p[0] << 8) | p[1]);
	vp = fr_pair_afrom_da(ctx, attr_tftp_opcode);
	if (!vp) goto error;

	vp->vp_uint16 = opcode;
	fr_cursor_append(&cursor, vp);
	p += 2;

	switch (opcode) {
	case FR_TFTP_OPCODE_VALUE_READ_REQUEST:
	case FR_TFTP_OPCODE_VALUE_WRITE_REQUEST:
		/*
		 *  2 bytes     string    1 byte     string   1 byte   string    1 byte   string   1 byte
		 *  +------------------------------------------------------------------------------------+
		 *  | Opcode |  Filename  |   0  |    Mode    |   0  |  blksize  |  0  |  #blksize |  0  |
		 *  +------------------------------------------------------------------------------------+
		 *  Figure 5-1: RRQ/WRQ packet
		 */

		/* <filename> */
		q = memchr(p, '\0', (end - p));
		if (!(q && q[0] == '\0')) {
		error_malformed:
			fr_strerror_printf("Packet contains malformed attribute");
			goto error;
		}

		vp = fr_pair_afrom_da(ctx, attr_tftp_filename);
		if (!vp) goto error;

		fr_pair_value_bstrndup(vp, (char const *)p, (q - p), true);
		fr_cursor_append(&cursor, vp);
		p += (q - p) + 1 /* \0 */;

		/* <mode> */
		q = memchr(p, '\0', (end - p));
		if (!(q && q[0] == '\0')) goto error_malformed;

		vp = fr_pair_afrom_da(ctx, attr_tftp_mode);
		if (!vp) goto error;

		/* (ascii || octet) + \0 */
		if ((p + 6) > end) goto error_malformed;

		vp->vp_uint8 = fr_tftp_str2mode((char const *)p);
		if (vp->vp_uint8 == FR_TFTP_MODE_VALUE_INVALID) goto error_malformed;

		fr_cursor_append(&cursor, vp);
		p += + 6 /* (ascii || octet) + \0 */;

		if (p >= end) goto done;

		/*
		 *  Once here, the next 'blksize' is optional.
		 *  At least: | blksize | \0 | #blksize | \0 |
		 */
		if ((end - p) < 10) goto error_malformed;

		if (!memcmp(p, "blksize", 7)) {
			char *p_end;
			long blksize;

			vp = fr_pair_afrom_da(ctx, attr_tftp_block_size);
			if (!vp) goto error;

			p += sizeof("blksize");
			blksize = strtol((const char *)p, &p_end, 10);

			if (p == (const uint8_t *)p_end || blksize > FR_TFTP_BLOCK_MAX_SIZE) {
				goto error_malformed;
			}

			vp->vp_uint16 = (uint16_t)blksize;
			fr_cursor_append(&cursor, vp);
		}

		break;

	case FR_TFTP_OPCODE_VALUE_ACKNOWLEDGEMENT:
	case FR_TFTP_OPCODE_VALUE_DATA:
		/**
		 *  2 bytes     2 bytes
		 *  ---------------------
		 *  | Opcode |   Block #  |
		 *  ---------------------
		 *  Figure 5-3: ACK packet
		 */

		vp = fr_pair_afrom_da(ctx, attr_tftp_block);
		if (!vp) goto error;

		vp->vp_uint16 = ((p[0] << 8) | p[1]);

		fr_cursor_append(&cursor, vp);

		/*
		 *	From that point...
		 *
		 *  2 bytes     2 bytes      n bytes
		 *  ----------------------------------
		 *  | Opcode |   Block #  |   Data     |
		 *  ----------------------------------
		 *  Figure 5-2: DATA packet
		 */
		if (opcode != FR_TFTP_OPCODE_VALUE_DATA) goto done;

		if ((p + 2) >= end) goto error_malformed;

		p += 2;

		vp = fr_pair_afrom_da(ctx, attr_tftp_data);
		if (!vp) goto error;

		fr_pair_value_memdup(vp, p, (end - p), true);
		fr_cursor_append(&cursor, vp);

		break;

	case FR_TFTP_OPCODE_VALUE_ERROR:
		/**
		 *  2 bytes     2 bytes      string    1 byte
		 *  -----------------------------------------
		 *  | Opcode |  ErrorCode |   ErrMsg   |   0  |
		 *  -----------------------------------------
		 *
		 *  Figure 5-4: ERROR packet
		 */

		if ((p + 2) >= end) goto error_malformed;

		vp = fr_pair_afrom_da(ctx, attr_tftp_error_code);
		if (!vp) goto error;

		vp->vp_uint16 = ((p[0] << 8) | p[1]);

		fr_cursor_append(&cursor, vp);

		p  += 2; /* <ErrorCode> */
		q   = memchr(p, '\0', (end - p));
		if (!q || q[0] != '\0') goto error_malformed;

		vp = fr_pair_afrom_da(ctx, attr_tftp_error_message);
		if (!vp) goto error;

		fr_pair_value_bstrndup(vp, (char const *)p, (q - p), true);
		fr_cursor_append(&cursor, vp);

		break;

	default:
		fr_strerror_printf("Invalid TFTP opcode %#04x", opcode);
		goto error;
	}

done:
	return data_len;
}

ssize_t fr_tftp_encode(uint8_t *buffer, size_t buflen, UNUSED uint8_t const *original, VALUE_PAIR *vps)
{
	VALUE_PAIR *vp;
	uint16_t opcode;
	uint8_t *p, *end;
	char const *buf;
	size_t len;

	fr_assert(buffer != NULL);
	fr_assert(buflen > 0);
	fr_assert(vps != NULL);

	if (buflen < FR_TFTP_HDR_LEN) {
	error:
		fr_strerror_printf("Output buffer is too small for TFTP packet. (%zu < %d)", buflen, FR_TFTP_HDR_LEN);
		return -1;
	}

	vp = fr_pair_find_by_da(vps, attr_tftp_opcode);
	if (!vp) {
		fr_strerror_printf("Cannot send TFTP packet without %s", attr_tftp_opcode->name);
		return -1;
	}

	p = buffer;
	end = (buffer + buflen);

	/* <Opcode> */
	opcode = htons(vp->vp_uint16);
	memcpy(p, &opcode, 2);
	p += 2;
	opcode = vp->vp_uint16;

	switch (opcode) {
	case FR_TFTP_OPCODE_VALUE_READ_REQUEST:
	case FR_TFTP_OPCODE_VALUE_WRITE_REQUEST:
		/*
		 *  2 bytes     string    1 byte     string   1 byte   string    1 byte   string   1 byte
		 *  +------------------------------------------------------------------------------------+
		 *  | Opcode |  Filename  |   0  |    Mode    |   0  |  blksize  |  0  |  #blksize |  0  |
		 *  +------------------------------------------------------------------------------------+
		* Figure 5-1: RRQ/WRQ packet
		*/

		/* <Filename> */
		vp = fr_pair_find_by_da(vps, attr_tftp_filename);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_filename->name);
			return -1;
		}

		memcpy(p, vp->vp_strvalue, vp->vp_length);
		p += vp->vp_length;
		*p++ = '\0';

		/* <mode> */
		vp = fr_pair_find_by_da(vps, attr_tftp_mode);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_mode->name);
			return -1;
		}

		buf = fr_tftp_mode2str(vp->vp_uint16);
		if (!buf) {
			fr_strerror_printf("Invalid %s value", attr_tftp_mode->name);
			return -1;
		}
		len = strlen(buf);
		memcpy(p, buf, len);
		p += len;
		*p++ = '\0';

		/* <blksize> is optional */
		vp = fr_pair_find_by_da(vps, attr_tftp_block_size);
		if (vp) {
			char tmp[5+1];                                   /* max: 65535 */

			/* at least: blksize|\0|65535|\0 */
			if ((p + 14) >= end) goto error;

			memcpy(p, "blksize\0", 8);                       /* blksize */
			p += 8;

			snprintf(tmp, sizeof(tmp), "%d", vp->vp_uint16); /* #blksize */
			len = strlen(tmp);
			memcpy(p, tmp, len);
			p += len;

			*p++ = '\0';
		}

		break;

	case FR_TFTP_OPCODE_VALUE_ACKNOWLEDGEMENT:
	case FR_TFTP_OPCODE_VALUE_DATA:
		/**
		 * 2 bytes     2 bytes
		 * ---------------------
		 * | Opcode |   Block #  |
		 * ---------------------
		 * Figure 5-3: ACK packet
		 */

		/* <Block> */
		vp = fr_pair_find_by_da(vps, attr_tftp_block);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_block->name);
			return -1;
		}

		len = htons(vp->vp_uint16);
		memcpy(p, &len, 2);
		p += 2;

		/*
		 *	From that point...
		 *
		 *  2 bytes     2 bytes      n bytes
		 *  ----------------------------------
		 *  | Opcode |   Block #  |   Data     |
		 *  ----------------------------------
		 *  Figure 5-2: DATA packet
		 */
		if (opcode != FR_TFTP_OPCODE_VALUE_DATA) goto done;

		/* <Data> */
		vp = fr_pair_find_by_da(vps, attr_tftp_data);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_data->name);
			return -1;
		}

		memcpy(p, vp->vp_octets, vp->vp_length);
		p += vp->vp_length;

		break;

	case FR_TFTP_OPCODE_VALUE_ERROR:
	{
		/**
		 * 2 bytes     2 bytes      string    1 byte
		 * -----------------------------------------
		 * | Opcode |  ErrorCode |   ErrMsg   |   0  |
		 * -----------------------------------------
		 *
		 * Figure 5-4: ERROR packet
		 */
		uint16_t error_code = 0;
		char const *error_msg;
		uint16_t error_msg_len;

		/* <ErroCode> */
		vp = fr_pair_find_by_da(vps, attr_tftp_error_code);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_error_code->name);
			return -1;
		}

		error_code = vp->vp_uint16;
		len = htons(error_code);
		memcpy(p, &len, 2);
		p += 2;

		/* <ErrMsg> */
		vp = fr_pair_find_by_da(vps, attr_tftp_error_message);
		if (vp) {
			error_msg = vp->vp_strvalue;
			error_msg_len = vp->vp_length;
		} else {
			error_msg = fr_tftp_error_codes[error_code] ? fr_tftp_error_codes[error_code] : "Invalid ErrorCode";
			error_msg_len = strlen(error_msg);
		}

		memcpy(p, error_msg, error_msg_len);
		p += error_msg_len;
		*p++ = '\0';
		break;
	}

	default:
		fr_strerror_printf("Invalid TFTP opcode %#04x", opcode);
		return -1;
	}

done:
	return (p - buffer);
}

/**
 *	Used as the decoder ctx.
 */
typedef struct {
	fr_dict_attr_t const *root;
} fr_tftp_ctx_t;

/*
 *	Test points for protocol decode
 */
static ssize_t fr_tftp_decode_proto(TALLOC_CTX *ctx, VALUE_PAIR **vps, uint8_t const *data, size_t data_len, UNUSED void *proto_ctx)
{
	return fr_tftp_decode(ctx, data, data_len, vps);
}

static int _decode_test_ctx(UNUSED fr_tftp_ctx_t *proto_ctx)
{
	fr_tftp_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_tftp_ctx_t *test_ctx;

	if (fr_tftp_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_tftp_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->root = fr_dict_root(dict_tftp);
	talloc_set_destructor(test_ctx, _decode_test_ctx);

	*out = test_ctx;

	return 0;
}

extern fr_test_point_proto_decode_t tftp_tp_decode_proto;
fr_test_point_proto_decode_t tftp_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_tftp_decode_proto
};
