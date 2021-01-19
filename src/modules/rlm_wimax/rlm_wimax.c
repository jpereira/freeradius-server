/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_wimax.c
 * @brief Supports various WiMax functionality.
 *
 * @copyright 2008 Alan DeKok (aland@networkradius.com)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#define LOG_PREFIX "rlm_wimax - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/sim/milenage.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/missing.h>
#include <freeradius-devel/util/hex.h>

#ifdef HAVE_OPENSSL_HMAC_H
#include <openssl/hmac.h>
#endif

#define WIMAX_EPSAKA_RAND_SIZE         16
#define WIMAX_EPSAKA_KI_SIZE           16
#define WIMAX_EPSAKA_OPC_SIZE          16
#define WIMAX_EPSAKA_AMF_SIZE          2
#define WIMAX_EPSAKA_SQN_SIZE          6
#define WIMAX_EPSAKA_MAC_A_SIZE        8
#define WIMAX_EPSAKA_MAC_S_SIZE        8
#define WIMAX_EPSAKA_XRES_SIZE         8
#define WIMAX_EPSAKA_CK_SIZE           16
#define WIMAX_EPSAKA_IK_SIZE           16
#define WIMAX_EPSAKA_AK_SIZE           6
#define WIMAX_EPSAKA_AK_RESYNC_SIZE    6
#define WIMAX_EPSAKA_KK_SIZE           32
#define WIMAX_EPSAKA_KS_SIZE           14
#define WIMAX_EPSAKA_PLMN_SIZE         3
#define WIMAX_EPSAKA_KASME_SIZE        32
#define WIMAX_EPSAKA_AUTN_SIZE         16
#define WIMAX_EPSAKA_AUTS_SIZE         14

/*
 *	FIXME: Fix the build system to create definitions from names.
 */
typedef struct {
	bool	delete_mppe_keys;
} rlm_wimax_t;

static const CONF_PARSER module_config[] = {
  { FR_CONF_OFFSET("delete_mppe_keys", FR_TYPE_BOOL, rlm_wimax_t, delete_mppe_keys), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;
static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_wimax_dict[];
fr_dict_autoload_t rlm_wimax_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_eap_emsk;
static fr_dict_attr_t const *attr_eap_msk;
static fr_dict_attr_t const *attr_sim_ki;
static fr_dict_attr_t const *attr_sim_opc;
static fr_dict_attr_t const *attr_sim_amf;
static fr_dict_attr_t const *attr_sim_sqn;

static fr_dict_attr_t const *attr_wimax_mn_nai;
static fr_dict_attr_t const *attr_wimax_sim_rand;

static fr_dict_attr_t const *attr_calling_station_id;

static fr_dict_attr_t const *attr_wimax_msk;
static fr_dict_attr_t const *attr_wimax_ip_technology;
static fr_dict_attr_t const *attr_wimax_mn_hha_mip4_key;
static fr_dict_attr_t const *attr_wimax_mn_hha_mip4_spi;
static fr_dict_attr_t const *attr_wimax_hha_ip_mip4;
static fr_dict_attr_t const *attr_wimax_hha_ip_mip6;
static fr_dict_attr_t const *attr_wimax_mn_hha_mip6_key;
static fr_dict_attr_t const *attr_wimax_mn_hha_mip6_spi;
static fr_dict_attr_t const *attr_wimax_fa_rk_key;
static fr_dict_attr_t const *attr_wimax_fa_rk_spi;
static fr_dict_attr_t const *attr_wimax_rrq_mn_ha_spi;
static fr_dict_attr_t const *attr_wimax_rrq_ha_ip;
static fr_dict_attr_t const *attr_wimax_ha_rk_key_requested;

static fr_dict_attr_t const *attr_wimax_visited_plmn_id;

static fr_dict_attr_t const *attr_wimax_e_utran_vector_item_number;
static fr_dict_attr_t const *attr_wimax_e_utran_vector_rand;
static fr_dict_attr_t const *attr_wimax_e_utran_vector_xres;
static fr_dict_attr_t const *attr_wimax_e_utran_vector_autn;
static fr_dict_attr_t const *attr_wimax_e_utran_vector_kasme;

static fr_dict_attr_t const *attr_wimax_requested_eutran_authentication_info;
static fr_dict_attr_t const *attr_wimax_number_of_requested_vectors;
static fr_dict_attr_t const *attr_wimax_immediate_response_preferred;
static fr_dict_attr_t const *attr_wimax_re_syncronization_info;

static fr_dict_attr_t const *attr_ms_mppe_send_key;
static fr_dict_attr_t const *attr_ms_mppe_recv_key;

extern fr_dict_attr_autoload_t rlm_wimax_dict_attr[];
fr_dict_attr_autoload_t rlm_wimax_dict_attr[] = {
	{ .out = &attr_eap_emsk, .name = "EAP-EMSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_msk, .name = "EAP-MSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_ki, .name = "SIM-Ki", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_opc, .name = "SIM-OPc", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_amf, .name = "SIM-AMF", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_sim_sqn, .name = "SIM-SQN", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },

	{ .out = &attr_wimax_mn_nai, .name = "WiMAX-MN-NAI", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_wimax_sim_rand, .name = "WiMAX-SIM-RAND", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_calling_station_id, .name = "Calling-Station-ID", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ .out = &attr_wimax_e_utran_vector_item_number, .name = "Vendor-Specific.WiMAX.Authentication-Info.E-UTRAN-Vector.Item-Number", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_e_utran_vector_rand, .name = "Vendor-Specific.WiMAX.Authentication-Info.E-UTRAN-Vector.RAND", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_e_utran_vector_xres, .name = "Vendor-Specific.WiMAX.Authentication-Info.E-UTRAN-Vector.XRES", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_e_utran_vector_autn, .name = "Vendor-Specific.WiMAX.Authentication-Info.E-UTRAN-Vector.AUTN", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_e_utran_vector_kasme, .name = "Vendor-Specific.WiMAX.Authentication-Info.E-UTRAN-Vector.KASME", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ .out = &attr_wimax_msk, .name = "Vendor-Specific.WiMAX.MSK", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_ip_technology, .name = "Vendor-Specific.WiMAX.IP-Technology", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_mn_hha_mip4_key, .name = "Vendor-Specific.WiMAX.MN-hHA-MIP4-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_mn_hha_mip4_spi, .name = "Vendor-Specific.WiMAX.MN-hHA-MIP4-SPI", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_hha_ip_mip4, .name = "Vendor-Specific.WiMAX.hHA-IP-MIP4", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_wimax_hha_ip_mip6, .name = "Vendor-Specific.WiMAX.hHA-IP-MIP6", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_radius },
	{ .out = &attr_wimax_mn_hha_mip6_key, .name = "Vendor-Specific.WiMAX.MN-hHA-MIP6-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_mn_hha_mip6_spi, .name = "Vendor-Specific.WiMAX.MN-hHA-MIP6-SPI", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_visited_plmn_id, .name = "Vendor-Specific.WiMAX.Visited-PLMN-ID", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_fa_rk_key, .name = "Vendor-Specific.WiMAX.FA-RK-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_fa_rk_spi, .name = "Vendor-Specific.WiMAX.FA-RK-SPI", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_rrq_mn_ha_spi, .name = "Vendor-Specific.WiMAX.RRQ-MN-HA-SPI", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_rrq_ha_ip, .name = "Vendor-Specific.WiMAX.RRQ-HA-IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_radius },
	{ .out = &attr_wimax_ha_rk_key_requested, .name = "Vendor-Specific.WiMAX.HA-RK-Key-Requested", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	{ .out = &attr_wimax_requested_eutran_authentication_info, .name = "Vendor-Specific.WiMAX.Requested-EUTRAN-Authentication-Info", .type = FR_TYPE_TLV, .dict = &dict_radius },
	{ .out = &attr_wimax_number_of_requested_vectors, .name = "Vendor-Specific.WiMAX.Requested-EUTRAN-Authentication-Info.Number-Of-Requested-Vectors", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_immediate_response_preferred, .name = "Vendor-Specific.WiMAX.Requested-EUTRAN-Authentication-Info.Immediate-Response-Preferred", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_re_syncronization_info, .name = "Vendor-Specific.WiMAX.Requested-EUTRAN-Authentication-Info.Re-synchronization-Info", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ NULL }
};

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	fr_pair_t *vp;

	/*
	 *	Fix Calling-Station-Id.  Damn you, WiMAX!
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_calling_station_id);
	if (vp && (vp->vp_length == 6)) {
		int	i;
		char	*p;
		uint8_t	buffer[6];

		memcpy(buffer, vp->vp_strvalue, 6);

		MEM(fr_pair_value_bstr_realloc(vp, &p, (5 * 3) + 2) == 0);

		/*
		 *	RFC 3580 Section 3.20 says this is the preferred
		 *	format.  Everyone *SANE* is using this format,
		 *	so we fix it here.
		 */
		for (i = 0; i < 6; i++) {
			fr_bin2hex(&FR_SBUFF_OUT(&p[i * 3], 2 + 1), &FR_DBUFF_TMP(&buffer[i], 1), SIZE_MAX);
			p[(i * 3) + 2] = '-';
		}

		DEBUG2("Fixing WiMAX binary Calling-Station-Id to %pV", &vp->data);
		RETURN_MODULE_OK;
	}

	/*
	 *	Check for attr WiMAX.Requested-EUTRAN-Authentication-Info.Re-synchronization-Info
	 *	which contains the concatenation of RAND and AUTS
	 *
	 *	If it is present then we proceed to verify the SIM and
	 *	extract the new value of SQN
	 */
	fr_pair_t *resync_info, *ki, *opc, *sqn, *rand;
	int m_ret;

	/* Look for the Re-synchronization-Info attribute in the request */
	resync_info = fr_pair_find_by_da(&request->request_pairs, attr_wimax_re_syncronization_info);
	if (resync_info && (resync_info->vp_length < (WIMAX_EPSAKA_RAND_SIZE + WIMAX_EPSAKA_AUTS_SIZE))) {
		RWDEBUG("Found request:%s with incorrect length: Ignoring it", attr_wimax_re_syncronization_info->name);
		resync_info = NULL;
	}

	/*
	 *	These are the private keys which should be added to the control
	 *	list after looking them up in a database by IMSI
	 *
	 *	We grab them from the control list here
	 */
	ki = fr_pair_find_by_da(&request->control_pairs, attr_sim_ki);
	if (ki && (ki->vp_length < MILENAGE_CK_SIZE)) {
		RWDEBUG("Found control:%s with incorrect length: Ignoring it", attr_sim_ki->name);
		ki = NULL;
	}

	opc = fr_pair_find_by_da(&request->control_pairs, attr_sim_opc);
	if (opc && (opc->vp_length < MILENAGE_IK_SIZE)) {
		RWDEBUG("Found control:%s with incorrect length: Ignoring it", attr_sim_opc->name);
		opc = NULL;
	}

	/* If we have resync info (RAND and AUTS), Ki and OPc then we can proceed */
	if (resync_info && ki && opc) {
		uint64_t sqn_bin;
		uint8_t rand_bin[WIMAX_EPSAKA_RAND_SIZE];
		uint8_t auts_bin[WIMAX_EPSAKA_AUTS_SIZE];

		RDEBUG("Found WiMAX.Re-synchronization-Info. Proceeding with SQN resync");

		/* Split Re-synchronization-Info into seperate RAND and AUTS */
		memcpy(rand_bin, &resync_info->vp_octets[0], WIMAX_EPSAKA_RAND_SIZE);
		memcpy(auts_bin, &resync_info->vp_octets[WIMAX_EPSAKA_RAND_SIZE], WIMAX_EPSAKA_AUTS_SIZE);

		RHEXDUMP3(rand_bin, WIMAX_EPSAKA_RAND_SIZE, "RAND   (%d bytes)", WIMAX_EPSAKA_RAND_SIZE);
		RHEXDUMP3(auts_bin, WIMAX_EPSAKA_AUTS_SIZE, "AUTS   (%d bytes)", WIMAX_EPSAKA_AUTS_SIZE);

		/*
		 *	This procedure uses the secret keys Ki and OPc to authenticate
		 *	the SIM and extract the SQN
		 */
		m_ret = milenage_auts(&sqn_bin, opc->vp_octets, ki->vp_octets, rand_bin, auts_bin);

		/*
		 *	If the SIM verification fails then we can't go any further as
		 *	we don't have the keys. And that probably means something bad
		 *	is happening so we bail out now
		 */
		if (m_ret < 0) {
			RDEBUG("SIM verification failed");
			RETURN_MODULE_REJECT;
		}

		/*
		 *	If we got this far it means have got a new SQN and RAND
		 *	so we store them in:
		 *	control:SIM-SQN
		 *	control:WiMAX.SIM-RAND
		 *
		 *	From there they can be grabbed by unlang and used later
		 */

		/* SQN is six bytes so we extract what we need from the 64 bit variable */
		const uint8_t sqn_bin_arr[WIMAX_EPSAKA_SQN_SIZE] = {
			(sqn_bin & 0x0000FF0000000000ull) >> 40,
			(sqn_bin & 0x000000FF00000000ull) >> 32,
			(sqn_bin & 0x00000000FF000000ull) >> 24,
			(sqn_bin & 0x0000000000FF0000ull) >> 16,
			(sqn_bin & 0x000000000000FF00ull) >>  8,
			(sqn_bin & 0x00000000000000FFull) >>  0
		};

		/* Add SQN to control:SIM-SQN */
		sqn = fr_pair_find_by_da(&request->control_pairs, attr_sim_sqn);
		if (sqn && sqn->vp_uint64 > 0xffffffffffff) { /* Max is 48bits */
			RWDEBUG("Found control:%s with incorrect length: Ignoring it", attr_sim_sqn->name);
			sqn = NULL;
		}

		if (!sqn) {
			MEM(pair_update_control(&sqn, attr_sim_sqn) >= 0);
			memcpy(&sqn->vp_uint64, sqn_bin_arr, WIMAX_EPSAKA_SQN_SIZE);
		}

		RHEXDUMP3((uint8_t *)&sqn->vp_uint64, WIMAX_EPSAKA_SQN_SIZE, "SQN   (%d bytes)", WIMAX_EPSAKA_SQN_SIZE);

		/* Add RAND to control:WiMAX.SIM-RAND */
		rand = fr_pair_find_by_da(&request->control_pairs, attr_wimax_sim_rand);
		if (rand && (rand->vp_length < WIMAX_EPSAKA_RAND_SIZE)) {
			RWDEBUG("Found control:%s with incorrect length: Ignoring it", attr_wimax_sim_rand->name);
			rand = NULL;
		}

		if (!rand) {
			MEM(pair_update_control(&rand, attr_wimax_sim_rand) >= 0);
			fr_pair_value_memdup(rand, rand_bin, WIMAX_EPSAKA_RAND_SIZE, true);
		}
		RHEXDUMP3(rand->vp_octets, WIMAX_EPSAKA_RAND_SIZE, "RAND   (%d bytes)", WIMAX_EPSAKA_RAND_SIZE);

		RETURN_MODULE_UPDATED;
	}

	RETURN_MODULE_NOOP;
}

/*
 *	Massage the request before recording it or proxying it
 */
static unlang_action_t CC_HINT(nonnull) mod_preacct(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	return mod_authorize(p_result, mctx, request);
}

/*
 *	This function generates the keys for old style WiMAX (v1 to v2.0)
 */
static int mip_keys_generate(const rlm_wimax_t *inst, request_t *request, fr_pair_t *msk, fr_pair_t *emsk)
{
	fr_pair_t *vp;
	fr_pair_t *mn_nai, *ip, *fa_rk;
	HMAC_CTX *hmac;
	unsigned int rk1_len, rk2_len, rk_len;
	uint32_t mip_spi;
	uint8_t usage_data[24];
	uint8_t mip_rk_1[EVP_MAX_MD_SIZE], mip_rk_2[EVP_MAX_MD_SIZE];
	uint8_t mip_rk[2 * EVP_MAX_MD_SIZE];

	/*
	 *	If we delete the MS-MPPE-*-Key attributes, then add in
	 *	the WiMAX-MSK so that the client has a key available.
	 */
	if (inst->delete_mppe_keys) {
		pair_delete_reply(attr_ms_mppe_send_key);
		pair_delete_reply(attr_ms_mppe_recv_key);

		MEM(pair_update_reply(&vp, attr_wimax_msk) >= 0);
		fr_pair_value_memdup(vp, msk->vp_octets, msk->vp_length, false);
	}

	/*
	 *	Initialize usage data.
	 */
	memcpy(usage_data, "miprk@wimaxforum.org", 21);	/* with trailing \0 */
	usage_data[21] = 0x02;
	usage_data[22] = 0x00;
	usage_data[23] = 0x01;

	/*
	 *	MIP-RK-1 = HMAC-SSHA256(EMSK, usage-data | 0x01)
	 */
	hmac = HMAC_CTX_new();
	HMAC_Init_ex(hmac, emsk->vp_octets, emsk->vp_length, EVP_sha256(), NULL);

	HMAC_Update(hmac, &usage_data[0], sizeof(usage_data));
	HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

	/*
	 *	MIP-RK-2 = HMAC-SSHA256(EMSK, MIP-RK-1 | usage-data | 0x01)
	 */
	HMAC_Init_ex(hmac, emsk->vp_octets, emsk->vp_length, EVP_sha256(), NULL);

	HMAC_Update(hmac, (uint8_t const *) &mip_rk_1, rk1_len);
	HMAC_Update(hmac, &usage_data[0], sizeof(usage_data));
	HMAC_Final(hmac, &mip_rk_2[0], &rk2_len);

	memcpy(mip_rk, mip_rk_1, rk1_len);
	memcpy(mip_rk + rk1_len, mip_rk_2, rk2_len);
	rk_len = rk1_len + rk2_len;

	/*
	 *	MIP-SPI = HMAC-SSHA256(MIP-RK, "SPI CMIP PMIP");
	 */
	HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha256(), NULL);

	HMAC_Update(hmac, (uint8_t const *) "SPI CMIP PMIP", 12);
	HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

	/*
	 *	Take the 4 most significant octets.
	 *	If less than 256, add 256.
	 */
	mip_spi = ((mip_rk_1[0] << 24) | (mip_rk_1[1] << 16) |
		   (mip_rk_1[2] << 8) | mip_rk_1[3]);
	if (mip_spi < 256) mip_spi += 256;

	REDEBUG2("MIP-RK = 0x%pH", fr_box_octets(mip_rk, rk_len));
	REDEBUG2("MIP-SPI = %08x", ntohl(mip_spi));

	/*
	 *	FIXME: Perform SPI collision prevention
	 */

	/*
	 *	Calculate mobility keys
	 */
	mn_nai = fr_pair_find_by_da(&request->request_pairs, attr_wimax_mn_nai);
	if (!mn_nai) mn_nai = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_mn_nai);
	if (!mn_nai) {
		RWDEBUG("%s was not found in the request or in the reply", attr_wimax_mn_nai->name);
		RWDEBUG("We cannot calculate MN-HA keys");
	}

	/*
	 *	WiMAX.IP-Technology
	 */
	vp = NULL;
	if (mn_nai) vp = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_ip_technology);
	if (!vp) {
		RWDEBUG("%s not found in reply", attr_wimax_ip_technology->name);
		RWDEBUG("Not calculating MN-HA keys");
	}

	if (vp) switch (vp->vp_uint32) {
	case 2:			/* PMIP4 */
		/*
		 *	Look for WiMAX.hHA-IP-MIP4
		 */
		ip = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_hha_ip_mip4);
		if (!ip) {
			RWDEBUG("%s not found.  Cannot calculate MN-HA-PMIP4 key", attr_wimax_hha_ip_mip4->name);
			break;
		}

		/*
		 *	MN-HA-PMIP4 =
		 *	   H(MIP-RK, "PMIP4 MN HA" | HA-IPv4 | MN-NAI);
		 */
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "PMIP4 MN HA", 11);
		HMAC_Update(hmac, (uint8_t const *) &ip->vp_ipv4addr, 4);
		HMAC_Update(hmac, (uint8_t const *) &mn_nai->vp_strvalue, mn_nai->vp_length);
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-PMIP4 into WiMAX.MN-hHA-MIP4-Key
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip4_key) >= 0);
		fr_pair_value_memdup(vp, &mip_rk_1[0], rk1_len, false);

		/*
		 *	Put MN-HA-PMIP4-SPI into WiMAX.MN-hHA-MIP4-SPI
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip4_spi) >= 0);
		vp->vp_uint32 = mip_spi + 1;
		break;

	case 3:			/* CMIP4 */
		/*
		 *	Look for WiMAX.hHA-IP-MIP4
		 */
		ip = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_hha_ip_mip4);
		if (!ip) {
			RWDEBUG("%s not found.  Cannot calculate MN-HA-CMIP4 key", attr_wimax_hha_ip_mip4->name);
			break;
		}

		/*
		 *	MN-HA-CMIP4 =
		 *	   H(MIP-RK, "CMIP4 MN HA" | HA-IPv4 | MN-NAI);
		 */
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "CMIP4 MN HA", 11);
		HMAC_Update(hmac, (uint8_t const *) &ip->vp_ipv4addr, 4);
		HMAC_Update(hmac, (uint8_t const *) &mn_nai->vp_strvalue, mn_nai->vp_length);
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-CMIP4 into WiMAX-MN-hHA-MIP4-Key
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip4_key) >= 0);
		fr_pair_value_memdup(vp, &mip_rk_1[0], rk1_len, false);

		/*
		 *	Put MN-HA-CMIP4-SPI into WiMAX.MN-hHA-MIP4-SPI
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip4_spi) >= 0);
		vp->vp_uint32 = mip_spi;
		break;

	case 4:			/* CMIP6 */
		/*
		 *	Look for WiMAX.hHA-IP-MIP6
		 */
		ip = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_hha_ip_mip6);
		if (!ip) {
			RWDEBUG("%s not found.  Cannot calculate MN-HA-CMIP6 key", attr_wimax_hha_ip_mip6->name);
			break;
		}

		/*
		 *	MN-HA-CMIP6 =
		 *	   H(MIP-RK, "CMIP6 MN HA" | HA-IPv6 | MN-NAI);
		 */
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "CMIP6 MN HA", 11);
		HMAC_Update(hmac, (uint8_t const *) &ip->vp_ipv6addr, 16);
		HMAC_Update(hmac, (uint8_t const *) &mn_nai->vp_strvalue, mn_nai->vp_length);
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-CMIP6 into WiMAX.MN-hHA-MIP6-Key
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip6_key) >= 0);
		fr_pair_value_memdup(vp, &mip_rk_1[0], rk1_len, false);

		/*
		 *	Put MN-HA-CMIP6-SPI into WiMAX.MN-hHA-MIP6-SPI
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip6_spi) >= 0);
		vp->vp_uint32 = mip_spi + 2;
		break;

	default:
		break;		/* do nothing */
	}

	/*
	 *	Generate FA-RK, if requested.
	 *
	 *	FA-RK = H(MIP-RK, "FA-RK")
	 */
	fa_rk = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_fa_rk_key);
	if (fa_rk && (fa_rk->vp_length <= 1)) {
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "FA-RK", 5);

		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		fr_pair_value_memdup(fa_rk, &mip_rk_1[0], rk1_len, false);
	}

	/*
	 *	Create FA-RK-SPI, which is really SPI-CMIP4, which is
	 *	really MIP-SPI.  Clear?  Of course.  This is WiMAX.
	 */
	if (fa_rk) {
		MEM(pair_update_reply(&vp, attr_wimax_fa_rk_spi) >= 0);
		vp->vp_uint32 = mip_spi;
	}

	/*
	 *	Give additional information about requests && responses
	 *
	 *	WiMAX.RRQ-MN-HA-SPI
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_wimax_rrq_mn_ha_spi);
	if (vp) {
		REDEBUG2("Client requested MN-HA key: Should use SPI to look up key from storage");
		if (!mn_nai) {
			RWDEBUG("MN-NAI was not found!");
		}

		/*
		 *	WiMAX.RRQ-HA-IP
		 */
		if (!fr_pair_find_by_da(&request->request_pairs, attr_wimax_rrq_ha_ip)) {
			RWDEBUG("HA-IP was not found!");
		}

		/*
		 *	WiMAX.HA-RK-Key-Requested
		 */
		vp = fr_pair_find_by_da(&request->request_pairs, attr_wimax_ha_rk_key_requested);
		if (vp && (vp->vp_uint32 == 1)) {
			REDEBUG2("Client requested HA-RK: Should use IP to look it up from storage");
		}
	}

	/*
	 *	Wipe the context of all sensitive information.
	 */
	HMAC_CTX_free(hmac);

	return RLM_MODULE_UPDATED;
}

/*
 *	Generate the EPS-AKA authentication vector
 *
 *	These are the keys needed for new style WiMAX (LTE / 3gpp authentication),
 *  for WiMAX v2.1
 */
static unlang_action_t aka_keys_generate(rlm_rcode_t *p_result, request_t *request, fr_pair_t *ki, fr_pair_t *opc,
				     fr_pair_t *amf, fr_pair_t *sqn, fr_pair_t *plmn)
{
	size_t i;
	fr_pair_t *rand_previous, *rand, *xres, *autn, *kasme;

	/*
	 *	For most authentication requests we need to generate a fresh RAND
	 *
	 *	The exception is after SQN re-syncronisation - in this case we
	 *	get RAND in the request, and this module if called in authorize should
	 *	have put it in control:WiMAX-SIM-RAND so we can grab it from there)
	 */
	rand_previous = fr_pair_find_by_da(&request->control_pairs, attr_wimax_sim_rand);
	if (rand_previous && (rand_previous->vp_length < WIMAX_EPSAKA_RAND_SIZE)) {
		RWDEBUG("Found control:%s with incorrect size.  Ignoring it.", attr_wimax_sim_rand->name);
		rand_previous = NULL;
	}

	MEM(pair_update_reply(&rand, attr_wimax_e_utran_vector_rand) >= 0);
	if (!rand_previous) {
		uint32_t lvalue;
		uint8_t buffer[WIMAX_EPSAKA_RAND_SIZE];

		for (i = 0; i < (WIMAX_EPSAKA_RAND_SIZE / 4); i++) {
			lvalue = fr_rand();
			memcpy(buffer + i * 4, &lvalue, sizeof(lvalue));
		}

		fr_pair_value_memdup(rand, buffer, WIMAX_EPSAKA_RAND_SIZE, false);

	} else {
		fr_pair_value_memdup(rand, rand_previous->vp_octets, WIMAX_EPSAKA_RAND_SIZE, false);
	}

	/*
	 *	Feed AMF, Ki, SQN and RAND into the Milenage algorithm (f1, f2, f3, f4, f5)
	 *	which returns AUTN, AK, CK, IK, XRES.
	 */
	uint8_t xres_bin[WIMAX_EPSAKA_XRES_SIZE];
	uint8_t ck_bin[WIMAX_EPSAKA_CK_SIZE];
	uint8_t ik_bin[WIMAX_EPSAKA_IK_SIZE];
	uint8_t ak_bin[WIMAX_EPSAKA_AK_SIZE];
	uint8_t autn_bin[WIMAX_EPSAKA_AUTN_SIZE];

	if (!opc || (opc->vp_length < MILENAGE_OPC_SIZE)) {
		RWDEBUG("Found control:WiMAX-SIM-OPC with incorrect size.  Ignoring it");
		RETURN_MODULE_NOOP;
	}
	if (!amf || (amf->vp_length < MILENAGE_AMF_SIZE)) {
		RWDEBUG("Found control:WiMAX-SIM-AMF with incorrect size.  Ignoring it");
		RETURN_MODULE_NOOP;
	}
	if (!ki || (ki->vp_length < MILENAGE_KI_SIZE)) {
		RWDEBUG("Found control:WiMAX-SIM-KI with incorrect size.  Ignoring it");
		RETURN_MODULE_NOOP;
	}

	/* Call milenage */
	milenage_umts_generate(autn_bin, ik_bin, ck_bin, ak_bin, xres_bin, opc->vp_octets,
			       amf->vp_octets, ki->vp_octets, sqn->vp_uint64, rand->vp_octets);

	/*
	 *	Now we genertate KASME
	 *
	 *	Officially described in 33401-g30.doc section A.2
	 *	But an easier to read explanation can be found at:
	 *	https://medium.com/uw-ictd/lte-authentication-2d0810a061ec
	 *
	 */

	/* k = CK || IK */
	uint8_t kk_bin[WIMAX_EPSAKA_KK_SIZE];
	memcpy(kk_bin, ck_bin, sizeof(ck_bin));
	memcpy(kk_bin + sizeof(ck_bin), ik_bin, sizeof(ik_bin));

	/* Initialize a 14 byte buffer s */
	uint8_t ks_bin[WIMAX_EPSAKA_KS_SIZE];

	/* Assign the first byte of s as 0x10 */
	ks_bin[0] = 0x10;

	/* Copy the 3 bytes of PLMN into s */
	memcpy(ks_bin + 1, plmn->vp_octets, 3);

	/* Assign 5th and 6th byte as 0x00 and 0x03 */
	ks_bin[4] = 0x00;
	ks_bin[5] = 0x03;

	/* Assign the next 6 bytes as SQN XOR AK */
	uint8_t *sqn_byte = (uint8_t *)&sqn->vp_uint64;
	for (i = 0; i < 6; i++) {
		ks_bin[i+6] = sqn_byte[i] ^ ak_bin[i];
	}

	/* Assign the last two bytes as 0x00 and 0x06 */
	ks_bin[12] = 0x00;
	ks_bin[13] = 0x06;

	/* Perform an HMAC-SHA256 using Key k from step 1 and s as the message. */
	uint8_t kasme_bin[WIMAX_EPSAKA_KASME_SIZE];
	HMAC_CTX *hmac;
	unsigned int kasme_len = sizeof(kasme_bin);

	hmac = HMAC_CTX_new();
	HMAC_Init_ex(hmac, kk_bin, sizeof(kk_bin), EVP_sha256(), NULL);
	HMAC_Update(hmac, ks_bin, sizeof(ks_bin));
	HMAC_Final(hmac, &kasme_bin[0], &kasme_len);
	HMAC_CTX_free(hmac);

	/*
	 *	Add reply attributes XRES, AUTN and KASME (RAND we added earlier)
	 *
	 *	Note that we can't call fr_pair_find_by_num(), as
	 *	these attributes are buried deep inside of the WiMAX
	 *	hierarchy.
	 */
	MEM(pair_update_reply(&xres, attr_wimax_e_utran_vector_rand) >= 0);
	fr_pair_value_memdup(xres, xres_bin, WIMAX_EPSAKA_XRES_SIZE, false);

	MEM(pair_update_reply(&autn, attr_wimax_e_utran_vector_autn) >= 0);
	fr_pair_value_memdup(autn, autn_bin, WIMAX_EPSAKA_AUTN_SIZE, false);

	MEM(pair_update_reply(&kasme, attr_wimax_e_utran_vector_kasme) >= 0);
	fr_pair_value_memdup(kasme, kasme_bin, WIMAX_EPSAKA_KASME_SIZE, false);

	/* Print keys to log for debugging */
	if (RDEBUG_ENABLED3) {
		RDEBUG("-------- Milenage in --------");
		RHEXDUMP3(opc->vp_octets, opc->vp_length, "OPc   ");
		RHEXDUMP3(ki->vp_octets, ki->vp_length, "Ki    ");
		RHEXDUMP3(rand->vp_octets, rand->vp_length, "RAND  ");
		RHEXDUMP3((uint8_t *)&sqn->vp_uint64, WIMAX_EPSAKA_SQN_SIZE, "SQN   ");
		RHEXDUMP3(amf->vp_octets, amf->vp_length, "AMF   ");

		RDEBUG("-------- Milenage out -------");
		RHEXDUMP3(xres->vp_octets, xres->vp_length, "XRES  ");
		RHEXDUMP3(ck_bin, sizeof(ck_bin), "Ck    ");
		RHEXDUMP3(ik_bin, sizeof(ik_bin), "Ik    ");
		RHEXDUMP3(ak_bin, sizeof(ak_bin), "Ak    ");
		RHEXDUMP3(autn->vp_octets, autn->vp_length, "AUTN  ");

		RDEBUG("-----------------------------");
		RHEXDUMP3(kk_bin, sizeof(kk_bin), "Kk    ");
		RHEXDUMP3(ks_bin, sizeof(ks_bin), "Ks    ");
		RHEXDUMP3(kasme->vp_octets, kasme->vp_length, "KASME ");
	}

	RETURN_MODULE_UPDATED;
}

/*
 *	Generate the keys after the user has been authenticated.
 */
static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_wimax_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_wimax_t);
	fr_pair_t 		*msk, *emsk, *ki, *opc, *amf, *sqn, *plmn;

	/*
	 *	If we have MSK and EMSK then assume we want MIP keys
	 *	Else if we have the SIM keys then we want the EPS-AKA vector
	 */
	msk = fr_pair_find_by_da(&request->reply_pairs, attr_eap_msk);
	emsk = fr_pair_find_by_da(&request->reply_pairs, attr_eap_emsk);
	if (msk || emsk) {
		RDEBUG("MSK and EMSK found.  Generating MIP keys");
		return mip_keys_generate(inst, request, msk, emsk);
	}

	ki = fr_pair_find_by_da(&request->control_pairs, attr_sim_ki);
	opc = fr_pair_find_by_da(&request->control_pairs, attr_sim_opc);
	amf = fr_pair_find_by_da(&request->control_pairs, attr_sim_amf);
	sqn = fr_pair_find_by_da(&request->control_pairs, attr_sim_sqn);
	plmn = fr_pair_find_by_da(&request->request_pairs, attr_wimax_visited_plmn_id);

	if (ki && opc && amf && sqn && plmn) {
		RDEBUG("AKA attributes found.  Generating AKA keys.");
		return aka_keys_generate(p_result, request, ki, opc, amf, sqn, plmn);
	}

	RDEBUG("Input keys not found.  Cannot create WiMAX keys");
	RETURN_MODULE_NOOP;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_wimax;
module_t rlm_wimax = {
	.magic		= RLM_MODULE_INIT,
	.name		= "wimax",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_wimax_t),
	.config		= module_config,
	.dict		= &dict_radius,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
