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
 * @file src/modules/rlm_hlr/hlr_milenage_mip.h
 * @brief Handle Milenage MIP keys
 *
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2021 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "hlr.h"
#include "attrs.h"

static const CONF_PARSER milenage_mip_in_config[] = {
	{ FR_CONF_OFFSET("amf", FR_TYPE_TMPL, rlm_hlr_t, config.milenage_mip.in.amf), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("auts", FR_TYPE_TMPL, rlm_hlr_t, config.milenage_mip.in.auts), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("op", FR_TYPE_TMPL, rlm_hlr_t, config.milenage_mip.in.op), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("opc", FR_TYPE_TMPL, rlm_hlr_t, config.milenage_mip.in.opc), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("plmn_id", FR_TYPE_TMPL, rlm_hlr_t, config.milenage_mip.in.plmn_id), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("kasme", FR_TYPE_TMPL, rlm_hlr_t, config.milenage_mip.in.kasme), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("ki", FR_TYPE_TMPL, rlm_hlr_t, config.milenage_mip.in.ki), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("sqn", FR_TYPE_TMPL, rlm_hlr_t, config.milenage_mip.in.sqn), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("rand", FR_TYPE_TMPL, rlm_hlr_t, config.milenage_mip.in.rand), .quote = T_BARE_WORD },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER milenage_mip_out_config[] = {
	{ FR_CONF_OFFSET("amf", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.in.amf), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("auts", FR_TYPE_TMPL| FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.in.auts), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("op", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.in.op), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("opc", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.in.opc), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("plmn_id", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.in.plmn_id), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("kasme", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.in.kasme), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("ki", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.in.ki), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("sqn", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.in.sqn), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("rand", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.in.rand), .quote = T_BARE_WORD },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER milenage_mip_delete_config[] = {
	{ FR_CONF_OFFSET("attr", FR_TYPE_TMPL | FR_TYPE_MULTI | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.milenage_mip.delete_attr), .quote = T_BARE_WORD },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER milenage_mip_fixup_config[] = {
	{ FR_CONF_OFFSET("calling_station_id", FR_TYPE_BOOL, rlm_hlr_t, config.milenage_mip.fixup.calling_station_id), .quote = T_BARE_WORD },

	CONF_PARSER_TERMINATOR
};

const CONF_PARSER milenage_mip_config[] = {
	{ FR_CONF_POINTER("in", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) milenage_mip_in_config },
	{ FR_CONF_POINTER("out", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) milenage_mip_out_config },
	{ FR_CONF_POINTER("delete", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) milenage_mip_delete_config },
	{ FR_CONF_POINTER("fixup", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) milenage_mip_fixup_config },

	CONF_PARSER_TERMINATOR
};

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
unlang_action_t hlr_milenage_mip_handle(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_hlr_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_hlr_t);
	hlr_kdf_config_t const *config = &inst->config.milenage_mip;
	fr_pair_t *vp, *msk, *emsk, *mn_nai, *fa_rk;
	fr_milenage_mip_ip_type_t ip_type = MILENAGE_MIP_IP_TYPE_NONE;

	/*
	 *	If we have MSK and EMSK then assume we want MIP keys
	 */
	msk = fr_pair_find_by_da(&request->reply_pairs, attr_eap_msk);
	emsk = fr_pair_find_by_da(&request->reply_pairs, attr_eap_emsk);
	if (!msk || !emsk) {
		RDEBUG("MSK or EMSK not found. Ignoring");
		RETURN_MODULE_NOOP;
	}

	RDEBUG("MSK and EMSK found.  Generating MIP keys");

	/*
	 *	Process the fixup functions
	 */
	hlr_process_fixup(inst, config, request);

	// RDEBUG("############# rand = %vP", config->in.rand);

	/*
	 *	Check mobility keys
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
		RETURN_MODULE_NOOP;
	} else {
		ip_type = (uint32_t)vp->vp_uint32;
	}

	if (ip_type != MILENAGE_MIP_IP_TYPE_NONE) {
		int ret;
		uint8_t mip_key[EVP_MAX_MD_SIZE];
		uint32_t mip_spi;
		size_t mip_len;
		uint8_t fa_rk_key[EVP_MAX_MD_SIZE];
		uint32_t fa_rk_spi;
		size_t fa_rk_len;
		fr_pair_t *ip;
		fr_dict_attr_t const *attr_mip_ip, *attr_mip_key, *attr_mip_spi;

		switch(ip_type) {
		case MILENAGE_MIP_IP_TYPE_PMIP4:
			attr_mip_ip  = attr_wimax_hha_ip_mip4;
			attr_mip_key = attr_wimax_mn_hha_mip4_key;
			attr_mip_spi = attr_wimax_mn_hha_mip4_spi;
			break;
		case MILENAGE_MIP_IP_TYPE_CMIP4:
			attr_mip_ip  = attr_wimax_hha_ip_mip4;
			attr_mip_key = attr_wimax_mn_hha_mip4_key;
			attr_mip_spi = attr_wimax_mn_hha_mip4_spi;
			break;
		case MILENAGE_MIP_IP_TYPE_CMIP6:
			attr_mip_ip  = attr_wimax_hha_ip_mip6;
			attr_mip_key = attr_wimax_mn_hha_mip6_key;
			attr_mip_spi = attr_wimax_mn_hha_mip6_spi;
			break;
		default:
			RERROR("%s has a invalid value: %d", attr_wimax_ip_technology->name, (int)ip_type);
			RETURN_MODULE_NOOP;
		}

		/*
		 *	Look for WiMAX.hHA-IP-XXX
		 */
		ip = fr_pair_find_by_da(&request->reply_pairs, attr_mip_ip);
		if (!ip) {
			RWDEBUG("%s not found.  Cannot calculate (MN-HA-PMIP4|MN-HA-PMIP6) key", attr_mip_ip->name);
			RETURN_MODULE_NOOP;
		}

		/*
		 *	Calculate MIP keys
		 */
		ret = milenage_mip_generate(mip_key, &mip_len, &mip_spi, fa_rk_key, &fa_rk_len, &fa_rk_spi,
							emsk->vp_octets, mn_nai->vp_strvalue, mn_nai->vp_length, ip_type, &ip->vp_ip);
	
		if (ret < 0) {
			RERROR("Problems calculating MIP keys: %s", fr_strerror());
			RETURN_MODULE_NOOP;
		}

		/*
		 *	Put MN-HA-XXX into WiMAX.MN-hHA-XXX-Key
		 */
		MEM(pair_update_reply(&vp, attr_mip_key) >= 0);
		fr_pair_value_memdup(vp, mip_key, mip_len, false);

		/*
		 *	Put MN-HA-PMIP4-SPI into WiMAX.MN-hHA-XXX-SPI
		 */
		MEM(pair_update_reply(&vp, attr_mip_spi) >= 0);
		vp->vp_uint32 = mip_spi;

		/*
		 *	Put FA-RK, if requested.
		 */
		fa_rk = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_fa_rk_key);
		if (fa_rk && (fa_rk->vp_length <= 1)) {
			fr_pair_value_memdup(fa_rk, fa_rk_key, fa_rk_len, false);
		}

		/*
		 *	Create FA-RK-SPI, which is really SPI-CMIP4, which is
		 *	really MIP-SPI.  Clear?  Of course.  This is WiMAX.
		 */
		if (fa_rk) {
			MEM(pair_update_reply(&vp, attr_wimax_fa_rk_spi) >= 0);
			vp->vp_uint32 = fa_rk_spi;
		}
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

	/**
	 *	Once everything is ok, process the delete{} section
	 */
	hlr_process_delete(inst, config, request);

	RETURN_MODULE_UPDATED;
}
