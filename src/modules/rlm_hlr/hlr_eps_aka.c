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
 * @file src/modules/rlm_hlr/hlr_eps_aka.c
 * @brief Handle EPS-AKA keys
 *
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2021 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "hlr.h"
#include "attrs.h"

static const CONF_PARSER eps_aka_in_config[] = {
	{ FR_CONF_OFFSET("amf", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_hlr_t, config.eps_aka.in.amf), .dflt = "%{control.SIM-AMF}", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("opc", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_hlr_t, config.eps_aka.in.opc), .dflt = "%{control.SIM-OPc}", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("ki", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_hlr_t, config.eps_aka.in.ki), .dflt = "%{control.SIM-Ki}", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("sqn", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_hlr_t, config.eps_aka.in.sqn), .dflt = "%{control.SIM-SQN}", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("plmn_id", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_hlr_t, config.eps_aka.in.plmn_id) },
	{ FR_CONF_OFFSET("rand", FR_TYPE_TMPL, rlm_hlr_t, config.eps_aka.in.rand) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER eps_aka_out_config[] = {
	{ FR_CONF_OFFSET("autn", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_hlr_t, config.eps_aka.out.autn), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("kasme", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_hlr_t, config.eps_aka.out.kasme), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("xres", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_hlr_t, config.eps_aka.out.xres), .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("rand", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_hlr_t, config.eps_aka.out.rand), .quote = T_BARE_WORD },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER eps_aka_delete_config[] = {
	{ FR_CONF_OFFSET("attr", FR_TYPE_TMPL | FR_TYPE_MULTI | FR_TYPE_ATTRIBUTE, rlm_hlr_t, config.eps_aka.delete_attr), .quote = T_BARE_WORD },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER eps_aka_fixup_config[] = {
	{ FR_CONF_OFFSET("calling_station_id", FR_TYPE_BOOL, rlm_hlr_t, config.eps_aka.fixup.calling_station_id), .quote = T_BARE_WORD },

	CONF_PARSER_TERMINATOR
};

const CONF_PARSER eps_aka_config[] = {
	{ FR_CONF_POINTER("in", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) eps_aka_in_config },
	{ FR_CONF_POINTER("out", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) eps_aka_out_config },
	{ FR_CONF_POINTER("delete", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) eps_aka_delete_config },
	{ FR_CONF_POINTER("fixup", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) eps_aka_fixup_config },

	CONF_PARSER_TERMINATOR
};

/*
 *	Generate the EPS-AKA authentication vector
 *
 *	These are the keys needed for new style WiMAX (LTE / 3gpp authentication),
 *	for WiMAX v2.1
 */
unlang_action_t hlr_eps_aka_handle(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_hlr_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_hlr_t);
	hlr_kdf_config_t const *config = &inst->config.eps_aka;

	/*
	 *	Process the fixup functions
	 */
	hlr_process_fixup(inst, config, request);

	// 1st. as the previous post_auth
	// aka_keys_generate(VALUE_PAIR *ki, VALUE_PAIR *opc, VALUE_PAIR *amf, VALUE_PAIR *sqn, VALUE_PAIR *plmn)
	if (1) {
		uint8_t rand_buf[MILENAGE_RAND_SIZE*4];
		uint8_t *rand_out = NULL;
		fr_pair_t *rand = NULL;
		int ret = 0;

		/*
		 *	For most authentication requests we need to generate a fresh RAND
		 *
		 *	The exception is after SQN re-syncronisation - in this case we
		 *	get RAND in the request, and this module if called in authorize should
		 *	have put it in control:WiMAX-SIM-RAND so we can grab it from there)
		 */
		if (!config->out.rand) {
			RWDEBUG2("Couldn't continue without the 'eps-aka.out { rand = &att }'");
			RETURN_MODULE_NOOP;
		}

		/*
		 *	For most authentication requests we need to generate a fresh RAND
		 *
		 *	The exception is after SQN re-syncronisation - in this case we
		 *	get RAND in the request, and this module if called in authorize should
		 *	have put it in control:WiMAX-SIM-RAND so we can grab it from there)
		 */
		if (tmpl_find_or_add_vp(&rand, request, config->out.rand) < 0) {
			RWDEBUG2("Couldn't find %s attribute, doing nothing...", config->out.rand->name);
			RETURN_MODULE_NOOP;
		}

		if (config->in.rand) {
			ret = tmpl_expand(&rand_out, rand_buf, sizeof(rand_buf), request, config->in.rand, NULL, NULL);
			if (ret > 0) {
				RDEBUG2("Using RAND from %s", config->in.rand->name);
			}
		}

		if (!ret) {
			uint32_t lvalue;
			size_t i;

			RDEBUG2("Generate RAND in %s", config->out.rand->name);
			for (i = 0; i < (MILENAGE_RAND_SIZE / 4); i++) {
				lvalue = fr_rand();
				memcpy(rand_buf + i * 4, &lvalue, sizeof(lvalue));
			}
			rand_out = rand_buf;
		}

		fr_pair_value_memdup(rand, rand_out, MILENAGE_RAND_SIZE, false);

		/*
		 *	Feed AMF, Ki, SQN and RAND into the Milenage algorithm (f1, f2, f3, f4, f5)
		 *	which returns AUTN, AK, CK, IK, XRES.
		 */
		fr_pair_t *xres = NULL;//, *autn = NULL, *kasme = NULL;
		uint8_t *opc = NULL, opc_buf[MILENAGE_OPC_SIZE*2];
		uint8_t *amf = NULL, amf_buf[MILENAGE_AMF_SIZE*2];
		uint8_t *ki = NULL, ki_buf[MILENAGE_KI_SIZE*2];
		uint64_t sqn = 0, plmn_id = 0;
		uint8_t sqn_buf[MILENAGE_SQN_SIZE], plmn_id_buf[MILENAGE_SQN_SIZE];

		uint8_t xres_bin[MILENAGE_XRES_SIZE];
		uint8_t ck_bin[MILENAGE_CK_SIZE];
		uint8_t ik_bin[MILENAGE_IK_SIZE];
		uint8_t ak_bin[MILENAGE_AK_SIZE];
		uint8_t autn_bin[MILENAGE_AUTN_SIZE];
		uint8_t kasme_bin[MILENAGE_KASME_SIZE];

		ret = tmpl_expand(&opc, opc_buf, sizeof(opc_buf), request, config->in.opc, NULL, NULL);
		if (ret < MILENAGE_OPC_SIZE) {
			RWDEBUG("Found %s with incorrect size. Ignoring it", config->in.opc->name);
			RETURN_MODULE_NOOP;
		}

		ret = tmpl_expand(&amf, amf_buf, sizeof(amf_buf), request, config->in.amf, NULL, NULL);
		if (ret < MILENAGE_AMF_SIZE) {
			RWDEBUG("Found %s with incorrect size. Ignoring it", config->in.amf->name);
			RETURN_MODULE_NOOP;
		}

		ret = tmpl_expand(&ki, ki_buf, sizeof(ki_buf), request, config->in.ki, NULL, NULL);
		if (ret < MILENAGE_KI_SIZE) {
			RWDEBUG("Found %s with incorrect size. Ignoring it", config->in.ki->name);
			RETURN_MODULE_NOOP;
		}

		ret = tmpl_expand(&sqn, sqn_buf, sizeof(sqn_buf), request, config->in.sqn, NULL, NULL);
		if (ret < 0) {
			RWDEBUG("Found %s with incorrect size. Ignoring it", config->in.sqn->name);
			RETURN_MODULE_NOOP;
		}

		ret = tmpl_expand(&plmn_id, plmn_id_buf, sizeof(plmn_id_buf), request, config->in.plmn_id, NULL, NULL);
		if (ret < 0) {
			RWDEBUG("Found %s with incorrect size. Ignoring it", config->in.plmn_id->name);
			RETURN_MODULE_NOOP;
		}

		/* Call milenage */
		milenage_umts_generate(autn_bin, ik_bin, ck_bin, ak_bin, xres_bin, opc, amf, ki, sqn, rand_out);

		/* Now we generate KASME */
		milenage_kasme_generate(kasme_bin, ck_bin, ik_bin, ak_bin, plmn_id, sqn);

		/*
		 *	Add attributes XRES, AUTN and KASME (RAND we added earlier)
		 */
		if (tmpl_find_or_add_vp(&xres, request, config->out.xres) < 0) {
			RWDEBUG2("Couldn't find %s attribute, doing nothing...", config->out.xres->name);
			RETURN_MODULE_NOOP;
		}
		xres->vp_uint32 = 111;
		// fr_pair_value_memdup(xres, xres_bin, MILENAGE_XRES_SIZE, false);

		// if (tmpl_find_or_add_vp(&autn, request, config->out.autn) < 0) {
		// 	RWDEBUG2("Couldn't find %s attribute, doing nothing...", config->out.autn->name);
		// 	RETURN_MODULE_NOOP;
		// }
		// // fr_pair_value_memdup(autn, autn_bin, MILENAGE_AUTN_SIZE, false);
		// autn->vp_uint32 = 222;

		// if (tmpl_find_or_add_vp(&kasme, request, config->out.kasme) < 0) {
		// 	RWDEBUG2("Couldn't find %s attribute, doing nothing...", config->out.kasme->name);
		// 	RETURN_MODULE_NOOP;
		// }
		// // fr_pair_value_memdup(kasme, kasme_bin, MILENAGE_KASME_SIZE, false);
		// kasme->vp_uint32 = 333;

		RETURN_MODULE_UPDATED;
	}

#if 0
	// 2st. As the previous mod_authorize()
	/*
	 *	Check for attr WiMAX.Requested-EUTRAN-Authentication-Info.Re-synchronization-Info
	 *	which contains the concatenation of RAND and AUTS
	 *
	 *	If it is present then we proceed to verify the SIM and
	 *	extract the new value of SQN
	 */

	/* Look for the Re-synchronization-Info attribute in the request */
	resync_info = fr_pair_find_by_da(&request->request_pairs, attr_wimax_re_syncronization_info);
	if (resync_info && (resync_info->vp_length < (MILENAGE_RAND_SIZE + MILENAGE_AUTS_SIZE))) {
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
		uint8_t rand_bin[MILENAGE_RAND_SIZE];
		uint8_t auts_bin[MILENAGE_AUTS_SIZE];

		RDEBUG("Found WiMAX.Re-synchronization-Info. Proceeding with SQN resync");

		/* Split Re-synchronization-Info into seperate RAND and AUTS */
		memcpy(rand_bin, &resync_info->vp_octets[0], MILENAGE_RAND_SIZE);
		memcpy(auts_bin, &resync_info->vp_octets[MILENAGE_RAND_SIZE], MILENAGE_AUTS_SIZE);

		RHEXDUMP3(rand_bin, MILENAGE_RAND_SIZE, "RAND   (%d bytes)", MILENAGE_RAND_SIZE);
		RHEXDUMP3(auts_bin, MILENAGE_AUTS_SIZE, "AUTS   (%d bytes)", MILENAGE_AUTS_SIZE);

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
		const uint8_t sqn_bin_arr[MILENAGE_SQN_SIZE] = {
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
			memcpy(&sqn->vp_uint64, sqn_bin_arr, MILENAGE_SQN_SIZE);
		}

		RHEXDUMP3((uint8_t *)&sqn->vp_uint64, MILENAGE_SQN_SIZE, "SQN   (%d bytes)", MILENAGE_SQN_SIZE);

		/* Add RAND to control:WiMAX.SIM-RAND */
		rand = fr_pair_find_by_da(&request->control_pairs, attr_wimax_sim_rand);
		if (rand && (rand->vp_length < MILENAGE_RAND_SIZE)) {
			RWDEBUG("Found control:%s with incorrect length: Ignoring it", attr_wimax_sim_rand->name);
			rand = NULL;
		}

		if (!rand) {
			MEM(pair_update_control(&rand, attr_wimax_sim_rand) >= 0);
			fr_pair_value_memdup(rand, rand_bin, MILENAGE_RAND_SIZE, true);
		}
		RHEXDUMP3(rand->vp_octets, MILENAGE_RAND_SIZE, "RAND   (%d bytes)", MILENAGE_RAND_SIZE);

		goto done;
	}
#endif

	/**
	 *	Once everything is ok, process the delete{} section
	 */
	hlr_process_delete(inst, config, request);

	RETURN_MODULE_UPDATED;
}
