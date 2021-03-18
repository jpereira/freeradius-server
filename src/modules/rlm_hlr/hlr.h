#pragma once
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
 * @file src/modules/rlm_hlr/hlr.h
 * @brief Supports various HLR functionality.
 *
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2021 The FreeRADIUS server project
 */

RCSIDH(rlm_hlr_hlr_h, "$Id$")

#include <freeradius-devel/eap/types.h>

#include <freeradius-devel/sim/milenage.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/sim/milenage.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/missing.h>
#include <freeradius-devel/util/hex.h>

typedef struct {
	struct {
		tmpl_t *amf;	//!< Authentication management field.
		tmpl_t *auts;	//!< Authentication token from client.
		tmpl_t *autn;	//!< Authentication token from network.
		tmpl_t *op;	//!< Operator Code.
		tmpl_t *opc;	//!< Operator variant algorithm configuration field.
		tmpl_t *plmn_id;//!< Public land mobile network identity.
		tmpl_t *kasme;	//!< Key Access Security Management Entries.
		tmpl_t *ki;	//!< Key Identification.
		tmpl_t *sqn;	//!< Sequence number.
		tmpl_t *rand;	//!< RANDom number.
		tmpl_t *xres;	//!< 
	} in;

	struct {
		tmpl_t *amf;	//!< Authentication management field.
		tmpl_t *auts;	//!< Authentication token from client.
		tmpl_t *autn;	//!< Authentication token from network.
		tmpl_t *op;	//!< Operator Code.
		tmpl_t *opc;	//!< Operator variant algorithm configuration field.
		tmpl_t *plmn_id;//!< Public land mobile network identity.
		tmpl_t *kasme;	//!< Key Access Security Management Entries.
		tmpl_t *ki;	//!< Key Identification.
		tmpl_t *sqn;	//!< Sequence number.
		tmpl_t *rand;	//!< RANDom number.
		tmpl_t *xres;	//!< 
	} out;

	tmpl_t **delete_attr;			//!< Holds all attributes expected to be deleted over the delete{} section.

	struct {
		bool calling_station_id;	//!<
	} fixup;	//!< With all _fixups_ needed to bypass some specifications mistakes.
} hlr_kdf_config_t;

typedef struct {
	hlr_kdf_config_t eps_aka;		//!< All settings for eps-aka{} section.
	hlr_kdf_config_t milenage_mip;		//!< All settings for milenage-mip{} section.
} hlr_config_t;

typedef struct {
	char const	*name;		//!< Config name instance.
	hlr_config_t 	config;		//!< Config set for all supported keys.
	tmpl_t 		**op_selection;	//!< OP value for this module instance.
} rlm_hlr_t;

/* base.c */
void hlr_process_fixup(rlm_hlr_t const *inst, hlr_kdf_config_t const *config, request_t *request);

void hlr_process_delete(rlm_hlr_t const *inst, hlr_kdf_config_t const *config, request_t *request);

/* hlr_eps_aka.c */
unlang_action_t hlr_eps_aka_handle(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request);

/* hlr_milenage_mip.c */
unlang_action_t hlr_milenage_mip_handle(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request);
