
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
 * @file src/modules/rlm_hlr/rlm_hlr.c
 * @brief Supports various HLR functionality.
 *
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2021 The FreeRADIUS server project
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_hlr - "

#include "hlr.h"
#include "attrs.h"

extern const CONF_PARSER eps_aka_config[];
extern const CONF_PARSER milenage_mip_config[];

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("op_selection", FR_TYPE_TMPL | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, rlm_hlr_t, op_selection) },

	{ FR_CONF_POINTER("eps-aka", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *)eps_aka_config },
	{ FR_CONF_POINTER("milenage-mip", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *)milenage_mip_config },

	CONF_PARSER_TERMINATOR
};

static int mod_bootstrap(UNUSED void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_hlr_t *inst = talloc_get_type_abort_const(instance, rlm_hlr_t);

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	return 0;
}

extern module_t rlm_hlr;
module_t rlm_hlr = {
	.magic		= RLM_MODULE_INIT,
	.name		= "hlr",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_hlr_t),
	.bootstrap	= mod_bootstrap,
	.config		= module_config,
	.dict		= &dict_radius,
	.method_names = (module_method_names_t[]){
		{ .name1 = "eps-aka", .name2 = CF_IDENT_ANY, .method = hlr_eps_aka_handle },
		{ .name1 = "milenage-mip", .name2 = CF_IDENT_ANY, .method = hlr_milenage_mip_handle },

		MODULE_NAME_TERMINATOR
	}
};
