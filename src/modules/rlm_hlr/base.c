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
 * @file src/modules/rlm_hlr/base.c
 * @brief Supports various HLR functionality.
 *
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2021 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hex.h>

#include "hlr.h"
#include "attrs.h"

fr_dict_t const *dict_radius;
fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_hlr_dict[];
fr_dict_autoload_t rlm_hlr_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

fr_dict_attr_t const *attr_eap_emsk;
fr_dict_attr_t const *attr_eap_msk;
fr_dict_attr_t const *attr_sim_ki;
fr_dict_attr_t const *attr_sim_opc;
fr_dict_attr_t const *attr_sim_amf;
fr_dict_attr_t const *attr_sim_sqn;

fr_dict_attr_t const *attr_wimax_mn_nai;
fr_dict_attr_t const *attr_wimax_sim_rand;

fr_dict_attr_t const *attr_calling_station_id;

fr_dict_attr_t const *attr_wimax_msk;
fr_dict_attr_t const *attr_wimax_ip_technology;
fr_dict_attr_t const *attr_wimax_mn_hha_mip4_key;
fr_dict_attr_t const *attr_wimax_mn_hha_mip4_spi;
fr_dict_attr_t const *attr_wimax_hha_ip_mip4;
fr_dict_attr_t const *attr_wimax_hha_ip_mip6;
fr_dict_attr_t const *attr_wimax_mn_hha_mip6_key;
fr_dict_attr_t const *attr_wimax_mn_hha_mip6_spi;
fr_dict_attr_t const *attr_wimax_fa_rk_key;
fr_dict_attr_t const *attr_wimax_fa_rk_spi;
fr_dict_attr_t const *attr_wimax_rrq_mn_ha_spi;
fr_dict_attr_t const *attr_wimax_rrq_ha_ip;
fr_dict_attr_t const *attr_wimax_ha_rk_key_requested;

fr_dict_attr_t const *attr_wimax_visited_plmn_id;

fr_dict_attr_t const *attr_wimax_e_utran_vector_item_number;
fr_dict_attr_t const *attr_wimax_e_utran_vector_rand;
fr_dict_attr_t const *attr_wimax_e_utran_vector_xres;
fr_dict_attr_t const *attr_wimax_e_utran_vector_autn;
fr_dict_attr_t const *attr_wimax_e_utran_vector_kasme;

fr_dict_attr_t const *attr_wimax_requested_eutran_authentication_info;
fr_dict_attr_t const *attr_wimax_number_of_requested_vectors;
fr_dict_attr_t const *attr_wimax_immediate_response_preferred;
fr_dict_attr_t const *attr_wimax_re_syncronization_info;

fr_dict_attr_t const *attr_ms_mppe_send_key;
fr_dict_attr_t const *attr_ms_mppe_recv_key;

extern fr_dict_attr_autoload_t rlm_hlr_dict_attr[];
fr_dict_attr_autoload_t rlm_hlr_dict_attr[] = {
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
 *	Process all fixup functions needed.
 */
void hlr_process_fixup(rlm_hlr_t const *inst, hlr_kdf_config_t const *config, request_t *request)
{
	fr_pair_t *vp;

	/*
	 *	Fix Calling-Station-Id.  Damn you, WiMAX!
	 */
	if (config->fixup.calling_station_id) {
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

			DEBUG2("%s - Fixing WiMAX binary %s to %pV", inst->name, attr_calling_station_id->name, &vp->data);
		}
	}
}

/*
 *	Clean up all desire attributes.
 */
void hlr_process_delete(rlm_hlr_t const *inst, hlr_kdf_config_t const *config, UNUSED request_t *request)
{
	talloc_foreach(config->delete_attr, item) {
		DEBUG2("%s - delete {} attr %s", inst->name, item->name);
	}
}
