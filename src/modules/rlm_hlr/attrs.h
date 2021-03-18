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
 * @file src/modules/rlm_hlr/attrs.h
 * @brief HLR attributes
 *
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2021 The FreeRADIUS server project
 */

RCSIDH(rlm_hlr_attrs_h, "$Id$")

extern fr_dict_t const *dict_radius;
extern fr_dict_t const *dict_freeradius;

extern fr_dict_attr_t const *attr_eap_emsk;
extern fr_dict_attr_t const *attr_eap_msk;
extern fr_dict_attr_t const *attr_sim_ki;
extern fr_dict_attr_t const *attr_sim_opc;
extern fr_dict_attr_t const *attr_sim_amf;
extern fr_dict_attr_t const *attr_sim_sqn;

extern fr_dict_attr_t const *attr_wimax_mn_nai;
extern fr_dict_attr_t const *attr_wimax_sim_rand;

extern fr_dict_attr_t const *attr_calling_station_id;

extern fr_dict_attr_t const *attr_wimax_msk;
extern fr_dict_attr_t const *attr_wimax_ip_technology;
extern fr_dict_attr_t const *attr_wimax_mn_hha_mip4_key;
extern fr_dict_attr_t const *attr_wimax_mn_hha_mip4_spi;
extern fr_dict_attr_t const *attr_wimax_hha_ip_mip4;
extern fr_dict_attr_t const *attr_wimax_hha_ip_mip6;
extern fr_dict_attr_t const *attr_wimax_mn_hha_mip6_key;
extern fr_dict_attr_t const *attr_wimax_mn_hha_mip6_spi;
extern fr_dict_attr_t const *attr_wimax_fa_rk_key;
extern fr_dict_attr_t const *attr_wimax_fa_rk_spi;
extern fr_dict_attr_t const *attr_wimax_rrq_mn_ha_spi;
extern fr_dict_attr_t const *attr_wimax_rrq_ha_ip;
extern fr_dict_attr_t const *attr_wimax_ha_rk_key_requested;

extern fr_dict_attr_t const *attr_wimax_visited_plmn_id;

extern fr_dict_attr_t const *attr_wimax_e_utran_vector_item_number;
extern fr_dict_attr_t const *attr_wimax_e_utran_vector_rand;
extern fr_dict_attr_t const *attr_wimax_e_utran_vector_xres;
extern fr_dict_attr_t const *attr_wimax_e_utran_vector_autn;
extern fr_dict_attr_t const *attr_wimax_e_utran_vector_kasme;

extern fr_dict_attr_t const *attr_wimax_requested_eutran_authentication_info;
extern fr_dict_attr_t const *attr_wimax_number_of_requested_vectors;
extern fr_dict_attr_t const *attr_wimax_immediate_response_preferred;
extern fr_dict_attr_t const *attr_wimax_re_syncronization_info;

extern fr_dict_attr_t const *attr_ms_mppe_send_key;
extern fr_dict_attr_t const *attr_ms_mppe_recv_key;
