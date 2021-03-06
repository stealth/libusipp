/* Mostly taken from:
 *
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012, 2013 Markus Amend <markus@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <daniel@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */
#ifndef usipp_80211_h
#define usipp_80211_h


#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <asm/byteorder.h>

#define __packed __attribute__((packed))

namespace usipp {

namespace ieee80211 {

/* Note: Fields are encoded in little-endian! */
struct frame_ctrl {
	union {
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
		uint16_t version:2,
			  type:2,
			  subtype:4,
			  to_ds:1,
			  from_ds:1,
			  more_frags:1,
			  retry:1,
			  power_mgmt:1,
			  more_data:1,
			  wep:1,
			  order:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint16_t subtype:4,
			  type:2,
			  version:2,
			  order:1,
			  wep:1,
			  more_data:1,
			  power_mgmt:1,
			  retry:1,
			  more_frags:1,
			  from_ds:1,
			  to_ds:1;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
	} bits;
	uint16_t value;
	};
} __packed;

/* Management Frame start */
/* Note: Fields are encoded in little-endian! */
struct mgmt {
	uint16_t duration;
	uint8_t da[6];
	uint8_t sa[6];
	uint8_t bssid[6];
	uint16_t seq_ctrl;
} __packed;

struct mgmt_auth {
	uint16_t auth_alg;
	uint16_t auth_transaction;
	uint16_t status_code;
	/* possibly followed by Challenge text */
	//uint8_t variable[1];
} __packed;

struct mgmt_deauth {
	uint16_t reason_code;
} __packed;

struct mgmt_assoc_req {
	uint16_t capab_info;
	uint16_t listen_interval;
	/* followed by SSID and Supported rates */
	//uint8_t variable[1];
} __packed;

struct mgmt_assoc_resp {
	uint16_t capab_info;
	uint16_t status_code;
	uint16_t aid;
	/* followed by Supported rates */
	//uint8_t variable[1];
} __packed;

struct mgmt_reassoc_resp {
	uint16_t capab_info;
	uint16_t status_code;
	uint16_t aid;
	/* followed by Supported rates */
	//uint8_t variable[1];
} __packed;

struct mgmt_reassoc_req {
	uint16_t capab_info;
	uint16_t listen_interval;
	uint8_t current_ap[6];
	/* followed by SSID and Supported rates */
	//uint8_t variable[1];
} __packed;

struct mgmt_disassoc {
	uint16_t reason_code;
} __packed;

struct mgmt_probe_req {
} __packed;

struct mgmt_beacon {
	uint64_t timestamp;
	uint16_t beacon_int;
	uint16_t capab_info;
	/* followed by some of SSID, Supported rates,
	  * FH Params, DS Params, CF Params, IBSS Params, TIM */
	//uint8_t variable[1];
} __packed;

struct mgmt_probe_resp {
	uint8_t timestamp[8];
	uint16_t beacon_int;
	uint16_t capab_info;
	/* followed by some of SSID, Supported rates,
	  * FH Params, DS Params, CF Params, IBSS Params, TIM */
	//uint8_t variable[1];
} __packed;
/* Management Frame end */


struct ctrl_rts {
	uint16_t duration;
	uint8_t da[6];
	uint8_t sa[6];
} __packed;

struct ctrl_cts {
	uint16_t duration;
	uint8_t da[6];
} __packed;

struct ctrl_ack {
	uint16_t duration;
	uint8_t da[6];
} __packed;

struct ctrl_ps_poll {
	uint16_t aid;
	uint8_t bssid[6];
	uint8_t sa[6];
} __packed;

struct ctrl_cf_end {
	uint16_t duration;
	uint8_t bssid[6];
	uint8_t sa[6];
} __packed;

struct ctrl_cf_end_ack {
	uint16_t duration;
	uint8_t bssid[6];
	uint8_t sa[6];
} __packed;
/* Control Frame end */

/* Data Frame start */
/* Note: Fields are encoded in little-endian! */
struct data_frame {
	uint16_t duration;
	uint8_t da[6];
	uint8_t sa[6];
	int8_t bssid[6];
	uint16_t seq_ctrl;
} __packed;

/* TODO: Extend */
/* Data Frame end */

struct element_reserved {
	uint8_t etype;
	uint8_t len;
} __packed;

struct element_ssid {
	uint8_t etype;
	uint8_t len;
	uint8_t SSID[32];
} __packed;

struct element_supp_rates {
	uint8_t etype;
	uint8_t len;
	uint8_t rates[8];	// no more than 8 rates. more must use ext_rates
} __packed;

struct element_fh_ps {
	uint8_t etype;
	uint8_t len;
	uint16_t dwell_time;
	uint8_t hop_set;
	uint8_t hop_pattern;
	uint8_t hop_index;
} __packed;

struct element_dsss_ps {
	uint8_t etype;
	uint8_t len;
	uint8_t curr_ch;
} __packed;

struct element_cf_ps {
	uint8_t etype;
	uint8_t len;
	uint8_t cfp_cnt;
	uint8_t cfp_period;
	uint16_t cfp_max_dur;
	uint16_t cfp_dur_rem;
} __packed;


// 802.11-2012 Section 8.4.2.27: RSNE for lists with len=1
struct element_rsn_1 {
	uint8_t etype;
	uint8_t len;
	uint16_t version;
	uint32_t gcs;		// group cipher suite
	uint16_t gcs_count;	// 1
	uint32_t pcsl;		// pairwise cipher suite list
	uint16_t akms_count;	// akm suite count (1)
	uint32_t akml;		// auth key management list
	uint16_t rsn_caps;	// RSN capabilities
	uint16_t pkmid_count;	// 1
	uint8_t pkmidl[16];
	uint32_t gmcs;		// group mgmt cipher suite
} __packed;


struct element_tim {
	uint8_t etype;
	uint8_t len;
	uint8_t dtim_cnt;
	uint8_t dtim_period;
	uint8_t bmp_cntrl;
	uint8_t part_virt_bmp[1];
} __packed;

struct element_ibss_ps {
	uint8_t etype;
	uint8_t len;
	uint16_t atim_win;
} __packed;

struct element_country_tripled {
	uint8_t etype;
	uint8_t frst_ch;
	uint8_t nr_ch;
	uint8_t max_trans;
} __packed;

struct element_country {
	uint8_t etype;
	uint8_t len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
	uint8_t country_first;
	uint8_t country_sec;
	uint8_t country_third;
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint8_t country_third;
	uint8_t country_sec;
	uint8_t country_first;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
	/* triplet may repeat */
	struct element_country_tripled tripled [1];
	/*uint8_t pad[0];*/
} __packed;

struct element_hop_pp {
	uint8_t etype;
	uint8_t len;
	uint8_t prime_radix;
	uint8_t nr_ch;
} __packed;

struct element_hop_pt {
	uint8_t etype;
	uint8_t len;
	uint8_t flag;
	uint8_t nr_sets;
	uint8_t modules;
	uint8_t offs;
	uint8_t rand_tabl[1];
} __packed;

struct element_req {
	uint8_t etype;
	uint8_t len;
	uint8_t req_elem_idl[1];
} __packed;

struct element_bss_load {
	uint8_t etype;
	uint8_t len;
	uint16_t station_cnt;
	uint8_t ch_util;
	uint16_t avlb_adm_cap;
} __packed;

struct element_edca_ps {
	uint8_t etype;
	uint8_t len;
	uint8_t qos_inf;
	uint8_t res;
	uint32_t ac_be;
	uint32_t ac_bk;
	uint32_t ac_vi;
	uint32_t ac_vo;
} __packed;

struct element_tspec {
	uint8_t etype;
	union {
		uint32_t len_ts_info;
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
		 uint32_t len:8,
				  traffic_type:1,
				  tsid:4,
				  direction:2,
				  access_policy:2,
				  aggr:1,
				  apsd:1,
				  user_prior:3,
				  tsinfo_ack_pol:2,
				  schedule:1,
				  res:7;
#elif defined(__BIG_ENDIAN_BITFIELD)
		 uint32_t len:8,
				  res:7,
				  schedule:1,
				  tsinfo_ack_pol:2,
				  user_prior:3,
				  apsd:1,
				  aggr:1,
				  access_policy:2,
				  direction:2,
				  tsid:4,
				  traffic_type:1;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
	} bits;
	};
	uint16_t nom_msdu_size;
	uint16_t max_msdu_size;
	uint32_t min_srv_intv;
	uint32_t max_srv_intv;
	uint32_t inactive_intv;
	uint32_t susp_intv;
	uint32_t srv_start_time;
	uint32_t min_data_rate;
	uint32_t mean_data_rate;
	uint32_t peak_data_rate;
	uint32_t burst_size;
	uint32_t delay_bound;
	uint32_t min_phy_rate;
	uint16_t surplus_bandw_allow;
	uint16_t med_time;
} __packed;

struct element_tclas {
	uint8_t etype;
	uint8_t len;
	uint8_t user_priority;
	uint8_t frm_class[1];
} __packed;

struct element_tclas_frm_class {
	uint8_t mask;
	uint8_t param[1];
} __packed;

struct element_tclas_type0 {
	uint8_t sa[6];
	uint8_t da[6];
	uint16_t type;
} __packed;

struct element_tclas_type1 {
	uint8_t version;
	uint8_t subparam[1];
} __packed;

struct element_tclas_type1_ip4 {
	uint32_t sa;
	uint32_t da;
	uint16_t sp;
	uint16_t dp;
	uint8_t dscp;
	uint8_t proto;
	uint8_t reserved;
} __packed;

struct element_tclas_type1_ip6 {
	in6_addr sa;
	in6_addr da;
	uint16_t sp;
	uint16_t dp;
	union {
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		 uint8_t  flow_label3:8;
		 uint8_t  flow_label2:8;
		 uint8_t  flow_label1:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
		 uint8_t  flow_label1:8;
		 uint8_t  flow_label2:8;
		 uint8_t  flow_label3:8;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		} bits;
		uint8_t value[3];
	} flow_label;
} __packed;

struct element_tclas_type2 {
	uint16_t vlan_tci;
} __packed;

struct element_tclas_type3 {
	uint16_t offs;
	uint8_t data[1]; /* value, masks */
} __packed;

struct element_tclas_type4 {
	uint8_t version;
	uint8_t subparam[1];
} __packed;

struct element_tclas_type4_ip4 {
	uint32_t sa;
	uint32_t da;
	uint16_t sp;
	uint16_t dp;
	uint8_t dscp;
	uint8_t proto;
	uint8_t reserved;
} __packed;

struct element_tclas_type4_ip6 {
	in6_addr sa;
	in6_addr da;
	uint16_t sp;
	uint16_t dp;
	uint8_t dscp;
	uint8_t nxt_hdr;
	union {
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		 uint8_t  flow_label3:8;
		 uint8_t  flow_label2:8;
		 uint8_t  flow_label1:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
		 uint8_t  flow_label1:8;
		 uint8_t  flow_label2:8;
		 uint8_t  flow_label3:8;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		} bits;
		uint8_t value[3];
	} flow_label;
} __packed;

struct element_tclas_type5 {
	uint8_t pcp;
	uint8_t cfi;
	uint8_t vid;
} __packed;

struct element_schedule {
	uint8_t etype;
	uint8_t len;
	uint16_t inf;
	uint32_t start;
	uint32_t serv_intv;
	uint16_t spec_intv;
} __packed;

struct element_chall_txt {
	uint8_t etype;
	uint8_t len;
	uint8_t chall_txt[1];
} __packed;

struct element_pwr_constr {
	uint8_t etype;
	uint8_t len;
	uint8_t local_pwr_constr;
} __packed;

struct element_pwr_cap {
	uint8_t etype;
	uint8_t len;
	uint8_t min_pwr_cap;
	uint8_t max_pwr_cap;
} __packed;

struct element_tpc_req {
	uint8_t etype;
	uint8_t len;
} __packed;

struct element_tpc_rep {
	uint8_t etype;
	uint8_t len;
	uint8_t trans_pwr;
	uint8_t link_marg;
} __packed;

struct element_supp_ch {
	uint8_t etype;
	uint8_t len;
	uint8_t value[2]; 	// first channel nr., nr. of channels
} __packed;

struct element_ch_sw_ann {
	uint8_t etype;
	uint8_t len;
	uint8_t switch_mode;
	uint8_t new_nr;
	uint8_t switch_cnt;
} __packed;

struct element_meas_basic {
	uint8_t ch_nr;
	uint64_t start;
	uint16_t dur;
} __packed;

struct element_meas_cca {
	uint8_t ch_nr;
	uint64_t start;
	uint16_t dur;
} __packed;

struct element_meas_rpi {
	uint8_t ch_nr;
	uint64_t start;
	uint16_t dur;
} __packed;

struct element_meas_ch_load {
	uint8_t op_class;
	uint8_t ch_nr;
	uint16_t rand_intv;
	uint16_t dur;
} __packed;

struct element_meas_noise {
	uint8_t op_class;
	uint8_t ch_nr;
	uint16_t rand_intv;
	uint16_t dur;
} __packed;

struct element_meas_beacon {
	uint8_t op_class;
	uint8_t ch_nr;
	uint16_t rand_intv;
	uint16_t dur;
	uint8_t mode;
	uint8_t bssid[6];
} __packed;

struct element_meas_frame {
	uint8_t op_class;
	uint8_t ch_nr;
	uint16_t rand_intv;
	uint16_t dur;
	uint8_t frame;
	uint8_t mac[6];
} __packed;

struct element_meas_sta {
	uint8_t peer_mac[6];
	uint16_t rand_intv;
	uint16_t dur;
	uint8_t group_id;
} __packed;

struct element_meas_lci {
	uint8_t loc_subj;
	uint8_t latitude_req_res;
	uint8_t longitude_req_res;
	uint8_t altitude_req_res;
} __packed;

struct element_meas_trans_str_cat {
	uint16_t rand_intv;
	uint16_t dur;
	uint8_t peer_sta_addr[6];
	uint8_t traffic_id;
	uint8_t bin_0_range;
} __packed;

struct element_meas_mcast_diag {
	uint16_t rand_intv;
	uint16_t dur;
	uint8_t group_mac[6];
} __packed;

struct element_meas_loc_civic {
	uint8_t loc_subj;
	uint8_t civic_loc;
	uint8_t loc_srv_intv_unit;
	uint16_t loc_srv_intv;
} __packed;

// 802.11-2012 section 8.4.2.73.2: Location Indication Parameters subelement
struct element_meas_loc_ind {
	uint8_t subtype;
	uint8_t len;
	uint8_t group_mac[6];
	uint8_t report_interval_units;
	uint16_t report_interval;
	uint8_t fps;			// frames per chan
	uint16_t im_report_interval;	// in-motion...
	uint8_t im_fps;
	uint8_t burst_interval;
	uint8_t tracking_dur;
	uint8_t ess_interval;
} __packed;


struct element_meas_loc_id {
	uint8_t loc_subj;
	uint8_t loc_srv_intv_unit;
	uint16_t loc_srv_intv;
} __packed;

struct element_meas_pause {
	uint8_t time;
} __packed;


// 802.11-2012 section 8.4.2.71: Diagnostic Request element
struct element_meas_req {
	uint8_t etype;
	uint8_t len;
	uint8_t token;
	uint8_t type;
	uint16_t timeout;
} __packed;

struct element_meas_rep {
	uint8_t etype;
	uint8_t len;
	uint8_t token;
	uint8_t rep_mode;
	uint8_t type;
	uint8_t rep[1];
} __packed;

struct element_quiet {
	uint8_t etype;
	uint8_t len;
	uint8_t cnt;
	uint8_t period;
	uint16_t dur;
	uint16_t offs;
} __packed;

struct element_ibss_dfs {
	uint8_t etype;
	uint8_t len;
	uint8_t owner[6];
	uint8_t rec_intv;
	uint8_t ch_map[1];
} __packed;

struct element_ibss_dfs_tuple {
	uint8_t ch_nr;
	uint8_t map;
} __packed;

struct element_erp {
	uint8_t etype;
	uint8_t len;
	uint8_t param;
} __packed;

struct element_ts_del {
	uint8_t etype;
	uint8_t len;
	uint32_t delay;
} __packed;

struct element_tclas_proc {
	uint8_t etype;
	uint8_t len;
	uint8_t proc;
} __packed;

struct element_ht_cap {
	uint8_t etype;
	uint8_t len;
	union {
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
		 uint16_t ldpc:1,
				  supp_width:1,
				  sm_pwr:2,
				  ht_green:1,
				  gi_20mhz:1,
				  gi_40mhz:1,
				  tx_stbc:1,
				  rx_stbc:2,
				  ht_ack:1,
				  max_msdu_length:1,
				  dsss_ck_mode:1,
				  res:1,
				  forty_int:1,
				  prot_supp:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
		 uint16_t rx_stbc:2,
				  ht_ack:1,
				  max_msdu_length:1,
				  dsss_ck_mode:1,
				  res:1,
				  forty_int:1,
				  prot_supp:1,
				  ldpc:1,
				  supp_width:1,
				  sm_pwr:2,
				  ht_green:1,
				  gi_20mhz:1,
				  gi_40mhz:1,
				  tx_stbc:1;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		} bits;
		uint16_t value;
	} info;
	uint8_t param;
	union {
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
		 uint8_t  bitmask1:8;
		 uint8_t  bitmask2:8;
		 uint8_t  bitmask3:8;
		 uint8_t  bitmask4:8;
		 uint8_t  bitmask5:8;
		 uint8_t  bitmask6:8;
		 uint8_t  bitmask7:8;
		 uint8_t  bitmask8:8;
		 uint8_t  bitmask9:8;
		 uint8_t  bitmask10_res:8;
		 uint16_t supp_rate_res:16;
		 uint32_t tx_param_res:32;

#elif defined(__BIG_ENDIAN_BITFIELD)
		 uint32_t tx_param_res:32;
		 uint16_t supp_rate_res:16;
		 uint8_t  bitmask10_res:8;
		 uint8_t  bitmask9:8;
		 uint8_t  bitmask8:8;
		 uint8_t  bitmask7:8;
		 uint8_t  bitmask6:8;
		 uint8_t  bitmask5:8;
		 uint8_t  bitmask4:8;
		 uint8_t  bitmask3:8;
		 uint8_t  bitmask2:8;
		 uint8_t  bitmask1:8;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		} bits;
		uint8_t value[16];
	} mcs_set;
	uint16_t ext_cap;
	uint32_t beam_cap;
	uint8_t asel_cap;
} __packed;

struct element_qos_cap {
	uint8_t etype;
	uint8_t len;
	uint8_t info;
} __packed;

struct element_ext_supp_rates {
	uint8_t etype;
	uint8_t len;
	uint8_t rates[4];		// no more than 4 for now
} __packed;

struct element_vend_spec {
	uint8_t etype;
	uint8_t len;
	uint8_t data[1]; // oui, specific
} __packed;


enum {
	etype_ssid		= 0,
	etype_rates		= 1,
	etype_fh_params		= 2,
	etype_ds_params		= 3,
	etype_cf_params		= 4,
	etype_tim		= 5,
	etype_ibbs_params	= 6,
	etype_challenge		= 16,
	etype_power		= 33,
	etype_chan		= 36,
	etype_rsn		= 48,
	etype_ext_rates		= 50
};


} // namespace ieeee80211

}

#endif

