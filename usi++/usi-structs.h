/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2015 by Sebastian Krahmer,
 *                  sebastian [dot] krahmer [at] gmail [dot] com
 *
 * libusi++ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libusi++ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with psc.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef usipp_usi_structs_h
#define usipp_usi_structs_h

#include <sys/types.h>
#include <stdint.h>

#ifndef USIPP_OWNSTRUCTS
#include <netinet/in.h>
#endif


namespace usipp {


namespace numbers {

enum  {
	max_buffer_len		= 0x1000000,
	max_packet_size		= 66000,
	min_packet_size		= 1522,	// maximum of ethernet + VLAN
	maxhostlen		= 1000,
	eth_alen		= 6
};


enum {
	TX_TAG_NONE		= 0,
	RX_TAG_NONE		= 0,

	TX_TAG_IP		= 0x1000,
	TX_TAG_IP6,
	TX_TAG_DNET_IP,
	TX_TAG_DNET_ETH,
	TX_TAG_PCAP,
	TX_TAG_PCAP_ETH,
	TX_TAG_STRING,

	RX_TAG_PCAP		= 0x2000,
	RX_TAG_STRING,
	RX_TAG_FD
};


// Ethernet Protocol ID's.
enum {
	eth_p_loop		= 0x0060,	// ethernet loopback packet
	eth_p_echo		= 0x0200,	// ethernet echo packet
	eth_p_pup		= 0x0400,	// xerox pup packet
	eth_p_ip		= 0x0800,	// internet protocol packet
	eth_p_x25		= 0x0805,	// ccitt x.25
	eth_p_arp		= 0x0806,	// address resolution packet
	eth_p_bpq		= 0x08ff,	// g8bpq ax.25 ethernet packet	[ not an officially registered id ]
	eth_p_dec		= 0x6000,	// dec assigned proto
	eth_p_dna_dl		= 0x6001,	// dec dna dump/load
	eth_p_dna_rc		= 0x6002,	// dec dna remote console
	eth_p_dna_rt		= 0x6003,	// dec dna routing
	eth_p_lat		= 0x6004,	// dec lat
	eth_p_diag		= 0x6005,	// dec diagnostics
	eth_p_cust		= 0x6006,	// dec customer use
	eth_p_sca		= 0x6007,	// dec systems comms arch
	eth_p_rarp		= 0x8035,	// reverse addr res packet
	eth_p_atalk		= 0x809b,	// appletalk ddp
	eth_p_aarp		= 0x80f3,	// appletalk aarp
	eth_p_ipx		= 0x8137,	// ipx over dix
	eth_p_ipv6		= 0x86dd,	// ipv6 over bluebook
	eth_p_eapol		= 0x888e,	// 802.1x eap over lan
	eth_p_pae		= eth_p_eapol,	// port access entry
	eth_p_pre_auth		= 0x88c7,	// wpa2 pre auth

	// Non DIX types. Won't clash for 1500 types

	eth_p_802_3		= 0x0001,	// dummy type for 802.3 frames
	eth_p_ax25		= 0x0002,	// dummy protocol id for ax.25
	eth_p_all		= 0x0003,	// every packet (be careful!!!)
	eth_p_802_2		= 0x0004,	// 802.2 frames
	eth_p_snap		= 0x0005,	// internal only
	eth_p_ddcmp		= 0x0006,	// dec ddcmp: internal only
	eth_p_wan_ppp		= 0x0007,	// dummy type for wan ppp frames
	eth_p_ppp_mp		= 0x0008,	// dummy type for ppp mp frames
	eth_p_localtalk		= 0x0009,	// localtalk pseudo type
	eth_p_ppptalk		= 0x0010,	// dummy type for atalk over ppp
	eth_p_tr_802_2		= 0x0011,	// 802.2 frames
	eth_p_mobitex		= 0x0015,	// mobitex (kaz@cafe.net)
	eth_p_control		= 0x0016,	// card specific control frames
	eth_p_irda		= 0x0017	// linux/ir
};


// ARP protocol hardware identifiers
enum {
	arphrd_netrom		= 0,		// from ka9q: net/rom pseudo
	arphrd_ether		= 1,		// ethernet 10/100mbps
	arphrd_eether		= 2,		// experimental ethernet
	arphrd_ax25		= 3,		// ax.25 level 2
	arphrd_pronet		= 4,		// pronet token ring
	arphrd_chaos		= 5,		// chaosnet
	arphrd_ieee802		= 6,		// ieee 802.2 ethernet/tr/tb
	arphrd_arcnet		= 7,		// arcnet
	arphrd_appletlk		= 8,		// appletalk.
	arphrd_dlci		= 15,		// frame relay dlci
	arphrd_metricom		= 23,		// metricom strip (new iana id)

	// dummy types for non arp hardware
	arphrd_slip		= 256,
	arphrd_cslip		= 257,
	arphrd_slip6		= 258,
	arphrd_cslip6		= 259,
	arphrd_rsrvd		= 260,		// notional kiss type
	arphrd_adapt		= 64,
	arphrd_rose		= 270,
	arphrd_x25		= 271,		// ccitt x.25
	arphrd_ppp		= 512,
	arphrd_hdlc		= 513,		// (cisco) hdlc
	arphrd_lapb		= 516,		// lapb

	arphrd_tunnel		= 768,		// ipip tunnel
	arphrd_tunnel6		= 769,		// ipip6 tunnel
	arphrd_frad		= 770,		// frame relay access device.
	arphrd_skip		= 771,		// skip vif
	arphrd_loopback		= 772,		// loopback device
	arphrd_localtlk		= 773,		// localtalk device
	arphrd_fddi		= 774,		// fiber distributed data interface
	arphrd_bif		= 775,		// ap1000 bif
	arphrd_sit		= 776,		// sit0 device - ipv6-in-ipv4
	arphrd_ipddp		= 777,		// ip-in-ddp tunnel
	arphrd_ipgre		= 778,		// gre over ip
	arphrd_pimreg		= 779,		// pimsm register interface
	arphrd_hippi		= 780,		// high performance parallel i'face
	arphrd_ash		= 781,		// (nexus electronics) ash
	arphrd_econet		= 782,		// acorn econet
	arphrd_irda		= 783,		// linux/ir
	arphrd_fcpp		= 784,		// point to point fibrechanel
	arphrd_fcal		= 785,		// fibrechanel arbitrated loop
	arphrd_fcpl		= 786,		// fibrechanel public loop
	arphrd_fcpfabric	= 787		// fibrechanel fabric
};


// ARP protocol opcodes
enum {
	arpop_request		= 1,		// ARP request
	arpop_reply		= 2,		// ARP reply
	arpop_rrequest		= 3,		// RARP request
	arpop_rreply		= 4		// RARP reply
};


// IANA assigned protocol numbers
enum {
	ipproto_ip		= 0,
	ipproto6_hopopts	= 0,		// ipv6 hop-by-hop options
	ipproto_icmp		= 1,		// internet control message protocol
	ipproto_igmp		= 2,		// internet group management protocol
	ipproto_ipip		= 4,		// ipip tunnels (older ka9q tunnels use 94)
	ipproto_tcp		= 6,		// transmission control protocol
	ipproto_egp		= 8,		// exterior gateway protocol
	ipproto_pup		= 12,		// pup protocol
	ipproto_udp		= 17,		// user datagram protocol
	ipproto_idp		= 22,		// xns idp protocol
	ipproto_tp		= 29,		// so transport protocol class 4
	ipproto_dccp		= 33,		// datagram congestion control protocol
	ipproto_3pc		= 34,		// 3rd party connect protocol
	ipproto_idpr		= 35,		// inter domain policy routing protocol
	ipproto_xtp		= 36,		// XTP
	ipproto_ddp		= 37,		// Datagram Delivery Protocol
	ipproto_idpr_cmtp	= 38,		// IDPR control message transport protocol
	ipproto_il		= 40,		// IL transport protocol
	ipproto_ipv6		= 41,		// ipv6 header
	ipproto_sdrp		= 42,		// source demand routing protocol
	ipproto6_routing	= 43,		// ipv6 routing header
	ipproto6_fragment	= 44,		// ipv6 fragmentation header
	ipproto_idrp		= 45,		// inter domain routing protocol
	ipproto_rsvp		= 46,		// reservation protocol
	ipproto_gre		= 47,		// general routing encapsulation
	ipproto_dsr		= 48,		// dynamic source routing protocol
	ipproto_bna		= 49,		// BNA
	ipproto_esp		= 50,		// encapsulating security payload
	ipproto_ah		= 51,		// authentication header
	ipproto_inslp		= 52,		// integrated net layer security TUBA
	ipproto_swipe		= 53,		// ip with encryption
	ipproto_narp		= 54,		// NBMA address resolution protocol
	ipproto_mobile		= 55,		// IP mobility
	ipproto_tlsp		= 56,		// transport layer security protocol using kryptonet
	ipproto_skip		= 57,		// SKIP
	ipproto_icmpv6		= 58,		// icmpv6
	ipproto6_none		= 59,		// ipv6 no next header
	ipproto6_dstopts	= 60,		// ipv6 destination options
	ipproto_cftp		= 62,		// CFTP
	ipproto_kryptolan	= 65,		// KRYPTOLAN
	ipproto_ippc		= 67,		// Internet Pluribus Packet Core
	ipproto_satnetmon	= 69,		// SATNET monitoring
	ipproto_visa		= 70,		// VISA
	ipproto_ipcv		= 71,		// Internet Packet Core Utility
	ipproto_cphb		= 73,		// Computer Protocol Heart Beat
	ipproto_wasn		= 74,		// Wang Span Network
	ipproto_pvp		= 75,		// packet video protocol
	ipproto_brsatmon	= 76,		// Backroom SATNET monitoring
	ipproto_wbmon		= 78,		// WIDEBAND monitoring
	ipproto_wbexpak		= 79,		// WIDEBAND expak
	ipproto_vmtp		= 81,		// VMTP
	ipproto_svmtp		= 82,		// secure VMTP
	ipproto_vines		= 83,		// VINES
	ipproto_ttp_iptm	= 84,		// TTP or IPTM
	ipproto_eigrp		= 88,		// EIGRP
	ipproto_ospfigp		= 89,		// OSPFIGP
	ipproto_spriterpc	= 90,		// sprite RPC
	ipproto_larp		= 91,		// Lotus Address Resolution protocol
	ipproto_mtp		= 92,		// multicast transport protocol
	ipproto_ax25		= 93,		// AX.25
	ipproto_oldipip		= 94,		// IP in IP encapsulation
	ipproto_etherip		= 97,		// Ethernet within IP encapsulation
	ipproto_encap		= 98,		// encapsulation header
	ipproto_gmtp		= 100,		// GMTP
	ipproto_pim		= 103,		// protocol independent multicast
	ipproto_comp		= 108,		// compression header protocol
	ipproto_snp		= 109,		// Sitara Network protocols
	ipproto_compqp		= 110,		// compaq Peer Procotol
	ipproto_ipxip		= 111,		// IPX in IP
	ipproto_vrrp		= 112,		// Virtual Router Redunancy Protocol
	ipproto_smp		= 121,		// Simple Message Protocol
	ipproto_fire		= 125,		// FIRE
	ipproto_crtp		= 126,		// Combat Radio Transport Protocol
	ipproto_crudp		= 127,		// Combat Radio User Datagram
	ipproto_sps		= 128,		// Secure Packet Shield
	ipproto_pipe		= 131,		// Private IP Encapsulation within IP
	ipproto_sctp		= 132,		// stream control transmission protocol
	ipproto_fc		= 133,		// Fibre Channel
	ipproto_udplite		= 136,		// udp-lite protocol
	ipproto_shim6		= 140,		// Shim6
	ipproto_rohc		= 142		// Robust Header Compression
	//ipproto_raw		= 255,		// raw ip packets, use os, its not a packet protocol
};


// ICMP types
enum {
	icmp_echoreply		= 0,	// echo reply
	icmp_dest_unreach	= 3,	// destination unreachable
	icmp_source_quench	= 4,	// source quench
	icmp_redirect		= 5,	// redirect (change route)
	icmp_echo		= 8,	// echo request
	icmp_time_exceeded	= 11,	// time exceeded
	icmp_parameterprob	= 12,	// parameter problem
	icmp_timestamp		= 13,	// timestamp request
	icmp_timestampreply	= 14,	// timestamp reply
	icmp_info_request	= 15,	// information request
	icmp_info_reply		= 16,	// information reply
	icmp_address		= 17,	// address mask reques
	icmp_addressreply	= 18,	// address mask reply
	nr_icmp_types		= 18
};


// ICMP Codes for UNREACH
enum {
	icmp_net_unreach	= 0,	// network unreachable
	icmp_host_unreach	= 1,	// host unreachable
	icmp_prot_unreach	= 2,	// protocol unreachable
	icmp_port_unreach	= 3,	// port unreachable
	icmp_frag_needed	= 4,	// fragmentation needed/df set
	icmp_sr_failed		= 5,	// source route failed
	icmp_net_unknown	= 6,
	icmp_host_unknown	= 7,
	icmp_host_isolated	= 8,
	icmp_net_ano		= 9,
	icmp_host_ano		= 10,
	icmp_net_unr_tos	= 11,
	icmp_host_unr_tos	= 12,
	icmp_pkt_filtered	= 13,	// packet filtered
	icmp_prec_violation	= 14,	// precedence violation
	icmp_prec_cutoff	= 15,	// precedence cut off
	nr_icmp_unreach		= 15	// instead of hardcoding immediate value
};


// ICMP Codes for REDIRECT
enum {
	icmp_redir_net		= 0,	// redirect net
	icmp_redir_host		= 1,	// redirect host
	icmp_redir_nettos	= 2,	// redirect net for tos
	icmp_redir_hosttos	= 3	// redirect host for tos
};


// Codes for TIME_EXCEEDED.
enum {
	icmp_exc_ttli		= 0,	// ttl count exceeded
	icmp_exc_fragtime	= 1	// fragment reass time exceeded
};


// IP flags
enum {
	ip_rf			= 0x8000,
	ip_df			= 0x4000,
	ip_mf			= 0x2000,
	ip_offmask		= 0x1fff
};


// TCP flags
enum {
	th_fin			= 0x01,
	th_syn			= 0x02,
	th_rst			= 0x04,
	th_push			= 0x08,
	th_ack			= 0x10,
	th_urg			= 0x20,
	th_ece			= 0x40,
	th_cwr			= 0x80,
	th_ns			= 0x100
};


// TCP options
enum {
	tcpopt_eol		= 0,
	tcpopt_nop		= 1,
	tcpopt_maxseg		= 2,
	tcpolen_maxseg		= 4,
	tcpopt_window		= 3,
	tcpolen_window		= 3,
	tcpopt_sack_permitted	= 4,			// experimental
	tcpolen_sack_permitted	= 2,
	tcpopt_sack		= 5,			// experimental
	tcpopt_timestamp	= 8,
	tcpolen_timestamp	= 10,
	tcpolen_tstamp_appa	= (tcpolen_timestamp+2)	// appendix a
};


// IPv6 flow control
enum {
	ipv6_fl_a_get		= 0,
	ipv6_fl_a_put		= 1,
	ipv6_fl_a_renew		= 2,
	ipv6_fl_f_create	= 1,
	ipv6_fl_f_excl		= 2,
	ipv6_fl_s_none		= 0,
	ipv6_fl_s_excl		= 1,
	ipv6_fl_s_process	= 2,
	ipv6_fl_s_user		= 3,
	ipv6_fl_s_any		= 255
};


/*
 * Bitmask constant declarations to help applications select out the
 * flow label and priority fields.
 *
 * Note that this are in host byte order while the flowinfo field of
 * sockaddr_in6 is in network byte order.
 */

enum {
	ipv6_flowinfo_flowlabel	= 0x000fffff,
	ipv6_flowinfo_priority	= 0x0ff00000
};


// IPv6 TLV options
enum {
	ipv6_tlv_pad0		= 0,
	ipv6_tlv_padn		= 1,
	ipv6_tlv_routeralert	= 5,
	ipv6_tlv_jumbo		= 194
};


// ICMP6 types and options
enum {
	icmp6_dst_unreach	= 1,
	icmp6_packet_too_big	= 2,
	icmp6_time_exceeded	= 3,
	icmp6_param_prob	= 4,

	icmp6_infomsg_mask	= 0x80,			// all informational messages

	icmp6_echo_request	= 128,
	icmp6_echo_reply	= 129,
	icmp6_membership_query	= 130,
	icmp6_membership_report	= 131,
	icmp6_membership_reduction	= 132,

	icmp6_dst_unreach_noroute	= 0,	// no route to destination
	icmp6_dst_unreach_admin		= 1,	// communication with destination administratively prohibited
	icmp6_dst_unreach_notneighbor	= 2,	// not a neighbor
	icmp6_dst_unreach_addr		= 3,	// address unreachable
	icmp6_dst_unreach_noport	= 4,	// bad port

	icmp6_time_exceed_transit	= 0,	// hop limit == 0 in transit
	icmp6_time_exceed_reassembly	= 1,	// reassembly time out

	icmp6_paramprob_header		= 0,	// erroneous header field
	icmp6_paramprob_nextheader	= 1,	// unrecognized next header
	icmp6_paramprob_option		= 2,	// unrecognized ipv6 option

	icmp6_nd_router_solicit		= 133,
	icmp6_nd_router_advert		= 134,
	icmp6_nd_neighbor_solicit	= 135,
	icmp6_nd_neighbor_advert	= 136,
	icmp6_nd_redirect		= 137,

	nd_opt_source_ll_addr	= 1,
	nd_opt_target_ll_addr	= 2,
	nd_opt_prefix_info	= 3,
	nd_opt_redirect_hdr	= 4,
	nd_opt_mtu		= 5,
	nd_opt_route_info	= 24,
	nd_opt_rdnss		= 25,
	nd_opt_dnssl		= 31
};


enum {
	eapol_ptype_packet		= 0,
	eapol_ptype_eap			= 0,
	eapol_ptype_start		= 1,
	eapol_ptype_logoff		= 2,
	eapol_ptype_key			= 3,
	eapol_ptype_asf_atert		= 4,
	eapol_ptype_mka			= 5,
	eapol_ptype_announce_gen	= 6,
	eapol_ptype_announce_spec	= 7,
	eapol_announce_req		= 8
};


// IPv6 extension headers now found in ipproto_ numbers


}	// namespace numbers


namespace flags = numbers;
using namespace numbers;


namespace headers {

/*  This is a name for the 48 bit ethernet address available on many
 *  systems.
 */
struct ether_addr
{
	uint8_t ether_addr_octet[eth_alen];
};


struct ether_header
{
	uint8_t  ether_dhost[eth_alen];	// destination eth addr
	uint8_t  ether_shost[eth_alen];	// source ether addr
	uint16_t ether_type;		// packet type ID field
};


/*  see rfc 826 for protocol description.  arp packets are variable
 *  in size; the arphdr structure defines the fixed-length portion.
 *  Protocol type values are the same as those for 10 Mb/s Ethernet.
 *  It is followed by the variable-sized fields ar_sha, arp_spa,
 *  arp_tha and arp_tpa in that order, according to the lengths
 *  specified.  Field names used correspond to RFC 826.
 */
struct arphdr {
	uint16_t ar_hrd;	// Format of hardware address
	uint16_t ar_pro;	// Format of protocol address
	unsigned char ar_hln;	// Length of hardware address
	unsigned char ar_pln;	// Length of protocol address
	uint16_t ar_op;		// ARP opcode (command)
};



/* See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct	ether_arp {
	struct	arphdr ea_hdr;		// fixed-size header
	uint8_t arp_sha[eth_alen];	// sender hardware address
	uint8_t arp_spa[4];		// sender protocol address
	uint8_t arp_tha[eth_alen];	// target hardware address
	uint8_t arp_tpa[4];		// target protocol address
};


// ICMP header
struct icmphdr {
	uint8_t type;
	uint8_t code;
	uint16_t sum;

	union {
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo;
		uint32_t gateway;
		struct {
			uint16_t unused;
			uint16_t mtu;
		} frag;
	} un;
};


struct udphdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
};


// pseudo-header is used to calculate checksums over UDP and TCP packets
struct pseudohdr {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t len;
};


// TCP header
struct tcphdr
{
	uint16_t th_sport;		// source port
	uint16_t th_dport;		// destination port
	uint32_t th_seq;		// sequence number
	uint32_t th_ack;		// acknowledgement number
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t th_x2:4;		// (unused)
	uint8_t th_off:4;		// data offset
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t th_off:4;		// data offset
	uint8_t th_x2:4;		// (unused)
#endif
	uint8_t th_flags;
	uint16_t th_win;		// window
	uint16_t th_sum;		// checksum
	uint16_t th_urp;		// urgent pointer
};


// IPv4 header
struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t ihl:4;
	uint32_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint32_t version:4;
	uint32_t ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
	/* The options start here. */
};


// describes a fragment for re-assembling routines
struct fragments {
	int id;				// the IP id-filed
	int len;			// how much data received yet?
	int origLen;			// and how much has it to be?
	int userLen;			// and how much did we saved?
	char *data;     		// the packet itself
};



// global in6_addr should be defined nowadays
#ifdef USIPP_OWNSTRUCTS

struct in6_addr {
	union {
		uint8_t  u6_addr8[16];
		uint16_t u6_addr16[8];
		uint32_t u6_addr32[4];
	} in6_u;
};

#else
	using in6_addr = ::in6_addr;
#endif


struct ip6_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t                priority:4,
                                version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t                version:4,
                	        priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	uint8_t                flow_lbl[3];

	uint16_t               payload_len;
	uint8_t                nexthdr;
	uint8_t                hop_limit;

        in6_addr        saddr;
        in6_addr        daddr;
};



struct icmp6_hdr {
	uint8_t icmp6_type;			// type field
	uint8_t icmp6_code;			// code field
	uint16_t icmp6_cksum;			// checksum field
	union {
		uint32_t icmp6_data32[1];	// type-specific field
		uint16_t icmp6_data16[2];	// type-specific field
		uint8_t icmp6_data8[4];		// type-specific field
	} un;
};


/*
#define icmp6_data32    icmp6_dataun.icmp6_un_data32
#define icmp6_data16    icmp6_dataun.icmp6_un_data16
#define icmp6_data8     icmp6_dataun.icmp6_un_data8
#define icmp6_pptr      icmp6_data32[0]		// parameter prob
#define icmp6_mtu       icmp6_data32[0]		// packet too big
#define icmp6_id        icmp6_data16[0]		// echo request/reply
#define icmp6_seq       icmp6_data16[1]		// echo request/reply
#define icmp6_maxdelay  icmp6_data16[0]		// mcast group membership
*/


// RFC 6106 recursive DNS server option
struct icmp6_rdns_opt {
	uint8_t type;
	uint8_t len;
	uint16_t reserved;
	uint32_t lifetime;
	in6_addr addr[1];	// one or more addresses
} __attribute__((packed));


// RFC 6106 domain name search list
struct icmp6_domain_opt {
	uint8_t type;
	uint8_t len;
	uint16_t reserved;
	uint32_t lifetime;
	// encoded domain goes here
	unsigned char domain[1];
} __attribute__((packed));


// RFC 2461 router advertisement
struct icmp6_ra {
	uint32_t time1, time2;
	// options go here
} __attribute__((packed));


// RFC 2461 source link layer address option
struct icmp6_sll_opt {
	uint8_t type;
	uint8_t len;
	unsigned char address[1];
} __attribute__((packed));


// RFC 2461 prefix info option
struct icmp6_prefix_opt {
	uint8_t type;
	uint8_t len;
	uint8_t plen;
	uint8_t flags;
	uint32_t vtime;
	uint32_t lifetime;
	uint32_t reserved;
	// one or more
	in6_addr prefix[1];
} __attribute__((packed));


// RFC 2461 MTU option
struct icmp6_mtu_opt {
	uint8_t type;
	uint8_t len;
	uint16_t reserved;
	uint32_t mtu;
} __attribute__((packed));


// RFC 4191 route info option
struct icmp6_ri_opt {
	uint8_t type;
	uint8_t len;
	uint8_t plen;
	uint8_t flags;
	uint32_t lifetime;
	// one or more
	unsigned char prefix[1];
};


struct pseudohdr6 {
	in6_addr saddr, daddr;
	uint32_t len;
	uint8_t zero[3];
	uint8_t proto;
};


struct ip6_opt {
	uint8_t  ip6o_type;
	uint8_t  ip6o_len;
};


struct eapol_p {
	uint8_t version;
	uint8_t type;
	uint16_t len;
};


} // namespace headers

using namespace headers;

} // namespace usipp


#endif

