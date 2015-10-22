/* Mostly taken from Linux kernel-source/examples, but enum-ified */

#ifndef usipp_radiotap_h
#define usipp_radiotap_h

#include <stdint.h>
#include "80211.h"

namespace usipp {

struct ieee80211_radiotap_header {
	uint8_t version;	/* Version 0. Only increases
				 * for drastic changes,
				 * introduction of compatible
				 * new fields does not count.
				 */
	uint8_t pad;
	uint16_t len;		/* length of the whole
				 * header in bytes, including
				 * version, pad,
				 * len, and data fields.
				 */
	uint32_t present;	/* A bitmap telling which
				 * fields are present. Set bit 31
				 * (0x80000000) to extend the
				 * bitmap by another 32 bits.
				 * Additional extensions are made
				 * by setting bit 31.
				 */
} __attribute__((packed));



enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT			= 0,
	IEEE80211_RADIOTAP_FLAGS		= 1,
	IEEE80211_RADIOTAP_RATE			= 2,
	IEEE80211_RADIOTAP_CHANNEL		= 3,
	IEEE80211_RADIOTAP_FHSS			= 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL 	= 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE		= 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY		= 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION	= 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION	= 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER		= 10,
	IEEE80211_RADIOTAP_ANTENNA		= 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL		= 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE		= 13,
	IEEE80211_RADIOTAP_RX_FLAGS		= 14,
	IEEE80211_RADIOTAP_TX_FLAGS		= 15,
	IEEE80211_RADIOTAP_RTS_RETRIES		= 16,
	IEEE80211_RADIOTAP_DATA_RETRIES		= 17,

	IEEE80211_RADIOTAP_MCS			= 19,

	/* valid in every it_present bitmap, even vendor namespaces */
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE	= 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE	= 30,
	IEEE80211_RADIOTAP_EXT			= 31
};


/* Channel flags. */
enum ieee80211_channel_flags {
	IEEE80211_CHAN_TURBO	= 0x0010,	/* Turbo channel */
	IEEE80211_CHAN_CCK	= 0x0020,	/* CCK channel */
	IEEE80211_CHAN_OFDM	= 0x0040,	/* OFDM channel */
	IEEE80211_CHAN_2GHZ	= 0x0080,	/* 2 GHz spectrum channel. */
	IEEE80211_CHAN_5GHZ	= 0x0100,	/* 5 GHz spectrum channel */
	IEEE80211_CHAN_PASSIVE	= 0x0200,	/* Only passive scan allowed */
	IEEE80211_CHAN_DYN	= 0x0400,	/* Dynamic CCK-OFDM channel */
	IEEE80211_CHAN_GFSK	= 0x0800	/* GFSK channel (FHSS PHY) */
};


/* For IEEE80211_RADIOTAP_FLAGS */
enum ieee80211_radiotap_flags {

	IEEE80211_RADIOTAP_F_CFP	= 0x01,	/* sent/received
						 * during CFP
						 */
	IEEE80211_RADIOTAP_F_SHORTPRE	= 0x02,	/* sent/received
						 * with short
						 * preamble
						 */
	IEEE80211_RADIOTAP_F_WEP	= 0x04,	/* sent/received
						 * with WEP encryption
						 */
	IEEE80211_RADIOTAP_F_FRAG	= 0x08,	/* sent/received
						 * with fragmentation
						 */
	IEEE80211_RADIOTAP_F_FCS	= 0x10,	/* frame includes FCS */
	IEEE80211_RADIOTAP_F_DATAPAD	= 0x20,	/* frame has padding between
						 * 802.11 header and payload
						 * (to 32-bit boundary)
						 */
	IEEE80211_RADIOTAP_F_BADFCS	= 0x40,	/* bad FCS */

	/* For IEEE80211_RADIOTAP_RX_FLAGS */
	IEEE80211_RADIOTAP_F_RX_BADPLCP	= 0x0002,	/* frame has bad PLCP */

	/* For IEEE80211_RADIOTAP_TX_FLAGS */
	IEEE80211_RADIOTAP_F_TX_FAIL	= 0x0001,	/* failed due to excessive
							 * retries */
	IEEE80211_RADIOTAP_F_TX_CTS	= 0x0002,	/* used cts 'protection' */
	IEEE80211_RADIOTAP_F_TX_RTS	= 0x0004,	/* used rts/cts handshake */
	IEEE80211_RADIOTAP_F_TX_NOACK	= 0x0008,	/* don't expect an ack */


	/* For IEEE80211_RADIOTAP_MCS */
	IEEE80211_RADIOTAP_MCS_HAVE_BW	= 0x01,
	IEEE80211_RADIOTAP_MCS_HAVE_MCS	= 0x02,
	IEEE80211_RADIOTAP_MCS_HAVE_GI	= 0x04,
	IEEE80211_RADIOTAP_MCS_HAVE_FMT	= 0x08,
	IEEE80211_RADIOTAP_MCS_HAVE_FEC	= 0x10,

	IEEE80211_RADIOTAP_MCS_BW_MASK	= 0x03,
	IEEE80211_RADIOTAP_MCS_BW_20	= 0,
	IEEE80211_RADIOTAP_MCS_BW_40	= 1,
	IEEE80211_RADIOTAP_MCS_BW_20L	= 2,
	IEEE80211_RADIOTAP_MCS_BW_20U	= 3,
	IEEE80211_RADIOTAP_MCS_SGI	= 0x04,
	IEEE80211_RADIOTAP_MCS_FMT_GF	= 0x08,
	IEEE80211_RADIOTAP_MCS_FEC_LDPC	= 0x10
};


/* Radiotap header iteration
 *   implemented in net/wireless/radiotap.c
 *   docs in Documentation/networking/radiotap-headers.txt
 */
/**
 * struct ieee80211_radiotap_iterator - tracks walk thru present radiotap args
 * @rtheader: pointer to the radiotap header we are walking through
 * @max_length: length of radiotap header in cpu byte ordering
 * @this_arg_index: IEEE80211_RADIOTAP_... index of current arg
 * @this_arg: pointer to current radiotap arg
 * @arg_index: internal next argument index
 * @arg: internal next argument pointer
 * @next_bitmap: internal pointer to next present u32
 * @bitmap_shifter: internal shifter for curr u32 bitmap, b0 set == arg present
 */

struct ieee80211_radiotap_iterator {
	struct ieee80211_radiotap_header *rtheader;
	int max_length;
	int this_arg_index;
	uint8_t *this_arg;

	int arg_index;
	uint8_t *arg;
	uint32_t *next_bitmap;
	uint32_t bitmap_shifter;
};

extern int ieee80211_radiotap_iterator_init(
   struct ieee80211_radiotap_iterator *iterator,
   struct ieee80211_radiotap_header *radiotap_header,
   int max_length);

extern int ieee80211_radiotap_iterator_next(
   struct ieee80211_radiotap_iterator *iterator);


struct wifi_hdr {
	struct ieee80211_frm_ctrl fc;
	union {
		struct ieee80211_mgmt mgmt;
		struct ieee80211_data data;
	} u;
};

}

#endif

