/* Mostly taken from Linux kernel-source/examples, but enum-ified */

#ifndef usipp_radiotap_h
#define usipp_radiotap_h

#include <stdint.h>
#include <cstring>
#include "80211.h"

namespace usipp {


namespace ieee80211 {

#if 0

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

#endif


enum radiotap_type {
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
enum channel_flags {
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
enum radiotap_flags {

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


struct wifi_hdr {
	struct ieee80211::frame_ctrl fc;
	union {
		struct ieee80211::mgmt mgmt;
		struct ieee80211::data_frame data;
	};
};


/*
unsigned char rtap_hdr[] = {
        0x00, 0x00,		// radiotap version
        0x19, 0x00,		// radiotap header length
        0x6f, 0x08, 0x00, 0x00, // bitmap
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
        0x00,			// flags
	//0x6c, // rate
	0x02,	// rate (1MBit/s) 
	//0x71, 0x09, // channel freq
	//0xc0, 0x00, // channel type
	0x8a, 0x09,	// 0x098a = 2442MHz (channel 7)
	0xa0, 0x00,  	// 802.11b
	0xde,		// antsignal
        0,		// antnoise
        0,		// antenna
};
*/


enum {
	channel1		= 2412,
	channel2		= 2417,
	channel3		= 2422,
	channel4		= 2427,
	channel5		= 2432,
	channel6		= 2437,
	channel7		= 2442,
	channel8		= 2447,
	channel9		= 2452,
	channel10		= 2457,
	channel11		= 2462,
	channel12		= 2467,
	channel13		= 2472,
	channel14		= 2484
};


// little endian
struct radiotap_hdr {
	uint16_t version;
	uint16_t hlen;
	union {
		struct {
		uint32_t tsft:1;
		uint32_t flags:1;
		uint32_t rate:1;
		uint32_t channel:1;
		uint32_t fhss:1;
		uint32_t asignal:1;	// dbm antenna signal
		uint32_t anoise:1;	// dbm antenna noise
		uint32_t lquality:1;	// locak quality
		uint32_t txatten:1;	// TX attenuation
		uint32_t dbtxatten:1;	// db TX attenuation
		uint32_t dbmtxpower:1;	//
		uint32_t antenna:1;
		uint32_t dbantennas:1;	// db antenna signal
		uint32_t dbantennan:1;	// db antenna noise
		uint32_t rxflags:1;
		uint32_t txflags:1;
		uint32_t rtsretries:1;
		uint32_t dataretries:1;
		uint32_t channelplus:1;
		uint32_t mcs:1;
		uint32_t ampdu:1;
		uint32_t unused:8;
		uint32_t rtnsnext:1;	// radiotap NS next
		uint32_t vnsnext:1;	// vendor NS next
		uint32_t ext:1;
		} bits;
		uint32_t value;
	} pflags;
	uint8_t timestamp[8];
	union {
		struct {
		uint8_t cfp:1;
		uint8_t preamle:1;
		uint8_t wep:1;
		uint8_t frag:1;
		uint8_t fcs:1;
		uint8_t datapad:1;
		uint8_t badfcs:1;
		uint8_t shortgi:1;
		} bits;
		uint8_t value;
	} flags;
	// depends on pflags
	uint8_t rate;
	uint16_t ch_freq;
	uint16_t ch_type;
	uint8_t asignal;
	uint8_t anoise;
	uint8_t antenna;
	uint16_t txflags;
	uint8_t pad[1];

	// construct a sane default
	radiotap_hdr() : version(0), hlen(28),
	                 timestamp{0,0,0,0,0,0,0,0},
	                 rate(2),		// 1MBit/s
	                 ch_freq(channel7),	// 2442 Mhz
	                 ch_type(0x00a0),	// 802.11b
	                 asignal(0xde),
	                 anoise(0),
	                 antenna(0),
	                 txflags(0)
	{
		pflags.value = 0;
		pflags.bits.tsft = 1;
		pflags.bits.flags = 1;
		pflags.bits.rate = 1;
		pflags.bits.channel = 1;
		pflags.bits.fhss = 0;
		pflags.bits.asignal = 1;
		pflags.bits.anoise = 1;
		pflags.bits.antenna = 1;
		pflags.bits.txflags = 0;

		flags.value = 0;

		memset(pad, 0, sizeof(pad));
	}

	~radiotap_hdr() {}
} __attribute__((packed));

} // namespace ieee80211

}

#endif

