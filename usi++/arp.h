/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 *** 
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#ifndef __arp_h__
#define __arp_h__


#include "usi-structs.h"
#include "Layer2.h"
#include "TX_dnet_eth.h"
#include <stdio.h>
#include <stdint.h>
#include <string>


#ifdef HAVE_LIBDNET

namespace usipp {

/* ARP arp.h
 * RFC826, the address resolution protocol
 */
/*! \class ARP
 *  \brief capture and send ARP packets
 *  \example arps.cc
 */
class ARP : public Layer2 {
private:
   	struct arphdr arphdr;
	TX_dnet_eth *d_tx;
public:

	/*! Open device 'dev' for packet-capturing (ARP-packets)
	 *  ARP-objects don't need to call init_device().
	 */
   	ARP(const std::string &);

	virtual ~ARP();

	/*! Get the ARP command */
	uint16_t get_op() const;

	/*! Set the ARP-command.
 	 */
	uint16_t set_op(uint16_t op) { arphdr.ar_op = htons(op); return op; }

	/*! Get format of hardware address */
	uint16_t get_hw() const { return ntohs(arphdr.ar_hrd); }

	/*! Set format of hardware address */
	uint16_t set_hw(uint16_t hw) { arphdr.ar_hrd = htons(hw); return hw; }

	/*! Get format of protocol address */
	uint16_t get_proto() const { return ntohs(arphdr.ar_pro); }

	/*! Set format of protocol address */
	uint16_t set_proto(uint16_t p) { arphdr.ar_pro = htons(p); return p; }

	/*! Get length of hardware address */
	uint8_t get_hwlen() const { return arphdr.ar_hln; }

	/*! Set length of hardware address */
	uint8_t set_hwlen(uint8_t l) { return arphdr.ar_hln = l; }

	/*! Get length of protocol address */
	uint8_t get_protolen() const { return arphdr.ar_pln; }

	/*! Set length of protocol address */
	uint8_t set_protolen(uint8_t l) { return arphdr.ar_pln = l; }

	/*! Set source address of underlying TX (just for convenience) */
	int set_l2src(const std::string &);

	/*! Set destination address of underlying TX (just for convenience) */
	int set_l2dst(const std::string &);

	/*! Sniff for an ARP-request/reply ...
	 * \example arpw.cc
	 */
	virtual int sniffpack(void *, size_t);

	/*! Send a ARP request.You must provide target hw/proto amd source hw/proto address blob.
	 */
	virtual int sendpack(const void *, size_t);

	/*! Send a ARP request.You must provide target hw/proto amd source hw/proto address blob.
	 */
	virtual int sendpack(const std::string &);

	/*! Initialize device for capturing */
	/*! \example arpw.cc
	 */
	virtual int init_device(const std::string &, int, size_t);

	/*! Set a particular filter. Should not be needed for ARP. */
	virtual int setfilter(const std::string &);
};

} // namespace usipp

#endif // HAVE_LIBDNET
#endif 	// __arp_h__
 
