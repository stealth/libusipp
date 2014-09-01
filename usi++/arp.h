/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2013 by Sebastian Krahmer,
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

#ifndef __arp_h__
#define __arp_h__


#include "usi-structs.h"
#include "Layer2.h"
#include "TX_dnet_eth.h"
#include <stdio.h>
#include <stdint.h>
#include <string>


#if defined(HAVE_LIBDNET) || defined(HAVE_LIBDUMBNET)

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
 
