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

#ifndef usipp_icmp_h
#define usipp_icmp_h

#include "usi-structs.h"
#include "datalink.h"
#include "ip.h"
#include "RX.h"
#include "TX.h"

#include <string>
#include <stdint.h>


namespace usipp {


/*! \class ICMP icmp.h
 *  \brief the ICMP class
 */
/*! \example icmp_sniff.cc
 */

class ICMP : public IP {
private:
   	struct icmphdr icmphdr;
public:
	/*! Expects host.
	 */
	ICMP(const std::string &, RX *rx = NULL, TX *tx = NULL);

	virtual ~ICMP();

	/*! Copy-Construktor */
	ICMP(const ICMP &);

	/*! Assign-operator */
	ICMP &operator=(const ICMP &);

	/*! send an ICMP-packet containing 'payload' which
	 *  is 'paylen' bytes long
	 */
	virtual int sendpack(const void *, size_t);

	/*! send a ICMP-packet with string 'payload' as payload.
	 */
	virtual int sendpack(const std::string &);

	/*! Capture an packet from the NIC.
	*/
	virtual std::string &sniffpack(std::string &);

	/*! Capture an packet from the NIC.
	*/
	virtual int sniffpack(void *, size_t);

	/*! Initialize a device ("eth0" for example) for packet-
	 *  capturing. It MUST be called before sniffpack() is launched.
	 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
	 *  Fetch at most 'snaplen' bytes per call.
	 */
	virtual int init_device(const std::string&, int, size_t);

	/*! Set the type-field in the actuall ICMP-packet.
	 */
	uint8_t set_type(uint8_t);

	/*! Set ICMP-code.
 	 */
	uint8_t set_code(uint8_t);

	/*! Set id field in the actuall ICMP-packet
	 */
	uint16_t set_icmpId(uint16_t);

	/*! Set the sequecenumber of the actuall ICMP-packet.
	 */
	uint16_t set_seq(uint16_t);

	/*! Set new GW address if applicable (network order). */
	uint32_t set_gateway(uint32_t);

	/*! Set MUT field if applicable. */
	uint16_t set_mtu(uint16_t);

	/*! Get the type-field from the actuall ICMP-packet.
 	 */
	uint8_t get_type();

	/*! Get ICMP-code.
 	 */
	uint8_t get_code();

	/*! Get the id field from actuall ICMP-packet.
	 */
	uint16_t get_icmpId();

	/*! Get the sequence-number of actuall ICMP-packet
	 */
	uint16_t get_seq();

	/*! Get new gateway address if applicable. */
	uint32_t get_gateway();

	/*! Get MTU field if applicable (in network order). */
	uint16_t get_mtu();
}; // class ICMP{}


typedef ICMP ICMP4;

} // namespace usipp
#endif // _ICMP_H_

