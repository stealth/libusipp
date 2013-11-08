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

#ifndef __icmp6_h__
#define __icmp6_h__

#include "usi-structs.h"
#include "datalink.h"
#include "Layer2.h"
#include "ip6.h"
#include "RX.h"
#include "TX.h"

#include <string>
#include <stdint.h>
#include <sys/types.h>

namespace usipp {

/*! \class ICMP6
 *  \brief ICMP6 class
 *  \example martian_dest_test6.cc
 *  \example icmp6_sniff.cc
 */
class ICMP6 : public IP6 {
private:
	struct icmp6_hdr icmp6hdr;

public:
	/*! create a new ICMP6 object to destination dst */
	ICMP6(const std::string &dst, RX *rx = NULL, TX *tx = NULL);

	virtual ~ICMP6();

	//ICMP6(const ICMP6 &);

	//ICMP &operator=(const ICMP6 &);

	/*! Set ICMPv6 code */
	uint8_t set_code(uint8_t);

	/*! Get ICMPv6 code */
	uint8_t get_code();

	/*! Set ICMPv6 type */
	uint8_t set_type(uint8_t);

	/*! Get ICMPv6 type */
	uint8_t get_type();

	/*! Get ICMPv6 ID if applicable */
	uint16_t get_icmpId();

	/*! Set ICMPv6 ID field */
	uint16_t set_icmpId(uint16_t);

	/*! Get ICMPv6 sequence number if applicable */
	uint16_t get_seq();

	/*! Set ICMPv6 sequence number */
	uint16_t set_seq(uint16_t);

	/*! Get ICMpv6 data */
	uint32_t get_data();

	/*! Set ICMPv6 data */
	uint32_t set_data(uint32_t);

	/*! Send a ICMPv6 packet containg payload */
	virtual int sendpack(const void *, size_t);

	/*! Send a ICMPv6 packet containg payload */
	virtual int sendpack(const std::string &);

	/*! Sniff a ICMP6 packet and set up internal fields. */
	virtual std::string &sniffpack(std::string &);

	/*! Sniff a ICMP6 packet and set up internal fields. */
	virtual int sniffpack(void *, size_t);

};

}

#endif

