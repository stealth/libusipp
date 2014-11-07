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


#ifndef __usipp_h__
#define __usipp_h__

enum {
	usipp_version = 202
};

#include "config.h"
#include "usi-structs.h"
#include "object.h"
#include "arp.h"
#include "eapol.h"
#include "datalink.h"
#include "Layer2.h"
#include "ip.h"
#include "ip6.h"
#include "icmp.h"
#include "icmp6.h"
#include "udp.h"
#include "tcp.h"
#include "TX.h"
#include "TX_dnet_ip.h"
#include "TX_dnet_eth.h"
#include "TX_pcap_eth.h"
#include "TX_pcap.h"
#include "TX_IP.h"
#include "TX_IP6.h"
#include "RX.h"
#include <string>

namespace usipp {

/*! \class usifault
 *  \brief the class of which exceptions are thrown, if enabled
 */
class usifault {
	std::string fault;

public:
	/*! */
	usifault(const std::string &s = "undef") : fault(s) {}

	/*! */
        ~usifault() {}

	/*! return error string */
	const char *why() { return fault.c_str(); }
};

extern unsigned short in_cksum(unsigned short *ptr, int len, bool may_pad);


} // namespace usipp


#endif

