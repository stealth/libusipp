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

#ifndef usipp_tx_pcap_eth_h
#define usipp_tx_pcap_eth_h

#include "TX.h"
#include "datalink.h"
#include "refcount.h"
#include "config.h"
#include "usi-structs.h"
#include <sys/socket.h>
#include <string>


namespace usipp {

/*!\class TX_pcap_eth
 * \brief libpcap packet socket TX provider (via pcap_inject())
 * \example martian_dest_test2.cc
 */

class TX_pcap_eth : public TX {
private:

	usipp::pcap *d_pcap;
	ether_header ehdr;

public:

	/*! provide a pcap eth (layer 2) sender with a pcap object as argument.
	 * Does not take ownership of pcap *, so you must destroy it yourself.
	 */
	TX_pcap_eth(usipp::pcap *);

	/*! destructor */
	virtual ~TX_pcap_eth()
	{
	}

	/*! See TX::tag() */
	virtual int tag() { return TX_TAG_PCAP_ETH; }

	/*! send a packet with payload via libpcap (eth), hardware frame included */
	virtual int sendpack(const void *, size_t, struct sockaddr * = 0);

	/*! send a packet with payload via libpcap (eth), hardware frame included */
	int sendpack(const std::string &);

	/*! enable broadcasting of TX */
	virtual int broadcast();

	/*! Set ethernet source address. If len of string is ETH_A_LEN (6), use it as binary blob,
	 *  otherwise expect it to be of the 11:22:33:44:55:66 format.
	 */
	virtual int set_l2src(const std::string &);

	/*! Set ethernet destination address. If len of string is ETH_A_LEN (6), use it as binary blob,
         *  otherwise expect it to be of the 11:22:33:44:55:66 format.
	 */
	virtual int set_l2dst(const std::string &);

	/*!*/
	virtual int tx_fd() { return d_pcap->rx_fd(); }

	/*! Set ethernet type (ETH_P_IP, ETH_P_ARP etc).*/
	void set_type(uint16_t);

};

} // namespace usipp

#endif

