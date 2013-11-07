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

#ifndef __tx_pcap_eth_h__
#define __tx_pcap_eth_h__

#include "TX.h"
#include "datalink.h"
#include "refcount.h"
#include "config.h"
#include "usi-structs.h"
#include <sys/socket.h>
#include <string>


namespace usipp {

/*!\class TX_pcap
 * \brief libpcap packet socket TX provider (via pcap_ibject())
 */

class TX_pcap : public TX {
private:

	usipp::pcap *d_pcap;
	std::string d_cooked, d_frame;

public:

	/*! provide a pcap eth (layer 2) sender with a pcap object as argument.
	 * Does not take ownership of pcap *, so you must destroy it yourself.
	 */
	TX_pcap(usipp::pcap *);

	/*! destructor */
	virtual ~TX_pcap()
	{
	}

	/*! See TX::tag() */
	virtual int tag() { return TX_TAG_PCAP; }

	/*! send a packet with payload via libpcap (eth), hardware frame included */
	virtual int sendpack(const void *, size_t, struct sockaddr * = 0);

	/*! send a packet with payload via libpcap (eth), hardware frame included */
	int sendpack(const std::string &);

	/*! Nop, use set_frame() */
	virtual int broadcast()
	{
		return 0;
	}

	/*! Nop, use set_frame() */
	virtual int set_l2src(const std::string &s)
	{
		return 0;
	}

	/*! Nop, use set_frame() */
	virtual int set_l2dst(const std::string &s)
	{
		return 0;
	}

	/*! Nop, use set_frame() */
	void set_type(uint16_t)
	{
	}


	/*! Set the layer2 frame */
	void set_frame(const std::string &s)
	{
		d_frame = s;
	}


	/*! Set any cooked header, e.g. radiotap */
	void set_cooked(const std::string &s)
	{
		d_cooked = s;
	}

};

} // namespace usipp

#endif

