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

#ifndef __tx_dnet_eth_h__
#define __tx_dnet_eth_h__

#include "TX.h"
#include "config.h"
#include "usi-structs.h"
#include <sys/socket.h>
#include <string>

#ifdef HAVE_LIBDNET
#include <dnet.h>
#elif HAVE_LIBDUMBNET
#include <dumbnet.h>
#endif


namespace usipp {

/*!\class TX_dnet_eth
 * \brief libdnet packet socket TX provider
 * \example martian_dest_test.cc
 */
#if defined(HAVE_LIBDNET) || defined(HAVE_LIBDUMBNET)

class TX_dnet_eth : public TX {
private:

	eth_t *deth;

	usipp::ether_header ehdr;

public:

	/*! provide a dnet eth (layer 2) sender with NIC-name as argument */
	TX_dnet_eth(const std::string &);

	/*! destructor */
	virtual ~TX_dnet_eth()
	{
		if (deth)
			eth_close(deth);
	}

	/*! See TX::tag() */
	virtual int tag() { return TX_TAG_DNET_ETH; }

	/*! send a packet with payload via libdnet (eth), hardware frame included */
	virtual int sendpack(const void *, size_t, struct sockaddr * = 0);

	/*! send a packet with payload via libdnet (eth), hardware frame included */
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

	/*! Set ethernet type (ETH_P_IP, ETH_P_ARP etc).*/
	void set_type(uint16_t);

};
#else

/* dummy wrapper; its strongly recommended to install libdnet */
class TX_dnet_eth : public TX {

public:

	TX_dnet_eth(const std::string &) {}

	virtual int tag() { return TX_TAG_NONE; }

	virtual int sendpack(const void *vp, size_t, struct sockaddr * = 0) { return -1; }

	virtual int broadcast() { return -1; }

	virtual int set_l2src(const std::string &) { return -1; }

	virtual int set_l2dst(const std::string &) { return -1; }
};

#endif

} // namespace usipp

#endif

