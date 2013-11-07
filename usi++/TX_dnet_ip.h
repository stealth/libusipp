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

#ifndef __tx_dnet_ip__
#define __tx_dnet_ip__

#include "TX.h"
#include "config.h"
#include "usi-structs.h"
#include <string>
#include <sys/socket.h>

#ifdef HAVE_LIBDNET
#include <dnet.h>
#endif


namespace usipp {

/*! \class TX_dnet_ip
 *  \brief libdnet raw socket TX provider
 *  \example synping.cc
 */
#ifdef HAVE_LIBDNET

class TX_dnet_ip : public TX {
private:

	ip_t *dip;

public:

	/*! Constructor */
	TX_dnet_ip();

	/*! Destructor */
	virtual ~TX_dnet_ip()
	{
		if (dip)
			ip_close(dip);
	}

	/*! See TX::tag() */
	virtual int tag() { return TX_TAG_DNET_IP; }

	/*! send a packet via libdnet (ip) */
	virtual int sendpack(const void *, size_t, struct sockaddr * = 0);

	/*! send a packet via libdnet (ip) */
	int sendpack(const std::string &);

	/*! enable broadcast sending */
	virtual int broadcast();

	/*! dummy, raw sockets dont have layer2 address */
	virtual int set_l2src(const std::string &) { return 0; }

	/*! dummy, raw sockets dont have layer2 address */
	virtual int set_l2dst(const std::string &) { return 0; }
};
#else

/* dummy wrapper; its strongly recommended to install libdnet */
class TX_dnet_ip : public TX {

public:

	/*!*/
	TX_dnet_ip(const std::string &) {}

	/*!*/
	virtual int tag() { return TX_TAG_NONE; }

	/*!*/
	virtual int sendpack(const void *vp, size_t, struct sockaddr * = 0) { return -1; }

	/*!*/
	virtual int broadcast() { return -1; }

	/*! dummy, raw sockets dont have layer2 address */
	virtual int set_l2src(const std::string &) { return -1; }

	/*! dummy, raw sockets dont have layer2 address */
	virtual int set_l2dst(const std::string &) { return -1; }
};


#endif

} // namespace usipp

#endif

