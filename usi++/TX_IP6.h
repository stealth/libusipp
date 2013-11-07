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

#ifndef __tx_ip6_h__
#define __tx_ip6_h__

#include "config.h"
#include "usi-structs.h"
#include "TX.h"
#include <stdio.h>
#include <unistd.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>


namespace usipp {

/*! \class TX_IP6
 *  \brief TX provider using raw IP6 sockets
 */
class TX_IP6 : public TX {
private:
	int rawfd;
public:

	/*! Constructor */
	TX_IP6() : rawfd(-1) {}

	/*! Destructor */
	virtual ~TX_IP6() { close(rawfd); }

	/*! See TX::tag() */
	virtual int tag() { return TX_TAG_IP6; }

	/*! Send a packet on raw socket (starting with IP-hdr) */
	virtual int sendpack(const void *, size_t, struct sockaddr* = 0);

	/*! Send a packet on raw socket (starting with IP-hdr) */
	int sendpack(const std::string &);

	/*! Enable broadcast option on socket */
	virtual int broadcast();

	/*! dummy, raw socket doesnt have layer2 address */
	virtual int set_l2src(const std::string &s) { return 0; }

	/*! dummy, raw socket doesnt have layer2 address */
	virtual int set_l2dst(const std::string &s) { return 0; }
};

}	// namespace
#endif

