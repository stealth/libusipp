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

#ifndef usipp_tx_h
#define usipp_tx_h

#include "config.h"
#include "usi-structs.h"
#include "object.h"
#include <stdio.h>
#include <sys/socket.h>

namespace usipp {

/*!\class TX
 * \brief abstract TX provider class
 *
 * The transmitter lets you send packets on the net.
 * You can write your own and register them with
 * register_tx() but you must provide at least
 * a sendpack(), broadcast(), set_l2src() and set_l2dst() functions.
 * Shipped with USI++ is TX_IP which
 * is in fact a RAW socket, TX_IP6, TX_dnet_ip and TX_dnet_eth for dnet providers  */
class TX : public Object {
public:

	/*! Constructor */
	TX() {}

	/*! Destructor */
	virtual ~TX() {}

	/*! Do the send. You don't call this directly. IP::sendpack() etc
	 *  deliver the request to here. You need to provide a sendpack()
	 *  when you write your own TX classes.
	 */
	virtual int sendpack(const void *, size_t, struct sockaddr * = 0) = 0;

	/*! return some TX-unique tag, e.g. TX_IP etc, see usi-structs.h enum.
	 *  This is for the upper layers to check which transport layer has been
	*   registered, since some require IP checksum compuatation, and some dont.
	 */
	virtual int tag() = 0;

	/*! Must have capability to send broadcast packets. May be
	 * just a dummy.
	 */
	virtual int broadcast() = 0;

	/*! set layer2 source address (may be a dummy for RAW sockets) */
	virtual int set_l2src(const std::string &) = 0;

	/*! set layer2 destination address ((may be a dummy for RAW sockets) */
	virtual int set_l2dst(const std::string &) = 0;
};

} // namespace usipp

#endif

