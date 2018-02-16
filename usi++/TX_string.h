/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2015 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
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

#ifndef usipp_tx_string_h
#define usipp_tx_string_h

#include "config.h"
#include "usi-structs.h"
#include "TX.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

namespace usipp {

/*! \class TX_string
 *  \brief TX provider implementing send/fetch as string
 */
class TX_string : public TX {
private:
	std::string pkt;
public:

	/*! Constructor */
	TX_string() : pkt("") {}

	/*! Destructor */
	virtual ~TX_string() { }

	/*! See RX::tag() */
	virtual int tag() { return TX_TAG_STRING; }

	/*! Send a packet into a string (starting with IP-hdr) */
	virtual int sendpack(const void *, size_t, struct sockaddr* = 0);

	/*! Send a packet into a string (starting with IP-hdr) */
	int sendpack(const std::string &);

	/*! Enable broadcast option (dummy) */
	virtual int broadcast();

	/*! dummy, no L2 address on strings */
	virtual int set_l2src(const std::string &s) { return 0; }

	/*! dummy, no L2 address on strings */
	virtual int set_l2dst(const std::string &s) { return 0; }

	/*! */
	virtual int tx_fd() { return -1; }

	/*! return the packet that was "sent" as string, including all payloads and hdrs */
	std::string get_pack() { return pkt; };
};

}	// namespace
#endif

