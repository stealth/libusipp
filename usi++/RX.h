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

#ifndef __rx_h__
#define __rx_h__

#include "config.h"
#include "usi-structs.h"
#include "object.h"
#include <stdio.h>
#include <string>
#include <sys/types.h>


namespace usipp {

/*! \class RX
 * \brief abstract RX provider class
 *
 * Receivier provider.
 * You can implement your own classes and register objects
 * via register_rx(). You must provide at least the functions
 * below. Shipped with usi++++ is the Pcap provider.
 */
class RX : public Object {
public:

	/*! Constructor */
	RX() {}

	/*! Destrcutor */
	virtual ~RX() {}

	/*! Capture a packet from the net, string version */
	virtual std::string &sniffpack(std::string &) = 0;

	/*! Capture a packet from the network.
	 *  At most a given len. */
	virtual int sniffpack(void *, size_t) = 0;

	/*! Init a device before capturing */
	virtual int init_device(const std::string &, int, size_t) = 0;

	/*! Set a filter of what must be captured */
	virtual int setfilter(const std::string &) = 0;

	/*! set a timeout */
	virtual int timeout(const struct timeval &) = 0;

	/*! RX derived class must also tell user when timeout occurs */
	virtual bool timeout() = 0;

	/*! Get Layer2 source address */
	virtual std::string &get_l2src(std::string &) = 0;

	/*! Get Layer2 destination address */
	virtual std::string &get_l2dst(std::string &) = 0;

	/*! return some RX-unique tag, e.g. RX_PCAP etc, see usi-structs.h enum.
	 *  This is for the upper layers to check which capture layer has been
	 *  registered.
	 */
	virtual int tag() = 0;
};

} // namespace usipp
#endif

