/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2016 by Sebastian Krahmer,
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

#ifndef usipp_rx_fd_h
#define usipp_rx_fd_h

#include "usi-structs.h"
#include "RX.h"
#include <stdio.h>
#include <string>
#include <sys/time.h>

#include "config.h"


namespace usipp {

/*! \class RX_fd
 *  \brief RX fd receiver, e.g. tuntap fd or alike
 */
class RX_fd : public RX {
private:
	struct timeval d_tv;

	int d_fd;

	ether_header d_ether;

	// filled by init_device()
	std::string d_dev;

	// true when timed out
	bool d_timeout;

	bool d_has_ether;

	const char *d_packet;

	int d_offset;

protected:

	std::string d_cooked;

public:

	/*! This constructor should be used to
	 *  initialize RX_fd.
	 */
	RX_fd(int);

	/*! Copy-constructor
	 */
	RX_fd(const RX_fd &);

	/*! destructor */
	virtual ~RX_fd();

	/*! assignment operator */
	RX_fd &operator=(const RX_fd &);

	/*! returns "" in tun case
	 */
	virtual std::string &get_l2src(std::string &);

	/*! returns "" in tun case
	 */
	virtual std::string &get_l2dst(std::string &);

	/*!
	 */
	virtual std::string &get_frame(std::string &);

	/*! special meaning
	 */
	virtual int init_device(const std::string &dev, int promisc, size_t snaplen);

	/*! NOP
	 */
	virtual int setfilter(const std::string &filter);

	/*! read a packet from fd */
	virtual std::string &sniffpack(std::string &);

	/*! read a packet from fd
	*/
	virtual int sniffpack(void *, size_t);

	/*! Set a timeout. Implements RX::timeout() = 0. */
	virtual int timeout(const struct timeval &);

	/*! Returns true when recv() timed out */
	virtual bool timeout();

	/*! See RX::tag() */
	virtual int tag() { return RX_TAG_FD; }

	/*! Get ethernet type if it has ethernet
	 */
	uint16_t get_etype();

	/*! returns fd. */
	int handle() { return d_fd; }

	/*! Return the cooked header if any, e.g. tuntap header */
	std::string &get_cooked(std::string &);

}; // class RX_fd {}


} // namespace usipp

#endif

