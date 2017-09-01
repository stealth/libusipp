/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2017 by Sebastian Krahmer,
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


#ifndef usipp_ipcomp_h
#define usipp_ipcomp_h

#include "usi-structs.h"

#include <string>

namespace usipp {


template<typename T>
class IPComp : public T {
private:

	usipp::ipcomp_hdr ipchdr;

public:

	IPComp(const std::string &, RX *rx = nullptr, TX *tx = nullptr);

	virtual ~IPComp();

	/*! Assignment operator
	 */
	IPComp<T> &operator=(const IPComp<T> &);

	/*! Copy constructor
	 */
	IPComp(const IPComp<T> &);

	/*! Capture an packet from the net.
	*/
	virtual std::string &sniffpack(std::string &);

	/*! Capture a packet from the net.
	 */
	virtual int sniffpack(void *buf, size_t buflen);

	/*! Capture a packet from the net.
	 */
	virtual int sniffpack(void *buf, size_t buflen, int &);

	/*! Send a packet.
	 */
	virtual int sendpack(const void *payload, size_t paylen);

	/*! Send a TCP packet with payload.
	 */
	virtual int sendpack(const std::string &);

	/*! Just sets filter to "tcp" and calls IP::init_device(), passing
	 *  the arguments along.
	 */
	virtual int init_device(const std::string &, int, size_t);

	uint8_t get_next() const
	{
		return ipchdr.next;
	}

	uint8_t set_next(uint8_t n)
	{
		return ipchdr.next = n;
	}

	uint8_t get_flags() const
	{
		return ipchdr.flags;
	}

	uint8_t set_flags(uint8_t f)
	{
		return ipchdr.flags = f;
	}

	/*! Get Compression Parameter Index */
	uint16_t get_cpi() const
	{
		return ntohs(ipchdr.cpi);
	}

	/*! Set Compression Parameter Index */
	uint16_t set_cpi(uint16_t c)
	{
		return ipchdr.cpi = htons(c);
	}

	/*! Get full IPComp header */
	ipcomp_hdr &get_ipchdr()
	{
		return ipchdr;
	}

	/*! Set full IPComp header */
	ipcomp_hdr &set_ipchdr(const ipcomp_hdr &i)
	{
		ipchdr = i;
		return ipchdr;
	}
};


typedef IPComp<IP> IPComp4;
typedef IPComp<IP6> IPComp6;

}	// namespace

#endif


