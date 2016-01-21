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

#ifndef usipp_rx_string_h
#define usipp_rx_string_h

#include "usi-structs.h"
#include "RX.h"
#include <stdio.h>
#include <string>
#include <sys/time.h>

#include "config.h"


namespace usipp {

/*! \class RX_string
 *  \brief RX string receiver
 */
class RX_string : public RX {
private:


	std::string d_pkt;

	// filled by init_device()
	std::string d_dev;

	std::string::size_type d_offset;

public:

	/*! This constructor should be used to
	 *  initialize RX_string.
	 */
	RX_string() : d_pkt(""), d_dev(""), d_offset(0) {};

	/*! Copy-constructor
	 */
	RX_string(const RX_string &);

	/*! destructor */
	virtual ~RX_string() {};

	/*! assignment operator */
	RX_string &operator=(const RX_string &);

	/*! returns ""
	 */
	virtual std::string &get_l2src(std::string &);

	/*! returns ""
	 */
	virtual std::string &get_l2dst(std::string &);

	/*! special meaning
	 */
	virtual int init_device(const std::string &dev, int promisc, size_t snaplen);

	/*! NOP
	 */
	virtual int setfilter(const std::string &filter);

	virtual void set_pack(const std::string &s) { d_pkt = s; }

	/*! read a packet from string */
	virtual std::string &sniffpack(std::string &);

	/*! read a packet from fd
	*/
	virtual int sniffpack(void *, size_t);

	/*! Set a timeout. Implements RX::timeout() = 0. */
	virtual int timeout(const struct timeval &);

	/*! Returns true when recv() timed out */
	virtual bool timeout();

	/*! See RX::tag() */
	virtual int tag() { return RX_TAG_STRING; }

}; // class RX_string {}


} // namespace usipp

#endif

