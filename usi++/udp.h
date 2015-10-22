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


#ifndef usipp_udp_h
#define usipp_udp_h

#include <string>
#include <stdint.h>

#include "usi-structs.h"
#include "datalink.h"
#include "ip6.h"
#include "ip.h"
#include "RX.h"
#include "TX.h"


namespace usipp {

/*! \class UDP
 *  \brief Available as UDP4 and UDP6
 *  \example udp_spoof.cc
 *  \example udp6_spoof.cc
 */
template<typename T>
class UDP : public T {
private:
	usipp::udphdr d_udph;
public:

	/*! Construct an UDP object, destinated to a host (FQDN or IP string).
	 */
	UDP(const std::string &, RX *rx = NULL, TX *tx = NULL);

	/*! Destructor
	 */
	virtual ~UDP();

	/*! Copy Constructor
	 */
	UDP(const UDP<T> &);

	/*! Assignment operator.
	 */
	UDP<T> &operator=(const UDP<T>&);

	/*! Get the source port of the UDP datagram.
	 */
	uint16_t get_srcport();


	/*! Get the destination port of the UDP datagram.
	 */
	uint16_t get_dstport();

	/*! Return length of UDP header plus contained data.
	 */
	uint16_t get_len();

	/*! Return the checksum of UDP datagram.
	 */
	uint16_t get_udpsum();

	/*! Set the sourceport in the UDP header.
	*/
	uint16_t set_srcport(uint16_t);

	/*! Set the destination port in the UDP header.
	 */
	uint16_t set_dstport(uint16_t);

	/*! Set the length of the UDP datagram.
	 */
	uint16_t set_len(uint16_t);

	/*! Set the UDP checksum. Calling this function with s != 0
	 *  will prevent sendpack() from setting the checksum.
	 */
	uint16_t set_udpsum(uint16_t);

	/*! Return complete UDP header.
	 *  Usefull for some types of ICMP messages.
	 */
	udphdr &get_udphdr();

	/*! Send an UDP datagram containing 'paylen' bytes of data.
	 */
	virtual int sendpack(const void*, size_t);

	/*! Send a packet conating a string of payload. */
	virtual int sendpack(const std::string &);


	/*! Capture an packet from the NIC.
	*/
	virtual std::string &sniffpack(std::string &);


	/*! Capture an packet from the NIC.
	*/
	virtual int sniffpack(void*, size_t);

	/*! Initialize a device ("eth0" for example) for packet-
	*  capturing. It MUST be called before sniffpack() is launched.
	*  Set 'promisc' to 1 if you want the device running in promiscous mode.
	*  Fetch at most 'snaplen' bytes per call.
	*/
	virtual int init_device(const std::string &, int promisc, size_t snaplen);

};   // class UDP {}

/*! \class UDP4
 */
typedef UDP<IP> UDP4;

/*! \class UDP6
 */
typedef UDP<IP6> UDP6;


} // namespace usipp

#endif // _UDP_H_


