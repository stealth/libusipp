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

#ifndef __ip6_h__
#define __ip6_h__

#include "usi-structs.h"
#include "datalink.h"
#include "Layer2.h"
#include "RX.h"
#include "TX.h"

#include <string>
#include <stdint.h>
#include <vector>


namespace usipp {


/*! \class IP6
 *  \brief IP6 class
 *  \example icmp6_sniff.cc
 */
class IP6 : public Layer2 {

public:
	/*! New IP6 packet with destination address and next-header proto.
	 *  Tries to set source
	 *  address to what it finds out via its own hostname. If that fails,
	 *  the src address will be 0.
	 */
	IP6(const struct in6_addr &dst, uint8_t proto, RX *rx = NULL, TX *tx = NULL);

	/*! New IP6 packet with destination address (hostname or IP6 string)
	 *  and next-header 'proto'.
	 *  Tries to set source
	 *  address to what it finds out via its own hostname. If that fails,
	 *  the src address will be 0.
	 */
	IP6(const std::string &dst, uint8_t proto, RX *rx = NULL, TX *tx = NULL);

	/*! Copy constructor */
	IP6(const IP6&);

	/*! assignment operator */
	IP6 &operator=(const IP6 &);

	/*! destructor */
	virtual ~IP6();

	/*! Get IP6 source address */
	struct in6_addr get_src();

	/*! Get IP6 source address, string version */
	std::string &get_src(std::string &);

	/*! Get IP6 destination address */
	struct in6_addr get_dst();

	/*! Get IP6 destination address, string version */
	std::string &get_dst(std::string &);

	/*! Set IP6 source address */
	struct in6_addr &set_src(const struct in6_addr &);

	/*! Set IP6 source address, hostname or IP6-string */
	int set_src(const std::string &);

	/*! Set IP6 destination address */
	struct in6_addr &set_dst(const struct in6_addr &);

	/*! Set IP6 destination address, hostname or IP6-string */
	int set_dst(const std::string &);

	/*! Get hop limit field */
	uint8_t get_hoplimit();

	/*! Set hop limit field */
	uint8_t set_hoplimit(uint8_t);

	/*! Get the next header value */
	uint8_t get_proto();

	/*! Set the next header value */
	uint8_t set_proto(uint8_t);

	/*! Get payload len in host byte order */
	uint16_t get_payloadlen();

	/*! Set payload len */
	uint16_t set_payloadlen(uint16_t);

	/*! Clear all IP6 extension headers, if any. Resets next header
	 *  field of IP6 header to the original Upper Layer value given during
	 *  object construction.
	 */
	void clear_headers();

	/*! How many extension headers for this IP6 packet exist? */
	uint16_t num_headers();

	/*! return the extension header as string at index or return empty
	 * string
	 */
	std::string &next_header(uint16_t idx, std::string &);

	/*! Add another extension header to this IP6 packet. The caller has to
	 *  set all the next header fields of ALL headers by himself, including
	 *  the IP6 header.
	 */
	int next_header(const std::string &);

	/*! Send an IP6 packet with payload */
	virtual int sendpack(const void *, size_t);

	/*! Send an IP6 packet with payload */
	virtual int sendpack(const std::string &);

	/*! initializse device for sniffing */
	virtual int init_device(const std::string &, int, size_t);

	/*! Sniff a IP6 packet and set up internal fields. */
	virtual std::string &sniffpack(std::string &);

	/*! Sniff a IP6 packet and set up internal fields. */
	virtual int sniffpack(void *, size_t);

private:
	struct ip6_hdr iph;
	uint8_t d_proto;
	std::vector<std::string> e_hdrs;
	uint16_t e_hdrs_len;
	TX *d_tx;

protected:
	struct pseudohdr6 d_pseudo;

};

};

#endif

