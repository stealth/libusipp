/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2020 by Sebastian Krahmer,
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
 * along with libusi++.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "usi++/usi++.h"
#include "usi++/ip6.h"
#include "usi++/TX_IP6.h"

#include "config.h"
#include <netdb.h>
#include <cstring>
#include <string>
#include <errno.h>
#include <new>
#include <vector>
#include <iostream>
#include <stdint.h>
#include <string>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>


namespace usipp {

using namespace std;

const uint8_t IP6::d_ipversion = 6;


IP6::IP6(const in6_addr &in6, uint8_t proto, RX *rx, TX *tx)
	: Layer2(rx, tx ? d_tx = tx : d_tx = new (nothrow) TX_IP6)
{
	memset(&iph, 0, sizeof(iph));
	memset(&d_pseudo, 0, sizeof(d_pseudo));

	iph.version = 6;
	iph.nexthdr = proto;
	d_proto = proto;
	iph.hop_limit = 64;
	set_dst(in6);
}


IP6::IP6(const string &hostname, uint8_t proto, RX *rx, TX *tx)
	: Layer2(rx, tx ? d_tx = tx : d_tx = new (nothrow) TX_IP6)
{
	memset(&iph, 0, sizeof(iph));
	memset(&d_pseudo, 0, sizeof(d_pseudo));

	iph.version = 6;
	iph.nexthdr = proto;
	d_proto = proto;
	iph.hop_limit = 64;
	set_dst(hostname);
}


IP6::IP6(const IP6 &rhs)
	: Layer2(rhs)
{
	if (this == &rhs)
		return;
	iph = rhs.iph;
	e_hdrs = rhs.e_hdrs;
	e_hdrs_len = rhs.e_hdrs_len;
	d_proto = rhs.d_proto;
	memset(&d_pseudo, 0, sizeof(d_pseudo));
}


IP6 &IP6::operator=(const IP6 &rhs)
{
	if (this == &rhs)
		return *this;
	Layer2::operator=(rhs);
	iph = rhs.iph;
	e_hdrs = rhs.e_hdrs;
	e_hdrs_len = rhs.e_hdrs_len;
	d_proto = rhs.d_proto;
	memset(&d_pseudo, 0, sizeof(d_pseudo));

	return *this;
}


IP6::~IP6()
{
	// not needed due to ref-counting
	//delete d_tx;
}


in6_addr IP6::get_src()
{
	return iph.saddr;
}


string &IP6::get_src(string &s)
{
	s = "";

	char buf[128] = {0};
	if (inet_ntop(AF_INET6, &iph.saddr, buf, sizeof(buf)))
		s = buf;
	return s;
}


in6_addr IP6::get_dst()
{
	return iph.daddr;
}


/* Get IPv6 destination address, dotted form */
string &IP6::get_dst(string &s)
{
	s = "";

	char buf[128] = {0};
	if (inet_ntop(AF_INET6, &iph.daddr, buf, sizeof(buf)))
		s = buf;
	return s;
}


/*! Set IPv6 source address */
int IP6::set_src(const string &src)
{
	in6_addr in6;

	if (inet_pton(AF_INET6, src.c_str(), &in6) != 1)
		return die("IP6::set_src::inet_pton", PERROR, errno);

	iph.saddr = in6;
	return 0;
}


/*! Set IPv6 destination address */
int IP6::set_dst(const string &dst)
{
	in6_addr in6;

	if (inet_pton(AF_INET6, dst.c_str(), &in6) != 1)
		return die("IP6::set_src::inet_pton", PERROR, errno);

	iph.daddr = in6;
	return 0;
}


/*! Set IPv6 destination address */
in6_addr &IP6::set_dst(const in6_addr &dst)
{
	iph.daddr = dst;
	return iph.daddr;
}


/*! Set IPv6 source address */
in6_addr &IP6::set_src(const in6_addr &src)
{
	iph.saddr = src;
	return iph.saddr;
}


uint8_t IP6::set_hoplimit(uint8_t hl)
{
	return iph.hop_limit = hl;
}


uint8_t IP6::get_hoplimit()
{
	return iph.hop_limit;
}


uint16_t IP6::get_payloadlen()
{
	return ntohs(iph.payload_len);
}


uint16_t IP6::set_payloadlen(uint16_t l)
{
	iph.payload_len = htons(l);
	return l;
}


int IP6::sendpack(const string &s)
{
	return sendpack(s.c_str(), s.size());
}


int IP6::sendpack(const void *payload, size_t paylen)
{
	size_t len = sizeof(iph) + e_hdrs_len + paylen;
	if (paylen > max_packet_size || len > max_packet_size)
		return die("IP6::sendpack: Packet payload too large.", STDERR, -1);

	char s[max_packet_size] = {0};

	iph.payload_len = htons(e_hdrs_len + paylen);

	memcpy(s, &iph, sizeof(iph));

	uint16_t offset = sizeof(iph);
	if (e_hdrs_len) {
		for (vector<string>::iterator i = e_hdrs.begin(); i != e_hdrs.end(); ++i) {
			memcpy(s + offset, i->c_str(), i->size());
			offset += i->size();
		}
	}

	sockaddr_in6 saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin6_family = AF_INET6;
	memcpy(&saddr.sin6_addr, &iph.daddr, sizeof(saddr.sin6_addr));

	memcpy(s + offset, payload, paylen);
	int r = Layer2::sendpack(s, len, (struct sockaddr*)&saddr);

	return r;
}


uint8_t IP6::get_proto()
{
	return iph.nexthdr;
}


uint8_t IP6::set_proto(uint8_t p)
{
	return iph.nexthdr = p;
}


void IP6::clear_headers()
{
	e_hdrs.clear();
	e_hdrs_len = 0;

	// reset protocol to the original proto that was given
	iph.nexthdr = d_proto;
}


uint16_t IP6::num_headers()
{
	return e_hdrs.size();
}


string &IP6::next_header(uint16_t idx, string &s)
{
	if (idx >= e_hdrs.size()) {
		s = "";
		return s;
	}
	s = e_hdrs[idx];
	return s;
}


// add an extra header
int IP6::next_header(const string &s)
{
	if (s.size() % 8)
		return -1;
	e_hdrs.push_back(s);
	e_hdrs_len += s.size();
	return 0;
}


/*! sniff a IP6 packet */
string &IP6::sniffpack(string &s)
{
	int off = 0;
	s = "";
	char buf[max_packet_size];
	int r = this->sniffpack(buf, sizeof(buf), off);
	if (r > off)
		s = string(buf + off, r - off);
	return s;
}


int IP6::sniffpack(void *s, size_t len)
{
	int off = 0;
	int r = sniffpack(s, len, off);
	if (r <= 0)
		return r;
	if (r <= off)
		return 0;
	if (off > 0)
		memmove(s, reinterpret_cast<char *>(s) + off, r - off);
	return r - off;
}


int IP6::sniffpack(void *buf, size_t blen, int &off)
{
	off = 0;
	int r = Layer2::sniffpack(buf, blen);

   	if (r == 0 && Layer2::timeout())
		return 0;	// timeout
	else if (r < 0)
		return -1;
	else if (r < off + (int)sizeof(iph))
		return die("IP6::sniffpack: short packet", STDERR, -1);

	memcpy(&iph, reinterpret_cast<char *>(buf) + off, sizeof(iph));
	off += sizeof(iph);

	int32_t totlen = (int32_t)get_payloadlen();
	totlen &= 0xffff;
	if (r < off + totlen || totlen > max_packet_size)
		return r;

	e_hdrs.clear();
	e_hdrs_len = 0;
	uint16_t offset = 0;

	// Any IP6 extension headers?
	if (iph.nexthdr == ipproto6_hopopts || iph.nexthdr == ipproto6_routing ||
	    iph.nexthdr == ipproto6_fragment || iph.nexthdr == ipproto6_dstopts ||
	    iph.nexthdr == ipproto_mobile) {
		ip6_opt *op = (ip6_opt *)(&iph + 1);
		do {
			totlen -= (8*op->ip6o_len + 8);
			if (totlen < 0)
				break;
			// cant wrap, since totlen is really 16bit
			offset += (8*op->ip6o_len + 8);
			e_hdrs.push_back(string((char *)op, 8*op->ip6o_len + 8));
			op = (ip6_opt *)((char *)op + 8*op->ip6o_len + 8);
		} while (op->ip6o_type == ipproto6_hopopts || op->ip6o_type == ipproto6_routing ||
		         op->ip6o_type == ipproto6_fragment ||op->ip6o_type == ipproto6_dstopts ||
	        	 op->ip6o_type == ipproto_mobile);
	}

	e_hdrs_len = offset;
	off += offset;

	return r;
}


int IP6::init_device(const string &dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);
	if (r < 0)
		return r;
	r = Layer2::setfilter("ip6");
	return r;
}


}

