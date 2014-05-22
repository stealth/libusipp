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

IP6::IP6(const struct in6_addr &in6, uint8_t proto, RX *rx, TX *tx)
	: Layer2(rx, tx ? d_tx = tx : d_tx = new TX_IP6)
{
	memset(&iph, 0, sizeof(iph));
	memset(&d_pseudo, 0, sizeof(d_pseudo));

	iph.version = 6;
	iph.nexthdr = proto;
	d_proto = proto;
	e_hdrs_len = 0;
	iph.hop_limit = 64;
	set_dst(in6);
}


IP6::IP6(const string &hostname, uint8_t proto, RX *rx, TX *tx)
	: Layer2(rx, tx ? d_tx = tx : d_tx = new TX_IP6)
{
	memset(&iph, 0, sizeof(iph));
	memset(&d_pseudo, 0, sizeof(d_pseudo));

	iph.version = 6;
	iph.nexthdr = proto;
	e_hdrs_len = 0;
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
	return *this;
}


IP6::~IP6()
{
	// not needed due to ref-counting
	//delete d_tx;
}


struct in6_addr IP6::get_src()
{
	return iph.saddr;
}


string &IP6::get_src(string &s)
{
	s = "";

	char buf[128];
	memset(buf, 0, sizeof(buf));
	if (inet_ntop(AF_INET6, &iph.saddr, buf, sizeof(buf)))
		s = buf;
	return s;
}


struct in6_addr IP6::get_dst()
{
	return iph.daddr;
}


string &IP6::get_dst(string &s)
{
	s = "";

	char buf[128];
	memset(buf, 0, sizeof(buf));
	if (inet_ntop(AF_INET6, &iph.daddr, buf, sizeof(buf)))
		s = buf;
	return s;
}


int IP6::set_src(const string &src)
{
	struct hostent *he = NULL;
	struct in6_addr in6;

	if (inet_pton(AF_INET6, src.c_str(), &in6) < 0) {
		if ((he = gethostbyname2(src.c_str(), AF_INET6)) == NULL)
			return die("IP6::set_src::gethostbyname2", RETURN, -h_errno);
		memcpy(&iph.saddr, he->h_addr, 16);
	} else
		iph.saddr = in6;
	return 0;
}


int IP6::set_dst(const string &dst)
{
	struct hostent *he = NULL;
	struct in6_addr in6;

	if (inet_pton(AF_INET6, dst.c_str(), &in6) < 0) {
		if ((he = gethostbyname2(dst.c_str(), AF_INET6)) == NULL)
			return die("IP6::set_src::gethostbyname2", RETURN, -h_errno);
		memcpy(&iph.daddr, he->h_addr, 16);
	} else {
		iph.daddr = in6;
	}
	return 0;
}


struct in6_addr &IP6::set_dst(const struct in6_addr &dst)
{
	iph.daddr = dst;
	return iph.daddr;
}


struct in6_addr &IP6::set_src(const struct in6_addr &src)
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
	return htons(iph.payload_len = l);
}


int IP6::sendpack(const string &s)
{
	return sendpack(s.c_str(), s.size());
}


int IP6::sendpack(const void *payload, size_t paylen)
{
	if (paylen > 66000)
		return -1;

	size_t len = sizeof(iph) + e_hdrs_len + paylen;
	char *s = new (nothrow) char[len];

	if (!s)
		return die("IP6::sendpack: OOM", STDERR, -1);

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
	delete [] s;

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
	s = "";
	char buf[4096];
	int r = this->sniffpack(buf, sizeof(buf));
	if (r > 0)
		s = string(buf, r);
	return s;
}


int IP6::sniffpack(void *buf, size_t blen)
{
	int r = 0;
	int xlen = 66000;

	char *tmp = new (nothrow) char[xlen];

	if (!tmp)
		return die("IP6::sniffpack: OOM", STDERR, -1);

	memset(tmp, 0, xlen);

   	if ((r = Layer2::sniffpack(tmp, xlen)) == 0 &&
	    Layer2::timeout()) {
		delete [] tmp;
		return 0;	// timeout
	} else if (r < (int)sizeof(iph)) {
		delete [] tmp;
		return -1;
	}

	memcpy(&iph, tmp, sizeof(iph));
	r -= sizeof(iph);

	int32_t totlen = (int32_t)get_payloadlen();
	if (r < 0) {
		delete [] tmp;
		return -1;
	} else if (r == 0 || r < totlen || totlen < 0) {//TODO: handle fragments
		delete [] tmp;
		return 0;
	}

	e_hdrs.clear();
	e_hdrs_len = 0;
	uint16_t offset = 0;

	// Any IP6 extension headers?
	if (iph.nexthdr == NEXT_HDR_HBH || iph.nexthdr == NEXT_HDR_RH ||
	    iph.nexthdr == NEXT_HDR_FH || iph.nexthdr == NEXT_HDR_DOH ||
	    iph.nexthdr == NEXT_HDR_MOB) {
		ip6_opt *op = (ip6_opt *)(&iph + 1);
		do {
			totlen -= (8*op->ip6o_len + 8);
			if (totlen < 0)
				break;
			offset += (8*op->ip6o_len + 8);
			e_hdrs.push_back(string((char *)op, 8*op->ip6o_len + 8));
			op = (ip6_opt *)((char *)op + 8*op->ip6o_len + 8);
		} while (op->ip6o_type == NEXT_HDR_HBH || op->ip6o_type == NEXT_HDR_RH ||
		         op->ip6o_type == NEXT_HDR_FH ||op->ip6o_type == NEXT_HDR_DOH ||
	        	 op->ip6o_type == NEXT_HDR_MOB);
	}

	e_hdrs_len = offset;
	r -= offset;

	if (r < 0) {
		delete [] tmp;
		return -1;
	}

	if (buf)
		memcpy(buf, tmp + sizeof(iph) + offset, r < (int)blen ? r : blen);

	delete [] tmp;
	return r < (int)blen ? r : blen;
}


int IP6::init_device(const string &dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);
	if (r < 0)
		return r;
	r = Layer2::setfilter("ip6");
	return r;
}


};

