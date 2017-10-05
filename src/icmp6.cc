/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2017 by Sebastian Krahmer,
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
#include "usi++/icmp6.h"
#include "usi++/TX_IP6.h"
#include "usi++/usi-structs.h"

#include "config.h"
#include <string>
#include <stdint.h>
#include <errno.h>
#include <new>
#include <vector>
#include <iostream>
#include <string.h>
#include <arpa/inet.h>


namespace usipp {

using namespace std;


ICMP6::ICMP6(const string &dst, RX *rx, TX *tx)
	: IP6(dst, numbers::ipproto_icmpv6, rx, tx)
{
	memset(&icmp6hdr, 0, sizeof(icmp6hdr));
}


ICMP6::~ICMP6()
{
}


uint8_t ICMP6::set_type(uint8_t t)
{
	return icmp6hdr.icmp6_type = t;
}


uint8_t ICMP6::get_type()
{
	return icmp6hdr.icmp6_type;
}


uint8_t ICMP6::set_code(uint8_t code)
{
	return icmp6hdr.icmp6_code = code;
}


uint8_t ICMP6::get_code()
{
	return icmp6hdr.icmp6_code;
}


uint16_t ICMP6::get_seq()
{
	return ntohs(icmp6hdr.un.icmp6_data16[1]);
}


uint16_t ICMP6::set_seq(uint16_t seq)
{
	icmp6hdr.un.icmp6_data16[1] = htons(seq);
	return seq;
}


uint16_t ICMP6::get_icmpId()
{
	return ntohs(icmp6hdr.un.icmp6_data16[0]);
}


uint16_t ICMP6::set_icmpId(uint16_t id)
{
	icmp6hdr.un.icmp6_data16[0] = htons(id);
	return id;
}


uint32_t ICMP6::get_data()
{
	return icmp6hdr.un.icmp6_data32[0];
}


uint32_t ICMP6::set_data(uint32_t d)
{
	icmp6hdr.un.icmp6_data32[0] = d;
	return d;
}


int ICMP6::sendpack(const void *payload, size_t paylen)
{
	pseudohdr6 pseudo;
	memset(&pseudo, 0, sizeof(pseudo));

	size_t len = sizeof(icmp6hdr) + paylen + sizeof(pseudo);
	if (paylen > max_packet_size || len > max_packet_size)
		return die("ICMP6::sendpack: Packet payload too large.", STDERR, -1);

	char s[max_packet_size] = {0};

	memcpy(s + sizeof(pseudo), &icmp6hdr, sizeof(icmp6hdr));
	memcpy(s + sizeof(pseudo) + sizeof(icmp6hdr), payload, paylen);

	icmp6_hdr *i = reinterpret_cast<icmp6_hdr *>(s + sizeof(pseudo));

	if (i->icmp6_cksum == 0) {
		pseudo.saddr = get_src();
		pseudo.daddr = get_dst();
		pseudo.proto = numbers::ipproto_icmpv6;
		pseudo.len = htonl(sizeof(icmp6_hdr) + paylen);

		// For routing extension header, the csum is calculated with the real
		// destination
	
		if (this->get_proto() == numbers::ipproto6_routing) {
			if (e_hdrs_len >= 24 && e_hdrs.begin() != e_hdrs.end())
				memcpy(&pseudo.daddr, e_hdrs.begin()->c_str() + e_hdrs.begin()->size() - 16, 16);
		}

		for (auto i = e_hdrs.begin(); i != e_hdrs.end(); ++i) {
			if (i->size() >= 24 && (*i)[0] == numbers::ipproto6_routing)
				memcpy(&pseudo.daddr, i->c_str() + i->size() - 16, 16);
		}

		memcpy(s, &pseudo, sizeof(pseudo));
		i->icmp6_cksum = in_cksum(reinterpret_cast<unsigned short *>(s), len, 1);
	}

	int r = IP6::sendpack(s + sizeof(pseudo), len - sizeof(pseudo));
	return r;
}


int ICMP6::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


/*! sniff a ICMPv6 packet */
string &ICMP6::sniffpack(string &s)
{
	int off = 0;
	s = "";
	char buf[max_packet_size];
	int r = this->sniffpack(buf, sizeof(buf), off);
	if (r > off)
		s = string(buf + off, r - off);
	return s;
}


int ICMP6::sniffpack(void *s, size_t len)
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


int ICMP6::sniffpack(void *buf, size_t blen, int &off)
{
	off = 0;
	int r = IP6::sniffpack(buf, blen, off);

	if (r == 0 && Layer2::timeout())
		return 0;
	else if (r < 0)
		return -1;
	else if (r < off + (int)sizeof(icmp6hdr))
		return die("ICMP6::sniffpack: short packet", STDERR, -1);

	memcpy(&icmp6hdr, reinterpret_cast<char *>(buf) + off, sizeof(icmp6hdr));
	off += sizeof(icmp6hdr);
	return r;
}

/*  Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
int ICMP6::init_device(const string &dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);
	if (r < 0)
		return r;
	r = Layer2::setfilter("icmp6");
	return r;
}


}

