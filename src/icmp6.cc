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

#include "usi++/usi++.h"
#include "usi++/icmp6.h"
#include "usi++/TX_IP6.h"

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


ICMP6::ICMP6(const string &dst)
	: IP6(dst, IPPROTO_ICMPV6)
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
	return ntohs(icmp6hdr.icmp6_seq);
}


uint16_t ICMP6::set_seq(uint16_t seq)
{
	icmp6hdr.icmp6_seq = htons(seq);
	return seq;
}


uint16_t ICMP6::get_icmpId()
{
	return ntohs(icmp6hdr.icmp6_id);
}


uint16_t ICMP6::set_icmpId(uint16_t id)
{
	icmp6hdr.icmp6_id = htons(id);
	return id;
}


uint32_t ICMP6::get_data()
{
	return icmp6hdr.icmp6_dataun.icmp6_un_data32[0];
}


uint32_t ICMP6::set_data(uint32_t d)
{
	icmp6hdr.icmp6_dataun.icmp6_un_data32[0] = d;
	return d;
}


int ICMP6::sendpack(const void *payload, size_t paylen)
{
	size_t len = sizeof(icmp6hdr) + paylen;
	char *s = new (nothrow) char[len];
	if (!s)
		return die("ICMP6::sendpack: OOM", STDERR, -1);

	memset(s, 0, len);

	memcpy(s, &icmp6hdr, sizeof(icmp6hdr));
	memcpy(s + sizeof(icmp6hdr), payload, paylen);

	icmp6_hdr *i = (icmp6_hdr*)s;
	if (i->icmp6_cksum == 0) {
		unsigned char *c = new (nothrow) unsigned char[2*sizeof(in6_addr)+3*sizeof(uint32_t)+len], *cptr = c;
		if (!c)
			return die("ICMP6::sendpack: OOM", STDERR, -1);

		in6_addr i6 = get_src();
		memcpy(cptr, &i6, sizeof(i6));
		cptr += sizeof(i6);
		i6 = get_dst();
		memcpy(cptr, &i6, sizeof(i6));
		cptr += sizeof(i6);
		uint32_t razia[2] = {htonl(len), htonl(IPPROTO_ICMPV6)};
		memcpy(cptr, razia, sizeof(razia));
		cptr += sizeof(razia);
		memcpy(cptr, s, len); cptr += len;
		i->icmp6_cksum = in_cksum((unsigned short*)c, cptr - c, 0);
		delete [] c;
	}


	int r = IP6::sendpack(s, len);
	delete [] s;
	return r;
}


int ICMP6::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


int ICMP6::sniffpack(void *buf, size_t blen)
{
	if (blen > max_buffer_len)
		return die("ICMP6::sniffpack: Insane large buffer len", STDERR, -1);

	int r = 0;
	char *tmp = new (nothrow) char[blen + sizeof(icmp6hdr)];
	if (!tmp)
		return die("ICMP6::sniffpack: OOM", STDERR, -1);

	memset(tmp, 0, blen + sizeof(icmp6hdr));
	memset(&icmp6hdr, 0, sizeof(icmp6hdr));

	r = IP6::sniffpack(tmp, blen + sizeof(icmp6hdr));

	if (r == 0 && Layer2::timeout()) {
		delete [] tmp;
		return 0;
	} else if (r < (int)sizeof(icmp6hdr)) {
		delete [] tmp;
		return -1;
	}

	memcpy(&icmp6hdr, tmp, sizeof(icmp6hdr));
	r -= sizeof(icmp6hdr);

	if (buf)
		memcpy(buf, tmp + sizeof(icmp6hdr), r < (int)blen ? r : blen);

	delete [] tmp;
	return r < (int)blen ? r : blen;
}


string &ICMP6::sniffpack(string &s)
{
	s = "";
	char buf[4096];

	int r = this->sniffpack(buf, sizeof(buf));
	if (r > 0)
		s = string(buf, r);
	return s;
}


}

