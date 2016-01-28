/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2016 by Sebastian Krahmer,
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
#include "usi++/icmp.h"

#include <cstring>
#include <string>
#include <stdint.h>
#include <errno.h>
#include <iostream>
#include <arpa/inet.h>

#ifdef USI_DEBUG
#include <iostream>
#endif

namespace usipp {

using namespace std;


ICMP::ICMP(const string &host, RX *rx, TX *tx)
      : IP(host, numbers::ipproto_icmp, rx, tx)
{
	// clear memory
	memset(&icmphdr, 0, sizeof(icmphdr));

}

ICMP::~ICMP()
{
}


ICMP::ICMP(const ICMP &rhs)
	: IP(rhs)
{
	if (this == &rhs)
		return;
	this->icmphdr = rhs.icmphdr;
}


ICMP &ICMP::operator=(const ICMP &rhs)
{
	if (this == &rhs)
		return *this;

	IP::operator=(rhs);
	this->icmphdr  = rhs.icmphdr;
	return *this;
}


/* Set the type-field in the actuall ICMP-packet.
 */
uint8_t ICMP::set_type(uint8_t t)
{
	return icmphdr.type = t;
}


/*! Get the type-field from the actuall ICMP-packet.
 */
uint8_t ICMP::get_type()
{
	return icmphdr.type;
}


/* Set ICMP-code.
 */
uint8_t ICMP::set_code(uint8_t c)
{
	return icmphdr.code = c;
}


/* Get ICMP-code.
 */
uint8_t ICMP::get_code()
{
	return icmphdr.code;
}


uint32_t ICMP::set_gateway(uint32_t g)
{
	icmphdr.un.gateway = htonl(g);
	return g;
}


uint32_t ICMP::get_gateway()
{
	return ntohl(icmphdr.un.gateway);
}


uint16_t ICMP::set_mtu(uint16_t mtu)
{
	icmphdr.un.frag.mtu = htons(mtu);
	return mtu;
}


uint16_t ICMP::get_mtu()
{
	return ntohs(icmphdr.un.frag.mtu);
}


/* Set id field in the actuall ICMP-packet
 */
uint16_t ICMP::set_icmpId(uint16_t id)
{
	icmphdr.un.echo.id = htons(id);
	return id;
}


/* Get the id field from actuall ICMP-packet.
 */
uint16_t ICMP::get_icmpId()
{
	return ntohs(icmphdr.un.echo.id);
}


/* Set the sequecenumber of the actuall ICMP-packet.
 */
uint16_t ICMP::set_seq(uint16_t s)
{
	icmphdr.un.echo.sequence = htons(s);
	return s;
}


/* Get the sequence-number of actuall ICMP-packet
 */
uint16_t ICMP::get_seq()
{
	return ntohs(icmphdr.un.echo.sequence);
}


/* send an ICMP-packet containing 'payload' which
 *  is 'paylen' bytes long
 */
int ICMP::sendpack(const void *payload, size_t paylen)
{
	size_t len = sizeof(struct icmphdr) + paylen;	// the packetlenght

	struct icmphdr *i;

	// s will be our packet
	char *s = new (nothrow) char[len];
	if (!s)
		return die("ICMP::sendpack: OOM", STDERR, -1);

	memset(s, 0, len);

	// copy ICMP header to packet
	memcpy((char*)s, (struct icmphdr*)&this->icmphdr, sizeof(icmphdr));

	if (payload)
		memcpy(s+sizeof(icmphdr), payload, paylen);

	i = (struct icmphdr*)s;

	// calc checksum over packet
	//i->sum = 0;

	if (i->sum == 0)
		i->sum = in_cksum((unsigned short*)s, len, 0);

	int r = IP::sendpack(s, len);
    	delete [] s;
	return r;
}


/* send a ICMP-packet with string 'payload' as payload.
 */
int ICMP::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.length());
}


/*! sniff a ICMP packet */
string &ICMP::sniffpack(string &s)
{
	int off = 0;
	s = "";
	char buf[max_packet_size];
	int r = this->sniffpack(buf, sizeof(buf), off);
	if (r > off)
		s = string(buf + off, r - off);
	return s;
}


/* handle packet
 */
int ICMP::sniffpack(void *s, size_t len)
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


/* handle packet
 */
int ICMP::sniffpack(void *s, size_t len, int &off)
{
	off = 0;
	int r = IP::sniffpack(s, len, off);

	if (r == 0 && Layer2::timeout())
		return 0;
	else if (r < off + (int)sizeof(icmphdr))
		return die("ICMP::sniffpack: received short packet.", STDERR, -1);

	// save ICMP header
	memcpy(&icmphdr, reinterpret_cast<char *>(s) + off, sizeof(struct icmphdr));
	off += sizeof(icmphdr);

	return r;
}


/*  Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
int ICMP::init_device(const string &dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);
	if (r < 0)
		return r;
	r = Layer2::setfilter("icmp");
	return r;
}


} // namespace usipp

