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
#include "usi++/ip.h"

#include "config.h"
#include <stdlib.h>
#include <cstring>
#include <string>
#include <errno.h>
#include <new>
#include <vector>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>


namespace usipp {

using namespace std;


const uint8_t IP::d_ipversion = 4;


/*! Create a IP-packet, with 'dst' for destination-adress.
 *  Set the protocol-field in the IP-header to 'proto'.
 *  This is used by the derived classes (TCP etc.) to set
 *  the correct protocol (IPPROTO_TCP etc.).
 *  The constructor assigns most of the IP header information
 *  with usable data by itself (IP version, TTL etc).
 */
IP::IP(const string &dst, uint8_t proto, RX *rx, TX *tx)
   	: Layer2(rx, tx)
{
	memset(&iph, 0, sizeof(iph));
	d_pseudo.zero = 0;

	iph.ttl = 64;
	iph.version = 4;
	iph.ihl = 5;
	iph.id = 0;
	iph.check = 0;
	iph.protocol = proto;
	iph.tot_len = 0;

	if (raw_tx()->tag() != TX_TAG_IP)
		calc_csum = 1;
	else
		calc_csum = 0;

	set_src(INADDR_ANY);
	set_dst(dst);
}


/*  Same as above, but use networkbyte-ordered int32 for destination-adress.
 *  This is usefull in case you do sth. like ip.set_src(ip2.get_src())
 */
IP::IP(uint32_t dst, uint8_t proto, RX *rx, TX *tx)
   	: Layer2(rx, tx)
{
	memset(&iph, 0, sizeof(iph));
	d_pseudo.zero = 0;


	iph.ttl = 64;
	iph.version = 4;
	iph.ihl = 5;
	iph.id = 0;
	iph.protocol = proto;

	if (raw_tx()->tag() != TX_TAG_IP)
		calc_csum = 1;
	else
		calc_csum = 0;

	set_src(INADDR_ANY);
	set_dst(dst);
}


/*! Assign-operator
 */
IP& IP::operator=(const IP &rhs)
{
	if (this == &rhs)
		return *this;

	Layer2::operator=(rhs);

	// and just copy header and such
	memcpy(&iph, &rhs.iph, sizeof(iph));
	calc_csum = rhs.calc_csum;
	d_pseudo.zero = 0;

	return *this;
}


/*! Copy-constructor
 */
IP::IP(const IP &rhs)
    : Layer2(rhs)
{
	if (this == &rhs)
		return;

	memcpy(&iph, &rhs.iph, sizeof(iph));
	calc_csum = rhs.calc_csum;
	d_pseudo.zero = 0;
}


IP::~IP()
{
}


/*! get IP header-length (number of 32bit words)
 */
uint8_t IP::get_hlen()
{
   	return iph.ihl;
}


/*! set IP-header-length
 */
uint8_t IP::set_hlen(uint8_t l)
{
	return iph.ihl = l;
}


/*! get IP-version field
 */
uint8_t IP::get_vers()
{
	return iph.version;
}


/*! set version field in IP-header
 */
uint8_t IP::set_vers(uint8_t v)
{
	return iph.version = v;
}


/*! get TOS field */
uint8_t IP::get_tos()
{
	return iph.tos;
}


/*! set TOS field */
uint8_t IP::set_tos(uint8_t tos)
{
	return iph.tos = tos;
}


/*! get total length of IP-packet
 */
uint16_t IP::get_totlen()
{
	return ntohs(iph.tot_len);
}


/*! set total length of IP-packet
 *  If you set the total length by yourself, you will prevent the
 *  sendpack() routine to do it. This is normally _not_ needed.
 */
uint16_t IP::set_totlen(uint16_t t)
{
#ifdef BROKEN_BSD
	return iph.tot_len = t;
#else
	iph.tot_len = htons(t);
	return t;
#endif
}


/*! get the IP id field
 */
uint16_t IP::get_id()
{
	return ntohs(iph.id);
}


/*! set the IP id field
 */
uint16_t IP::set_id(uint16_t id)
{
	iph.id = htons(id);
	return id;
}


string &IP::get_options(string &op)
{
	op = "";
	if (e_hdrs_len > 0)
		op = e_hdrs[0];
	return op;
}


int IP::set_options(const string &op)
{
	// too large or not aligned?
	if (op.length() > 40 || op.length() % 4)
		return -1;
	e_hdrs.clear();
	e_hdrs.push_back(op);
	e_hdrs_len = op.length();

	iph.ihl = (sizeof(iph) + op.length())>>2;
	return 0;
}


/*! get the IP-fragmentation offset */
uint16_t IP::get_fragoff()
{
	return ntohs(iph.frag_off);
}


/*! set the IP-fragmentation offset */
uint16_t IP::set_fragoff(uint16_t f)
{
#ifdef BROKEN_BSD
	return iph.frag_off = f;
#else
	iph.frag_off = htons(f);
	return f;
#endif
}


/*! get 'time to live'
 */
uint8_t IP::get_ttl()
{
	return iph.ttl;
}


/*! set 'time to live'
 */
uint8_t IP::set_ttl(uint8_t ttl)
{
	return iph.ttl = ttl;
}


/*! obtain the actuall protocol.
 */
uint8_t IP::get_proto()
{
	return iph.protocol;
}


/*! change the protocol-field of IP header to 'p' in case
 *  you need to.
 */
uint8_t IP::set_proto(uint8_t p)
{
	return iph.protocol = p;
}


/*! get IP-header checksum
 */
uint16_t IP::get_sum()
{
	return iph.check;
}


/*! set IP-header checksum
 *  Should not be used as long as you don't want to
 *  insert bad checksums into the header.
 */
uint16_t IP::set_sum(uint16_t sum)
{
	calc_csum = 0;
	return iph.check = sum;
}


/*! get the destination-address in network byteorder.
 */
uint32_t IP::get_dst()
{
	return iph.daddr;
}


/*! get the dst address in dotted form
 */
string &IP::get_dst(string &s)
{
	s = "";
	struct in_addr in;

	in.s_addr = iph.daddr;
	s = inet_ntoa(in);
	return s;
}



/*! return the source-address of actuall IP-packet
 *  in network-byte order.
 */
uint32_t IP::get_src()
{
	return iph.saddr;
}


/*! get the source address in dotted form
 */
string &IP::get_src(string &s)
{
	s = "";
	struct in_addr in;

	in.s_addr = iph.saddr;
	s = inet_ntoa(in);
	return s;
}


/*! Set the source-address, use network byteorder.
 */
uint32_t IP::set_src(uint32_t s)
{
	return iph.saddr = s;
}


/*! Set the source address.
 */
int IP::set_src(const string &src)
{
	in_addr in;
	if (inet_pton(AF_INET, src.c_str(), &in) != 1)
		return die("IP::set_src::inet_pton:", PERROR, errno);

	memcpy(&iph.saddr, &in.s_addr, sizeof(iph.saddr));
	return 0;
}


/*! set destination address
 */
uint32_t IP::set_dst(uint32_t d)
{
	return iph.daddr = d;
}


/*! set destinationaddress, similar to set_src()
 */
int IP::set_dst(const string &dst)
{
	in_addr in;
	if (inet_pton(AF_INET, dst.c_str(), &in) != 1)
		return die("IP::set_dst::inet_pton:", PERROR, errno);

	memcpy(&iph.daddr, &in.s_addr, sizeof(iph.daddr));
	return 0;
}


/*! get the raw IP header */
iphdr &IP::get_iphdr()
{
	return iph;
}


iphdr &IP::set_iphdr(const iphdr &ih)
{
	memcpy(&iph, &ih, sizeof(iph));
	return iph;
}


void IP::checksum(bool cs)
{
	calc_csum = cs;
}


/*! send a packet, containing 'paylen' bytes of data
 */
int IP::sendpack(const void *payload, size_t paylen)
{
	if (paylen > max_packet_size || paylen + sizeof(iph) + e_hdrs_len > max_packet_size)
		return die("IP::sendpack: Packet payload too large.", STDERR, -1);

	char s[max_packet_size] = {0};
	iphdr orig_iph = iph;

	// We give user the chance to set wrong length's
	// if he really want's to ...
	if (get_totlen() == 0)
		set_totlen(paylen + (iph.ihl<<2));		// how long ?


	// If dnet is used on BSD, also convert the otherwise host byte orderd
	// attributes
#ifdef BROKEN_BSD
	if (raw_tx()->tag() != TX_TAG_IP) {
		iph.tot_len = htons(iph.tot_len);
		iph.frag_off = htons(iph.frag_off);
	}
#endif

	memcpy(s, &iph, iph.ihl<<2 > (int)sizeof(iph) ? sizeof(iph) : iph.ihl<<2);

	// copy options if any
	if (e_hdrs_len > 0)
		memcpy(s + sizeof(iph), e_hdrs[0].c_str(), e_hdrs_len);


	if (calc_csum) {
		iphdr *iph_ptr = reinterpret_cast<iphdr *>(s);
		iph_ptr->check = 0;
		iph_ptr->check = in_cksum(reinterpret_cast<unsigned short *>(s), iph.ihl<<2, 0);
	}

	memcpy(s + (iph.ihl<<2), payload, paylen);

	sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = iph.daddr;

	int r = Layer2::sendpack(s, paylen + (iph.ihl<<2), reinterpret_cast<struct sockaddr *>(&saddr));


	// restore original totlen etc
	iph = orig_iph;

	return r;
}


int IP::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.length());
}


/*! sniff a IP packet */
string &IP::sniffpack(string &s)
{
	int off = 0;
	s = "";
	char buf[max_packet_size];
	int r = this->sniffpack(buf, sizeof(buf), off);
	if (r > off)
		s = string(buf + off, r - off);
	return s;
}


int IP::sniffpack(void *s, size_t len)
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


/*! handle packets, that are NOT actually for the
 *  local address
 */
int IP::sniffpack(void *buf, size_t len, int &off)
{
	int r = 0;
	off = 0;

	r = Layer2::sniffpack(buf, len, off);

	if (r == 0 && Layer2::timeout())
		return 0;	// timeout
	else if (r < 0)
		return -1;	// forward downstream errors
	else if (r < off + (int)sizeof(usipp::iphdr))
		return die("IP::sniffpack: short packet", STDERR, -1);

	struct usipp::iphdr *i = reinterpret_cast<usipp::iphdr *>(reinterpret_cast<char *>(buf) + off);

	// Copy header without options
	memcpy(&iph, reinterpret_cast<char *>(buf) + off, sizeof(usipp::iphdr));
	off += sizeof(iph);

	e_hdrs.clear();
	e_hdrs_len = 0;

	unsigned int iplen = i->ihl<<2;
	if (iplen < sizeof(iph))
		return r;

	// cant happen: only 4bit IHL, -> max of 40byte options == sizeof(ipOptions)
	//if (iplen > sizeof(iph) + sizeof(ipOptions)) 

	// Copy ip-options if any
	if (iplen > (int)sizeof(iph) && off + (int)iplen - (int)sizeof(iph) <= r) {
		e_hdrs_len = iplen - sizeof(iph);
		e_hdrs.push_back(string(reinterpret_cast<char *>(buf) + off, e_hdrs_len));
		off += e_hdrs_len;
		return r;
	}

	// must be short packet
	if (iplen != sizeof(iph))
		return die("IP::sniffpack: short packet", STDERR, -1);

	return r;
}


/*! Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
int IP::init_device(const string &dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);

	if (r < 0)
		return r;
	r = Layer2::setfilter("ip");
	return r;
}


} // namespace usipp

