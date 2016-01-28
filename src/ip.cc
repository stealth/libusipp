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

#ifdef USI_DEBUG
#include <iostream>
#endif

namespace usipp {

using namespace std;


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
	memset(ipOptions, 0, sizeof(ipOptions));
	memset(&d_pseudo, 0, sizeof(d_pseudo));

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
	memset(ipOptions, 0, sizeof(ipOptions));
	memset(&d_pseudo, 0, sizeof(d_pseudo));


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
	memcpy(ipOptions, rhs.ipOptions, sizeof(ipOptions));
	calc_csum = rhs.calc_csum;

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
	memcpy(ipOptions, rhs.ipOptions, sizeof(ipOptions));
	calc_csum = rhs.calc_csum;
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
	if (iph.ihl<<2 <= (int)sizeof(iph)) {
		op = "";
		return op;
	}
	op = string(ipOptions, (iph.ihl<<2) - sizeof(iph));
	return op;
}


int IP::set_options(const string &op)
{
	// too large or not aligned?
	if (op.length() > sizeof(ipOptions) || op.length() % 4)
		return -1;
	memcpy(ipOptions, op.c_str(), op.length());

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


/*! Set the sourceaddress, use hostname or IP.
 */
int IP::set_src(const string &host)
{
	struct hostent *he;

	if ((he = gethostbyname(host.c_str())) == NULL)
		return die("IP::set_src::gethostbyname:", RETURN, h_errno);
	memcpy(&iph.saddr, he->h_addr, he->h_length);
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
int IP::set_dst(const string &host)
{
   	struct hostent *he;

	if ((he = gethostbyname(host.c_str())) == NULL)
		return die("IP::set_dst::gethostbyname:", RETURN, h_errno);
	memcpy(&iph.daddr, he->h_addr, he->h_length);
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
	// get mem for packet
	char *s = new char[paylen + (iph.ihl<<2) + 1];
	int r = 0;

	memset(s, 0, paylen + (iph.ihl<<2) + 1);

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
	if (iph.ihl<<2 > (int)sizeof(iph))
		memcpy(s + sizeof(iph), ipOptions, (iph.ihl<<2)  - sizeof(iph));


	if (calc_csum) {
		iphdr *iph_ptr = (iphdr *)s;
		iph_ptr->check = 0;
		iph_ptr->check = in_cksum((unsigned short *)s, iph.ihl<<2, 0);
	}

	memcpy(s + (iph.ihl<<2), payload, paylen);

	sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = iph.daddr;

	r = Layer2::sendpack(s, paylen + (iph.ihl<<2), (struct sockaddr *)&saddr);


	// restore original totlen etc
	iph = orig_iph;

	delete [] s;
	return r;
}


int IP::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.length());
}


/*! sniff a IP packet */
string &IP::sniffpack(string &s)
{
	s = "";
	char buf[max_packet_size];
	int r = this->sniffpack(buf, sizeof(buf));
	if (r > 0)
		s = string(buf, r);
	return s;
}


/*! handle packets, that are NOT actually for the
 *  local address
 */
int IP::sniffpack(void *buf, size_t len)
{
	if (len > max_buffer_len)
		return die("IP::sniffpack: insane large buffer len", STDERR, -1);

	int r = 0;
	int xlen = len + sizeof(iph) + sizeof(ipOptions);
	struct usipp::iphdr *i = NULL;

	char *tmp = new (nothrow) char[xlen];
	if (!tmp)
		return die("IP::snifpack: OOM", STDERR, -1);

	memset(tmp, 0, xlen);

	/* until we assembled fragments or we received and unfragemented packet
	 */
	while (i == NULL) {
		memset(tmp, 0, xlen);
		if ((r = Layer2::sniffpack(tmp, xlen)) == 0 &&
		    Layer2::timeout()) {
			delete [] tmp;
			return 0;	// timeout
		} else if (r < 0) {
			delete [] tmp;
			return -1;
		}
#ifdef USI_REASSEMBLE
		i = (struct usipp::iphdr*)reassemble(tmp, len, &r);
#else
		i = (struct usipp::iphdr*)tmp;
#endif
	}

#ifdef USI_DEBUG
	cerr<<"IP::r="<<r<<endl;
	cerr<<"IP::ihlen="<<(i->ihl<<2)<<endl;
#endif

	unsigned int iplen = i->ihl<<2;
	// Copy header without options
	memcpy(&iph, (char *)i, sizeof(iph));
	r -= sizeof(iph);

	if (r < 0) {
		delete [] tmp;
		return -1;
	} else if (r == 0) {
		delete [] tmp;
		return 0;
	}

	// Copy ip-options if any
	if (r >= (int)iplen && iplen > (int)sizeof(iph)) {
		memcpy(ipOptions, (char *)i + sizeof(iph), iplen - sizeof(iph));
		r -= (iplen - sizeof(iph));
	}

	if (r < 0) {
		delete [] tmp;
		return -1;
	} else if (r == 0) {
		delete [] tmp;
		return 0;
	}

	if (buf)
		memcpy(buf, (char*)i + iplen, r < (int)len ? r : len);

	delete [] tmp;
	return r < (int)len ? r : len;
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


/*! re-assembles IP-fragments
 */
char *IP::reassemble(char *packet, int len, int *resultLen)
{
	static vector<fragments*> pending;
	fragments *f = NULL;
	int ihl = 0, xlen = 0, offset = 0;
	unsigned int i = 0;

	struct usipp::iphdr *ip = (struct usipp::iphdr*)(packet);
	ihl = ip->ihl<<2;

	/* can't be > 60 */
	if (ihl > 60)
		ihl = 60;

	/* if fragment-offset and DF-bit not set */
	if (ntohs(ip->frag_off) != 0 &&
	   (ntohs(ip->frag_off) & numbers::ip_df) != numbers::ip_df) {

		/* for all pending fragments */
		for (i = 0; i < pending.size(); i++) {
			if (pending[i] == NULL)
				continue;

			/* if we already have something that belongs to
			 * _this_ fragment
			 */
			if (ntohs(ip->id) == pending[i]->id) {
				f = pending[i];
				break;
			}
		}

		/* otherwise its the first one */
		if (f == NULL) {
			f = new fragments;
			f->id = ntohs(ip->id);
			f->data = new char[len + ihl];
			f->len = 0;			// # of bytes that are captured yet
			f->origLen = 0xffff;		// # of bytes IP-packet once contained
			f->userLen = 0;			// # of bytes saved
			memset(f->data, 0, len + ihl);
			memcpy(f->data, packet, ihl);
			pending.push_back(f);
		}

		offset = 8*(ntohs(ip->frag_off) & numbers::ip_offmask);

		if (offset + ntohs(ip->tot_len) - ihl <= len)
			xlen = ntohs(ip->tot_len) - ihl;
		else
			xlen = len - offset;

		/* Copy IP-data to the right offset.
		 * It may happen, that offset points out of our data-area.
		 * In this case is xlen < 0 and we ignore it.
		 */
		if (xlen > 0) {
			memcpy(f->data + offset + ihl,
			       packet + ihl,
			       xlen
			      );
			/* This is for the caller; how much was
			 * fetched AND COPIED for her.
			 */
			f->userLen += xlen;
		}
		/* We even count the not copied data! */
		f->len += ntohs(ip->tot_len) - ihl;


		/* OK, we received the last fragment with this id, so calculate
		 * how the original size of this packet was
		 */
		if ((ntohs(ip->frag_off) != 0 &&
		    (ntohs(ip->frag_off) & numbers::ip_mf) == 0)) {
			f->origLen = ntohs(ip->tot_len) + offset - ihl;
		}

		/* In case we reached the original len -> all fragments
		 * are received and assembled.
		 * NOTE that f->len counts the # of bytes _received_, not saved!
		 * The # of saved bytes is in f->userLen.
		 */
		if (f->len == f->origLen) {
			/* should not be necessary, but */
			if (i < pending.size())
				pending[i] = NULL;
			struct usipp::iphdr *ih = (struct usipp::iphdr*)(f->data);
			ih->frag_off = 0;

			ih->tot_len = htons(ihl + f->len);
			*resultLen = ihl + f->userLen;

			/* packet must at least be 'len+ihl' bytes big,
			 * where 'ihl' is max. 60.
			 */
			memset(packet, 0, len+ihl);
			memcpy(packet, f->data, len+ihl);

			delete [] f->data;
			delete f;
			return packet;
		} else  {
			*resultLen = 0;
			return NULL;
		}

	/* else, packet is not fragmented  */
	} else {
		*resultLen = ntohs(ip->tot_len);
		/* return IP-packet, hw-frame skipped */
		return packet;
	}
}


} // namespace usipp

