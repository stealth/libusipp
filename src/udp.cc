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
#include "usi++/udp.h"
#include "usi++/RX.h"
#include "usi++/TX.h"

#include <cstring>
#include <string>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>


namespace usipp {

using namespace std;


template<typename T>
UDP<T>::UDP(const string &host, RX *rx, TX *tx)
      : T(host, numbers::ipproto_udp, rx, tx)
{
	memset(&d_udph, 0, sizeof(d_udph));
}


template <typename T>
UDP<T>::~UDP()
{
}


template <typename T>
UDP<T>::UDP(const UDP<T> &rhs)
	: T(rhs)
{
	if (this == &rhs)
		return;
	d_udph = rhs.d_udph;
}

template <typename T>
UDP<T> &UDP<T>::operator=(const UDP<T> &rhs)
{
	if (this == &rhs)
		return *this;
	T::operator=(rhs);
	d_udph = rhs.d_udph;
	return *this;
}


/*! Get the sourceport of UDP-datagram.
 */
template <typename T>
uint16_t UDP<T>::get_srcport()
{
	return ntohs(d_udph.source);
}


/*! Get the destinationport of the UDP-datagram
 */
template <typename T>
uint16_t UDP<T>::get_dstport()
{
	return ntohs(d_udph.dest);
}


/*! Return length of template UDP-header plus contained data.
 */
template <typename T>
uint16_t UDP<T>::get_len()
{
	return ntohs(d_udph.len);
}


/* Return the checksum of UDP-datagram.
 */
template <typename T>
uint16_t UDP<T>::get_udpsum()
{
	return d_udph.check;
}


/*! Set the sourceport in the UDP-header.
 */
template <typename T>
uint16_t UDP<T>::set_srcport(uint16_t sp)
{
	d_udph.source = htons(sp);
	return sp;
}


/*! Set the destinationport in the UDP-header.
 */
template <typename T>
uint16_t UDP<T>::set_dstport(uint16_t dp)
{
	d_udph.dest = htons(dp);
	return dp;
}


/*! Set the length of the UDP-datagramm.
 */
template <typename T>
uint16_t UDP<T>::set_len(uint16_t l)
{
	d_udph.len = htons(l);
	return l;
}


/* Set the UDP-checksum. Calling this function with s != 0
 *  will prevent sendpack() from setting the checksum!!!
 */
template <typename T>
uint16_t UDP<T>::set_udpsum(uint16_t s)
{
	d_udph.check = s;
	return s;
}


/*! Get the raw UDP header. */
template <typename T>
udphdr &UDP<T>::get_udphdr()
{
	return d_udph;
}


/*! Send an UDP-datagramm, containing 'paylen' bytes of data.
 */
template <typename T>
int UDP<T>::sendpack(const void *buf, size_t paylen)
{
	size_t len = paylen + sizeof(d_udph) + sizeof(T::d_pseudo);
	int r = 0;
	char *tmp = new char[len+1];	// for padding, if needed
	memset(tmp, 0, len + 1);

	udphdr orig_udph = d_udph;

   	// build a pseudoheader for IPvX-checksum
	T::d_pseudo.saddr = T::get_src();	// sourceaddress
	T::d_pseudo.daddr = T::get_dst();	// destinationaddress

	uint32_t zero = 0;
	memcpy(&this->d_pseudo.zero, &zero, sizeof(this->d_pseudo.zero));
	T::d_pseudo.proto = numbers::ipproto_udp;

	if (d_udph.len == 0)
		d_udph.len = htons(paylen + sizeof(d_udph));

	if (sizeof(T::d_pseudo.len) == sizeof(uint16_t))
		T::d_pseudo.len = d_udph.len;
	else
		T::d_pseudo.len = htonl(ntohs(d_udph.len));



	// copy pseudohdr+header+data to buffer
	memcpy(tmp, &this->d_pseudo, sizeof(T::d_pseudo));
	memcpy(tmp + sizeof(T::d_pseudo), &d_udph, sizeof(d_udph));
	memcpy(tmp + sizeof(T::d_pseudo) + sizeof(d_udph), buf, paylen);

	// calc checksum over it
	struct udphdr *u = (struct udphdr*)(tmp + sizeof(T::d_pseudo));

	if (d_udph.check == 0)
		u->check = in_cksum((unsigned short*)tmp, len, 1);

	r = T::sendpack(tmp + sizeof(T::d_pseudo), len - sizeof(T::d_pseudo));

	d_udph = orig_udph;

	delete [] tmp;
	return r;
}


template <typename T>
int UDP<T>::sendpack(const string &s)
{
	return sendpack(s.c_str(), s.length());
}


/*! sniff a UDP packet */
template <typename T>
string &UDP<T>::sniffpack(string &s)
{
	int off = 0;
	s = "";
	char buf[max_packet_size];
	int r = this->sniffpack(buf, sizeof(buf), off);
	if (r > off)
		s = string(buf + off, r - off);
	return s;
}


/* Capture packets that are not for our host.
 */
template <typename T>
int UDP<T>::sniffpack(void *s, size_t len)
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


/* Capture packets that are not for our host.
 */
template <typename T>
int UDP<T>::sniffpack(void *buf, size_t len, int &off)
{
	off = 0;
	int r = T::sniffpack(buf, len, off);

	if (r == 0 && Layer2::timeout())
		return 0;
	else if (r < 0)
		return -1;
	else if (r < off + (int)sizeof(d_udph))
		return T::die("UDP::sniffpack: short packet", STDERR, -1);

	memcpy(&d_udph, reinterpret_cast<char *>(buf) + off, sizeof(d_udph));
	off += sizeof(d_udph);

	return r;
}


/* Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
template <typename T>
int UDP<T>::init_device(const string &dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);

	if (r < 0)
		return r;
	r = Layer2::setfilter("udp");
	return r;
}


/*! \class UDP4 */
template class UDP<IP>;

/*! \class UDP6 */
template class UDP<IP6>;


} // namespace usipp


