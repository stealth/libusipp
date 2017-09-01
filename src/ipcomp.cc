/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2017 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
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
#include "usi++/ipcomp.h"
#include "usi++/RX.h"
#include "usi++/TX.h"


namespace usipp {

using namespace std;


template<typename T>
IPComp<T>::IPComp(const string &host, RX *rx, TX *tx)
	: T(host, numbers::ipproto_comp, rx, tx)
{
	memset(&ipchdr, 0, sizeof(ipchdr));
}


template<typename T>
IPComp<T>::~IPComp()
{
}


template<typename T>
IPComp<T>::IPComp(const IPComp<T> &rhs)
	: T(rhs)
{
	if (this == &rhs)
		return;
	ipchdr = rhs.ipchdr;
}


template<typename T>
IPComp<T> &IPComp<T>::operator=(const IPComp<T> &rhs)
{
	if (this == &rhs)
		return *this;
	T::operator=(rhs);

	ipchdr = rhs.ipchdr;

	return *this;	
}


template<typename T>
int IPComp<T>::sendpack(const void *buf, size_t paylen)
{
	if (paylen > max_packet_size || paylen + sizeof(ipchdr) + 1 > max_packet_size)
		return T::die("IPComp::sendpack: Packet payload too large.", STDERR, -1);

	unsigned int len = paylen + sizeof(ipchdr);
	int r = 0;
	char tmp[max_packet_size];
	memset(tmp, 0, sizeof(tmp));

	memcpy(tmp, &ipchdr, sizeof(ipchdr));

	// data
	memcpy(tmp + sizeof(ipchdr), buf, paylen);

	r = T::sendpack(tmp, len);

	return r;
}


/*! send a IPComp  packet containing string 's' */
template<typename T>
int IPComp<T>::sendpack(const string &s)
{
	return sendpack(s.c_str(), s.length());
}


/*! sniff a IPComp packet */
template<typename T>
string &IPComp<T>::sniffpack(string &s)
{
	int off = 0;
	s = "";
	char buf[max_packet_size];
	int r = this->sniffpack(buf, sizeof(buf), off);
	if (r > off)
		s = string(buf + off, r - off);
	return s;
}


/*! sniff a IPComp-packet.  */
template<typename T>
int IPComp<T>::sniffpack(void *s, size_t len)
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


/*! sniff a IPComp-packet.  */
template<typename T>
int IPComp<T>::sniffpack(void *buf, size_t len, int &off)
{
	off = 0;
	int r = T::sniffpack(buf, len, off);

	if (r == 0 && Layer2::timeout())
		return 0;
	else if (r < 0)
		return -1;
	else if (r < off + (int)sizeof(ipchdr))
		return T::die("IPComp::sniffpack: short packet", STDERR, -1);

	memcpy(&ipchdr, reinterpret_cast<char *>(buf) + off, sizeof(ipchdr));

	off += sizeof(ipchdr);
       	return r;
}


/*! Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
template<typename T>
int IPComp<T>::init_device(const string &dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);
	if (r < 0)
		return r;
	r = Layer2::setfilter("ip proto 108");
	return r;
}


template class IPComp<IP>;
template class IPComp<IP6>;

}	// namespace

