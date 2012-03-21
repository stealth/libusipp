/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#include "usi++/usi++.h"
#include "usi++/udp.h"

#include <cstring>
#include <string>
#include <errno.h>
#include <stdint.h>

#ifdef USI_DEBUG
#include <iostream>
#endif

#include <arpa/inet.h>


namespace usipp {

using namespace std;


template<typename T>
UDP<T>::UDP(const string &host)
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
      : T(host, IPPROTO_UDP)
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

   	// build a pseudoheader for IPvX-checksum
	T::d_pseudo.saddr = T::get_src();	// sourceaddress
	T::d_pseudo.daddr = T::get_dst();	// destinationaddress

	uint32_t zero = 0;
	memcpy(&this->d_pseudo.zero, &zero, sizeof(this->d_pseudo.zero));
	T::d_pseudo.proto = IPPROTO_UDP;

	if (sizeof(T::d_pseudo.len) == sizeof(uint16_t))
		T::d_pseudo.len = htons(sizeof(d_udph) + paylen);
	else
		T::d_pseudo.len = htonl(sizeof(d_udph) + paylen);


	if (d_udph.len == 0)
		d_udph.len = htons(paylen + sizeof(d_udph));


	// copy pseudohdr+header+data to buffer
	memcpy(tmp, &this->d_pseudo, sizeof(T::d_pseudo));
	memcpy(tmp + sizeof(T::d_pseudo), &d_udph, sizeof(d_udph));
	memcpy(tmp + sizeof(T::d_pseudo) + sizeof(d_udph), buf, paylen);

	// calc checksum over it
	struct udphdr *u = (struct udphdr*)(tmp + sizeof(T::d_pseudo));

	if (d_udph.check == 0)
		u->check = in_cksum((unsigned short*)tmp, len, 1);

	r = T::sendpack(tmp + sizeof(T::d_pseudo), len - sizeof(T::d_pseudo));

	delete [] tmp;
	return r;
}


template <typename T>
int UDP<T>::sendpack(const string &s)
{
	return sendpack(s.c_str(), s.length());
}


/* Capture packets that are not for our host.
 */
template <typename T>
int UDP<T>::sniffpack(void *buf, size_t len)
{
	char *tmp = new char[len + sizeof(d_udph)];
	int r = 0;
	memset(tmp, 0, len + sizeof(d_udph));

	r = T::sniffpack(tmp, len + sizeof(d_udph));
	if (r == 0 && Layer2::timeout()) {	// timeout
		delete [] tmp;
		return 0;
	} else if (r < (int)sizeof(d_udph)) {
		delete [] tmp;
		return -1;
	}

#ifdef USI_DEBUG
	cerr<<"UDP size:"<<r<<endl;
#endif
	memcpy(&d_udph, tmp, sizeof(d_udph));
	r -= sizeof(d_udph);

	if (buf)
		memcpy(buf, tmp + sizeof(d_udph), r < (int)len ? r : len);

	delete [] tmp;
	return r < (int)len ? r : len;
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


