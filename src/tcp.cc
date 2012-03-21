/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights. If not,
 *** you can get it at http://www.cs.uni-potsdam.de/homepages/students/linuxer
 *** the logit-package. You will also find some other nice utillities there.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#include "usi++/usi++.h"
#include "usi++/tcp.h"

#include <cstring>
#include <string>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>


namespace usipp {


using namespace std;


/*! create a TCP object destined to 'host' */
template<typename T>
TCP<T>::TCP(const string &host)
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
     : T(host, IPPROTO_TCP)
{
	srand(time(NULL));
	memset(&tcph, 0, sizeof(tcph));
	memset(tcpOptions, 0, sizeof(tcpOptions));

	tcph.th_off = 5;
	tcph.th_seq = rand();
}

/*! get the sourceport in human-readable form
 */
template<typename T>
uint16_t TCP<T>::get_srcport()
{
	return ntohs(tcph.th_sport);
}


template<typename T>
TCP<T>::~TCP()
{
}


template<typename T>
TCP<T>::TCP(const TCP &rhs)
	: T(rhs)
{
	if (this == &rhs)
		return;
	tcph = rhs.tcph;
	memcpy(tcpOptions, rhs.tcpOptions, sizeof(tcpOptions));
}


template<typename T>
TCP<T> &TCP<T>::operator=(const TCP<T> &rhs)
{
	if (this == &rhs)
		return *this;
	T::operator=(rhs);
	tcph = rhs.tcph;
	memcpy(tcpOptions, rhs.tcpOptions, sizeof(tcpOptions));
	return *this;
}



/*! get the destinationport in human-readable form
 */
template<typename T>
uint16_t TCP<T>::get_dstport()
{
	return ntohs(tcph.th_dport);
}

/*! get TCP sequence number
 */
template<typename T>
uint32_t TCP<T>::get_seq()
{
	return ntohl(tcph.th_seq);
}

/*! get the actual achnkowledge number from the TCP-header
 */
template<typename T>
uint32_t TCP<T>::get_ack()
{
	return ntohl(tcph.th_ack);
}

/*! get TCP data offset.
 */
template<typename T>
uint8_t TCP<T>::get_off()
{
	return tcph.th_off;
}

/*! set TCP-flags
 */
template<typename T>
uint8_t TCP<T>::get_flags()
{
	return tcph.th_flags;
}


template<typename T>
uint16_t TCP<T>::get_win()
{
	return ntohs(tcph.th_win);
}


/*! get TCP checksum
 */
template<typename T>
uint16_t TCP<T>::get_tcpsum()
{
	return tcph.th_sum;
}


template<typename T>
uint16_t TCP<T>::get_urg()
{
	return ntohs(tcph.th_urp);
}


/*! set TCP sourceport
 */
template<typename T>
uint16_t TCP<T>::set_srcport(uint16_t sp)
{
	tcph.th_sport = htons(sp);
	return sp;
}


/* Set TCP destination port.
 */
template<typename T>
uint16_t TCP<T>::set_dstport(uint16_t dp)
{
	tcph.th_dport = htons(dp);
	return dp;
}


/* Set the sequencenumber-filed in the TCP-header.
 */
template<typename T>
uint32_t TCP<T>::set_seq(uint32_t s)
{
	tcph.th_seq = htonl(s);
	return s;
}


/*! Set the acknowledgenumber-field in the TCP-header.
 *  This is only monitored by the target-kernel, if TH_ACK
 *  is set in the TCP-flags.
 */
template<typename T>
uint32_t TCP<T>::set_ack(uint32_t a)
{
	tcph.th_ack = htonl(a);
	return a;
}


/*! set TCP data offset.
 */
template<typename T>
uint8_t TCP<T>::set_off(uint8_t o)
{
	return tcph.th_off = o;
}


/*! set TCP-flags
 */
template<typename T>
uint8_t TCP<T>::set_flags(uint8_t f)
{
	return tcph.th_flags = f;
}


/*! set TCP window */
template<typename T>
uint16_t TCP<T>::set_win(uint16_t w)
{
	tcph.th_win = htons(w);
	return w;
}


/*! set TCP-checksum
 *  Calling this function with s != 0
 *  will prevent sendpack from calculating the checksum.
 */
template<typename T>
uint16_t TCP<T>::set_tcpsum(uint16_t s)
{
	tcph.th_sum = s;
	return s;
}


/*! set TCP urgent pointer for OOB data */
template<typename T>
uint16_t TCP<T>::set_urg(uint16_t u)
{
	tcph.th_urp = htons(u);
	return u;
}


/*! get raw TCP header */
template<typename T>
tcphdr &TCP<T>::get_tcphdr()
{
	return tcph;
}


/*!  send a TCP-packet containing 'buf' data of 'paylen' bytes
 */
template<typename T>
int TCP<T>::sendpack(const void *buf, size_t paylen)
{
	unsigned int len = paylen + (tcph.th_off<<2) + sizeof(T::d_pseudo);
	int r = 0;
	char *tmp = new char[len + 1 + 20];	// +1 for padding if necessary
	memset(tmp, 0, len + 1);

   	// build a pseudoheader for IP-checksum
	T::d_pseudo.saddr = T::get_src();	// sourceaddress
	T::d_pseudo.daddr = T::get_dst();	// destinationaddress

	uint32_t zero = 0;
	memcpy(&this->d_pseudo.zero, &zero, sizeof(this->d_pseudo.zero));
	T::d_pseudo.proto = IPPROTO_TCP;

	if (sizeof(T::d_pseudo.len) == sizeof(uint16_t))
		T::d_pseudo.len = htons((tcph.th_off<<2) + paylen);
	else
		T::d_pseudo.len = htonl((tcph.th_off<<2) + paylen);

	// copy pseudohdr+header+data to buffer
	memcpy(tmp, &this->d_pseudo, sizeof(T::d_pseudo));
	memcpy(tmp + sizeof(T::d_pseudo), &tcph, sizeof(tcph));

	// options, might be 0-length
	if ((tcph.th_off<<2) > (int)sizeof(tcph))
		memcpy(tmp + sizeof(T::d_pseudo) + sizeof(tcph), tcpOptions, (tcph.th_off<<2)-sizeof(tcph));

	// data
	memcpy(tmp + sizeof(T::d_pseudo) + (tcph.th_off<<2), buf, paylen);

	// calc checksum over i
	struct tcphdr *t = (struct tcphdr*)(tmp + sizeof(T::d_pseudo));

	if (tcph.th_sum == 0)
		t->th_sum = in_cksum((unsigned short*)tmp, len, 1);

	r = T::sendpack(tmp + sizeof(T::d_pseudo), len - sizeof(T::d_pseudo));

	delete [] tmp;
	return r;
}


/*! send a TCP packet containing string 's' */
template<typename T>
int TCP<T>::sendpack(const string &s)
{
	return sendpack(s.c_str(), s.length());
}


/*! sniff a TCP-packet.
 */
template<typename T>
int TCP<T>::sniffpack(void *buf, size_t len)
{
	size_t xlen = len + sizeof(tcph) + sizeof(tcpOptions);

	char *tmp = new char[xlen];
	int r = 0;

	memset(tmp, 0, xlen);
	memset(buf, 0, len);
	memset(&tcph, 0, sizeof(tcph));

	r = T::sniffpack(tmp, xlen);

	if (r == 0 && Layer2::timeout()) {	// timeout
		delete[] tmp;
		return 0;
	} else if (r < (int)sizeof(tcph)) {
		delete [] tmp;
		return -1;
	}

	// Copy TCP-header without options
	memcpy(&tcph, tmp, sizeof(tcph));
	r -= sizeof(tcph);

	unsigned int tcplen = tcph.th_off<<2;

	if (r < (int)(tcplen - sizeof(tcph))) {
		delete [] tmp;
		return -1;
	}

	// copy options itself
	if (tcplen > sizeof(tcph)) {
		memcpy(tcpOptions, tmp + sizeof(tcph), tcplen - sizeof(tcph));
		r -= (tcplen - sizeof(tcph));
	}

	if (buf)
		memcpy(buf, tmp + tcplen, r < (int)len ? r : len);

	delete [] tmp;
       	return r < (int)len ? r : len;
}


/*! Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'snaplen' bytes per call.
 */
template<typename T>
int TCP<T>::init_device(const string &dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);
	if (r < 0)
		return r;
	r = Layer2::setfilter("tcp");
	return r;
}


template<typename T>
string &TCP<T>::get_options(string &op)
{
	if (tcph.th_off<<2 <= (int)sizeof(tcph)) {
		op = "";
		return op;
	}
	op = string(tcpOptions, (tcph.th_off<<2) - sizeof(tcpOptions));
	return op;
}


template<typename T>
int TCP<T>::set_options(const string &op)
{
	// too large or not aligned?
	if (op.length() > sizeof(tcpOptions) || op.length() % 4)
		return -1;
	memcpy(tcpOptions, op.c_str(), op.length());

	tcph.th_off = (sizeof(tcph) + op.length())>>2;
	return 0;
}


template class TCP<IP>;
template class TCP<IP6>;

} // namespace usipp

