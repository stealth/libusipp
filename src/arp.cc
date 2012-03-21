/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#include <stdio.h>
#include "config.h"
#include "usi++/usi++.h"
#include "usi++/arp.h"
#include "usi++/Layer2.h"
#include "usi++/datalink.h"

#include <string>
#include <cstring>
#include <stdint.h>


namespace usipp {

using namespace std;

#ifdef HAVE_LIBDNET

ARP::ARP(const string &dev)
	: Layer2(NULL, d_tx = new TX_dnet_eth(dev))
{
	memset(&arphdr, 0, sizeof(arphdr));

	// some sane default variables
	arphdr.ar_op = htons(ARPOP_REQUEST);
	arphdr.ar_hrd = htons(ARPHRD_ETHER);
	arphdr.ar_pro = htons(ETH_P_IP);
	arphdr.ar_hln = 6;
	arphdr.ar_pln = 4;

	d_tx->set_type(ETH_P_ARP);
	d_tx->broadcast();
}


ARP::~ARP()
{
	// dont delete d_tx, its ref-counted and GC'ed by Layer2{}
}


int ARP::set_l2src(const string &src)
{
	return d_tx->set_l2src(src);
}


int ARP::set_l2dst(const string &dst)
{
	return d_tx->set_l2dst(dst);
}


/* Return the ARP-command.
 */
uint16_t ARP::get_op() const
{
	return ntohs(arphdr.ar_op);
}


int ARP::init_device(const string &dev, int p, size_t len)
{
	return Layer2::init_device(dev, p, len);
}


int ARP::setfilter(const string &s)
{
	return Layer2::setfilter(s);
}


int ARP::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


int ARP::sendpack(const void *buf, size_t blen)
{
	char *tbuf = new (nothrow) char[blen + sizeof(arphdr)];
	if (!tbuf)
		return -1;
	memcpy(tbuf, &arphdr, sizeof(arphdr));
	memcpy(tbuf + sizeof(arphdr), buf, blen);

	int r = Layer2::sendpack(tbuf, blen + sizeof(arphdr));

	delete [] tbuf;
	return r;
}


/* Sniff for an ARP-request/reply ...
 */
int ARP::sniffpack(void *s, size_t len)
{
	char *tbuf = new (nothrow) char[sizeof(arphdr) + len];
	if (!tbuf)
		return -1;

	int r = Layer2::sniffpack(tbuf, sizeof(arphdr) + len);

	if (r == 0 && Layer2::timeout()) {
		delete [] tbuf;
		return 0;
	} else if (r < (int)sizeof(arphdr)) {
		delete [] tbuf;
		return -1;
	}

	memcpy(&arphdr, tbuf, sizeof(arphdr));
	r -= sizeof(arphdr);
	memcpy(s, tbuf + sizeof(arphdr), r);

	delete [] tbuf;
	return r;
}

#else
#warning "!!! No libdnet support !!!"
#endif // HAVE_LIBDNET

} // namespace usipp

