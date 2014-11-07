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
 * along with libusi++.  If not, see <http://www.gnu.org/licenses/>.
 */

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

#if defined(HAVE_LIBDNET) || defined(HAVE_LIBDUMBNET)

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
		return die("ARP::sendpack: OOM", STDERR, -1);

	memcpy(tbuf, &arphdr, sizeof(arphdr));
	memcpy(tbuf + sizeof(arphdr), buf, blen);

	int r = Layer2::sendpack(tbuf, blen + sizeof(arphdr));

	delete [] tbuf;
	return r;
}


string &ARP::sniffpack(string &s)
{
	s = "";
	char buf[4096];

	int r = 0;
	if ((r = sniffpack(buf, sizeof(buf))) < 0)
		return s;
	s = string(buf, r);
	return s;
}


/* Sniff for an ARP-request/reply ...
 */
int ARP::sniffpack(void *s, size_t len)
{
	char *tbuf = new (nothrow) char[sizeof(arphdr) + len];
	if (!tbuf)
		return die("ARP::sniffpack: OOM", RETURN, -1);

	int r = Layer2::sniffpack(tbuf, sizeof(arphdr) + len);

	if (r == 0 && Layer2::timeout()) {
		delete [] tbuf;
		return 0;
	} else if (r >= 0 && r < (int)sizeof(arphdr)) {
		delete [] tbuf;
		return die("ARP::sniffpack:: packet too short", RETURN, -1);
	} else if (r < 0) {
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

