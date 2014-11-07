/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2014 by Sebastian Krahmer,
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

#include <stdio.h>
#include "config.h"
#include "usi++/usi++.h"
#include "usi++/eapol.h"
#include "usi++/Layer2.h"
#include "usi++/datalink.h"

#include <string>
#include <cstring>
#include <stdint.h>


namespace usipp {

using namespace std;


// construct a dummy TX_IP, which has almost no overhead
// and which is destroyed/substituted right after by TX_pcap_eth().
// We cant create a TX_pcap_eth in the Layer2 constructor, since it needs
// the pcap RX object that is only ready after Layer2() returns.
EAPOL::EAPOL(const string &dev)
	: Layer2(NULL, new TX_IP)
{
	memset(&eapol_hdr, 0, sizeof(eapol_hdr));
	eapol_hdr.version = 1;

	// substitute dummy TX_IP
	// by a TX_pcap_eth, constructed from the default created RX
	Layer2::register_tx(d_tx = new TX_pcap_eth(reinterpret_cast<pcap *>(Layer2::raw_rx())));

	d_tx->set_l2dst("01:80:c2:00:00:03");
	d_tx->set_type(ETH_P_EAPOL);
}


EAPOL::~EAPOL()
{
}


int EAPOL::set_l2src(const string &src)
{
	return d_tx->set_l2src(src);
}


int EAPOL::set_l2dst(const string &dst)
{
	return d_tx->set_l2dst(dst);
}


string &EAPOL::sniffpack(string &s)
{
	s = "";
	char buf[4096];

	int r = 0;
	if ((r = sniffpack(buf, sizeof(buf))) < 0)
		return s;
	s = string(buf, r);
	return s;
}


int EAPOL::sniffpack(void *buf, size_t blen)
{
	char *tbuf = new (nothrow) char[sizeof(eapol_hdr) + blen];
	if (!tbuf)
		return die("EAPOL::sniffpack: OOM", RETURN, -1);

	int r = Layer2::sniffpack(tbuf, sizeof(eapol_hdr) + blen);
	if (r == 0 && Layer2::timeout()) {
		delete [] tbuf;
		return 0;
	} else if (r >= 0 && r <= (int)sizeof(eapol_hdr)) {
		delete [] tbuf;
		return die("EAPOL::sniffpack: packet too short", RETURN, -1);
	} else if (r < 0) {
		delete [] tbuf;
		return -1;
	}

	memcpy(&eapol_hdr, tbuf, sizeof(eapol_hdr));
	r -= sizeof(eapol_hdr);
	memcpy(buf, tbuf + sizeof(eapol_hdr), r);

	delete [] tbuf;
	return r;
}


int EAPOL::sendpack(const string &s)
{
	return sendpack(s.c_str(), s.size());
}


int EAPOL::sendpack(const void *buf, size_t blen)
{
	char *tbuf = new (nothrow) char[blen + sizeof(arphdr)];
	if (!tbuf)
		return die("EAPOL::sendpack: OOM", STDERR, -1);

	eapol_hdr.len = htons((uint16_t)(blen & 0xffff));
	memcpy(tbuf, &eapol_hdr, sizeof(eapol_hdr));
	memcpy(tbuf + sizeof(eapol_hdr), buf, blen);
	int r = Layer2::sendpack(tbuf, blen + sizeof(arphdr));
	delete [] tbuf;
	return r;
}


int EAPOL::init_device(const string &dev, int promisc, size_t snaplen)
{
	if (Layer2::init_device(dev, promisc, snaplen) < 0)
		return -1;
	return Layer2::setfilter("ether[12] == 0x888e");
}


}	// namespace


