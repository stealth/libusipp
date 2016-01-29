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


// construct a dummy TX_string, which has almost no overhead
// and which is destroyed/substituted right after by TX_pcap_eth().
// We cant create a TX_pcap_eth in the Layer2 constructor, since it needs
// the pcap RX object that is only ready after Layer2() returns.
EAPOL::EAPOL()
	: Layer2(NULL, new (nothrow) TX_string)
{
	memset(&eapol_hdr, 0, sizeof(eapol_hdr));
	eapol_hdr.version = 1;

	// substitute dummy TX_string
	// by a TX_pcap_eth, constructed from the default created RX
	// register_tx() will also delete old d_tx
	register_tx(pcap_eth_tx = new (nothrow) TX_pcap_eth(reinterpret_cast<pcap *>(Layer2::raw_tx())));
}


EAPOL::~EAPOL()
{
	// dont delete pcap_eth_tx, its ref-counted via register_tx()
}


int EAPOL::set_l2src(const string &src)
{
	return pcap_eth_tx->set_l2src(src);
}


int EAPOL::set_l2dst(const string &dst)
{
	return pcap_eth_tx->set_l2dst(dst);
}


string &EAPOL::sniffpack(string &s)
{
	int off = 0;
	s = "";
	char buf[max_packet_size];
	int r = this->sniffpack(buf, sizeof(buf), off);
	if (r > off)
		s = string(buf + off, r - off);
	return s;
}


int EAPOL::sniffpack(void *s, size_t len)
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


int EAPOL::sniffpack(void *buf, size_t blen, int &off)
{
	off = 0;
	int r = Layer2::sniffpack(buf, blen, off);
	if (r == 0 && Layer2::timeout())
		return 0;
	else if (r < 0)
		return -1;
	else if (r < off + (int)sizeof(eapol_hdr))
		return die("EAPOL::sniffpack: short packet", STDERR, -1);

	memcpy(&eapol_hdr, reinterpret_cast<char *>(buf) + off, sizeof(eapol_hdr));
	off += sizeof(eapol_hdr);
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
	pcap_eth_tx->set_l2dst("01:80:c2:00:00:03");
	pcap_eth_tx->set_type(numbers::eth_p_eapol);

	if (Layer2::init_device(dev, promisc, snaplen) < 0)
		return -1;
	return Layer2::setfilter("ether[12] == 0x888e");
}


}	// namespace


