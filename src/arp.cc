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

#include <stdio.h>
#include "config.h"
#include "usi++/usi++.h"
#include "usi++/arp.h"
#include "usi++/Layer2.h"
#include "usi++/datalink.h"
#include "usi++/TX_pcap_eth.h"
#include "usi++/TX_string.h"

#include <string>
#include <cstring>
#include <stdint.h>


namespace usipp {

using namespace std;


ARP::ARP()
	: Layer2(NULL, new (nothrow) TX_string)
{
	memset(&arphdr, 0, sizeof(arphdr));

	// some sane default variables
	arphdr.ar_op = htons(numbers::arpop_request);
	arphdr.ar_hrd = htons(numbers::arphrd_ether);
	arphdr.ar_pro = htons(numbers::eth_p_ip);
	arphdr.ar_hln = 6;
	arphdr.ar_pln = 4;

	// substitute dummy TX_string
	// by a TX_pcap_eth, constructed from the default created RX
	// register_tx() will also delete old d_tx
	register_tx(pcap_eth_tx = new (nothrow) TX_pcap_eth(reinterpret_cast<pcap *>(Layer2::raw_rx())));
}


ARP::~ARP()
{
	// dont delete pcap_eth_tx, its refcounted via register_tx()
}


// Layer2 protocols like ARP have convenience functions for setting l2 addresses.
int ARP::set_l2src(const string &src)
{
	return pcap_eth_tx->set_l2src(src);
}


int ARP::set_l2dst(const string &dst)
{
	return pcap_eth_tx->set_l2dst(dst);
}


/* Return the ARP-command.
 */
uint16_t ARP::get_op() const
{
	return ntohs(arphdr.ar_op);
}


int ARP::init_device(const string &dev, int promisc, size_t snaplen)
{
	int r = Layer2::init_device(dev, promisc, snaplen);
	if (r < 0)
		return -1;
	if ((r = Layer2::setfilter("arp")) < 0)
		return -1;

	pcap_eth_tx->set_type(numbers::eth_p_arp);
	pcap_eth_tx->broadcast();

	return r;
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
	char buf[max_packet_size];

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
	if (len > max_buffer_len)
		return die("ARP::sniffpack: Insane large buffer len", STDERR, -1);

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


} // namespace usipp

