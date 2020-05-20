/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2020 by Sebastian Krahmer,
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

#include "usi++/TX_pcap_eth.h"
#include "usi++/object.h"
#include "usi++/datalink.h"
#include "usi++/misc.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <string>
#include <cstdint>
#include <cstring>
#include <cerrno>


namespace usipp {


using namespace std;


TX_pcap_eth::TX_pcap_eth(usipp::pcap *p)
{
	memset(&ehdr, 0, sizeof(ehdr));
	d_pcap = p;
}


int TX_pcap_eth::set_l2src(const string &src)
{
	string mac_s = mac2bin(src);
	if (mac_s.size() != sizeof(ehdr.ether_shost))
		return -1;
	memcpy(ehdr.ether_shost, mac_s.c_str(), sizeof(ehdr.ether_shost));
	return 0;
}


int TX_pcap_eth::set_l2dst(const string &dst)
{
	string mac_s = mac2bin(dst);
	if (mac_s.size() != sizeof(ehdr.ether_dhost))
		return -1;
	memcpy(ehdr.ether_dhost, mac_s.c_str(), sizeof(ehdr.ether_dhost));
	return 0;
}


void TX_pcap_eth::set_type(uint16_t t)
{
	ehdr.ether_type = htons(t);
}


int TX_pcap_eth::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


#ifdef HAVE_PCAP_INJECT

int TX_pcap_eth::sendpack(const void *buf, size_t len, struct sockaddr *s)
{
	if (!d_pcap->handle())
		return die("TX_pcap_eth::sendpack: No eth interface opened!", STDERR, -1);

	if (len > max_packet_size || len + sizeof(ehdr) > max_packet_size)
		return die("TX_pcap_eth::sendpack: Packet payload too large.", STDERR, -1);

	char tbuf[max_packet_size] = {0};

	memcpy(tbuf, &ehdr, sizeof(ehdr));
	memcpy(tbuf + sizeof(ehdr), buf, len);

	int r = pcap_inject(d_pcap->handle(), tbuf, len + sizeof(ehdr));

	if (r < 0)
		return die("TX_pcap_eth::sendpack::pcap_inject:", PERROR, errno);
	return r;
}

#else

int TX_pcap_eth::sendpack(const void *buf, size_t len, struct sockaddr *s)
{
	return die("TX_pcap_eth::sendpack: Function not available with this libpcap.", STDERR, -1);
}

#endif

int TX_pcap_eth::broadcast()
{
	unsigned char bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	memcpy(ehdr.ether_dhost, bcast, sizeof(ehdr.ether_dhost));
	return 0;
}

} // namespace

