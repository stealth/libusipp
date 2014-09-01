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

#include "usi++/TX_dnet_eth.h"
#include "usi++/object.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <string>
#include <cstring>
#include <cerrno>


namespace usipp {

#if defined(HAVE_LIBDNET) || defined(HAVE_LIBDUMBNET)

using namespace std;


TX_dnet_eth::TX_dnet_eth(const string &dev)
{
	memset(&ehdr, 0, sizeof(ehdr));
	deth = eth_open(dev.c_str());
	if (!deth)
		die("TX_dnet_eth", PERROR, errno);
}


int TX_dnet_eth::set_l2src(const string &src)
{
	unsigned char mac[6];

	if (src.size() == ETH_ALEN) {
		memcpy(ehdr.ether_dhost, src.c_str(), ETH_ALEN);
		return 0;
	}

	if (sscanf(src.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != ETH_ALEN)
		return die("TX_dnet_eth::set_l2src::sscanf: invalid ethernet address", RETURN, -1);

	memcpy(ehdr.ether_shost, mac, sizeof(ehdr.ether_shost));
	return 0;
}


int TX_dnet_eth::set_l2dst(const string &dst)
{
	unsigned char mac[6];

	if (dst.size() == ETH_ALEN) {
		memcpy(ehdr.ether_dhost, dst.c_str(), ETH_ALEN);
		return 0;
	}

	if (sscanf(dst.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != ETH_ALEN)
		die("TX_dnet_eth::set_l2dst::sscanf: invalid ethernet address", RETURN, -1);

	memcpy(ehdr.ether_dhost, mac, sizeof(ehdr.ether_dhost));
	return 0;
}


void TX_dnet_eth::set_type(uint16_t t)
{
	ehdr.ether_type = htons(t);
}


int TX_dnet_eth::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


int TX_dnet_eth::sendpack(const void *buf, size_t len, struct sockaddr *s)
{

	if (!deth)
		return die("TX_dnet_eth::sendpack: No eth interface opened!", STDERR, -1);

	char *tbuf = new (nothrow) char[len + sizeof(ehdr)];

	if (!tbuf)
		return die("X_dnet_eth::sendpack::new: Out of Memory!", RETURN, -1);

	memcpy(tbuf, &ehdr, sizeof(ehdr));
	memcpy(tbuf + sizeof(ehdr), buf, len);

	ssize_t r = (int)eth_send(deth, tbuf, len + sizeof(ehdr));

	delete [] tbuf;

	if (r < 0)
		return die("TX_dnet_eth::sendpack::eth_send:", PERROR, errno);
	return r;
}


int TX_dnet_eth::broadcast()
{
	unsigned char bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	memcpy(ehdr.ether_dhost, bcast, sizeof(ehdr.ether_dhost));
	return 0;
}

#endif

} // namespace

