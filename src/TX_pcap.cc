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

#include "usi++/TX_pcap.h"
#include "usi++/object.h"
#include "usi++/datalink.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <string>
#include <cstring>
#include <string>
#include <cerrno>


namespace usipp {


using namespace std;


TX_pcap::TX_pcap(usipp::pcap *p)
{
	d_cooked = d_frame = "";
	d_pcap = p;
}


int TX_pcap::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


#ifdef HAVE_PCAP_INJECT

int TX_pcap::sendpack(const void *buf, size_t len, struct sockaddr *s)
{

	if (!d_pcap->handle())
		return die("TX_pcap::sendpack: No eth interface opened!", STDERR, -1);

	char *tbuf = new (nothrow) char[len + d_cooked.size() + d_frame.size()];

	if (!tbuf)
		return die("TX_pcap::sendpack::new: Out of Memory!", RETURN, -1);

	memcpy(tbuf, d_cooked.c_str(), d_cooked.size());
	memcpy(tbuf + d_cooked.size(), d_frame.c_str(), d_frame.size());
	memcpy(tbuf + d_cooked.size() + d_frame.size(), buf, len);

	int r = pcap_inject(d_pcap->handle(), tbuf, len + d_cooked.size() + d_frame.size());

	delete [] tbuf;

	if (r < 0)
		return die("TX_pcap::sendpack::pcap_inject:", PERROR, errno);
	return r;
}

#else

int TX_pcap::sendpack(const void *buf, size_t len, struct sockaddr *s)
{
	return die("TX_pcap::sendpack: Function not available with this libpcap.", STDERR, -1);
}

#endif


} // namespace

