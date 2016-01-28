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

#include "config.h"
#include "usi++/usi++.h"

#include <string>
#include <cstring>
#include <cstdint>
#include <cerrno>


namespace usipp {

using namespace std;


RX_fd::RX_fd(int fd)
	: RX()
{
	// Initialize
	d_cooked = "";
	d_dev = "";
	d_fd = fd;
	memset(&d_tv, 0, sizeof(d_tv));
	d_timeout = false;
	d_packet = NULL;
	d_offset = 0;
	d_has_ether = 0;

	memset(&d_ether, 0, sizeof(d_ether));
}



RX_fd::~RX_fd()
{
}


RX_fd::RX_fd(const RX_fd &rhs)
	: RX(rhs)
{
	if (this == &rhs)
		return;
	d_cooked = rhs.d_cooked;
	d_dev = rhs.d_dev;
	d_fd = rhs.d_fd;
	d_offset = rhs.d_offset;
	d_timeout = rhs.d_timeout;
	d_tv = rhs.d_tv;
	d_packet = NULL;
	d_has_ether = rhs.d_has_ether;
	d_ether = rhs.d_ether;

	return;
}


RX_fd &RX_fd::operator=(const RX_fd &rhs)
{
	if (this == &rhs)
		return *this;
	RX::operator=(rhs);

	d_cooked = rhs.d_cooked;
	d_dev = rhs.d_dev;
	d_fd = rhs.d_fd;
	d_offset = rhs.d_offset;
	d_timeout = rhs.d_timeout;
	d_tv = rhs.d_tv;
	d_packet = NULL;
	d_has_ether = rhs.d_has_ether;
	d_ether = rhs.d_ether;

	return *this;
}


/* Get the cooked header, if any
 */
string &RX_fd::get_cooked(string &hdr)
{
	hdr = d_cooked;
	return hdr;
}


string &RX_fd::get_l2src(string &hwaddr)
{
	hwaddr = "";
	if (d_has_ether)
		hwaddr = string(reinterpret_cast<char *>(d_ether.ether_shost), numbers::eth_alen);
	return hwaddr;
}


string &RX_fd::get_l2dst(string &hwaddr)
{
	hwaddr = "";
	if (d_has_ether)
		hwaddr = string(reinterpret_cast<char *>(d_ether.ether_dhost), numbers::eth_alen);
	return hwaddr;
}


uint16_t RX_fd::get_etype()
{
	return ntohs(d_ether.ether_type);
}


string &RX_fd::get_frame(string &frame)
{
	frame = "";

	char buf[1024];

	if (d_has_ether) {
		memcpy(buf, &d_ether, sizeof(d_ether));
		frame = string(buf, sizeof(d_ether));
	}
	return frame;
}


int RX_fd::init_device(const string &dev, int promisc, size_t snaplen)
{
	d_offset = 0;
	d_dev = dev;

	if (dev.find("tun") == 0 || dev.find("tap") == 0) {
		if (dev.find("IFF_NO_PI") == string::npos)
			d_offset = 4;
		d_has_ether = (dev.find("tap") == 0);
	}
	return 0;
}


int RX_fd::setfilter(const string &s)
{
	return 0;
}


string &RX_fd::sniffpack(string &s)
{
	s = "";
	char buf[max_packet_size];
	int r = sniffpack(buf, sizeof(buf));
	if (r > 0)
		s = string(buf, r);
	return s;
}


int RX_fd::sniffpack(void *s, size_t len)
{
	d_timeout = 0;
	d_cooked = "";
	memset(&d_ether, 0, sizeof(d_ether));

	int idx = d_offset;
	if (d_has_ether)
		idx += sizeof(d_ether);

	if (d_offset < 0 || (size_t)idx >= len)
		return die("RX_fd::sniffpack: Insane offset/len combination", STDERR, -1);

	if (d_tv.tv_sec != 0 || d_tv.tv_usec != 0) {	// TO was set
		while (1) {
			fd_set rset;
			FD_ZERO(&rset);
			FD_SET(d_fd, &rset);
			timeval tmp = d_tv;

			// wait for packet
			int sr;
			if ((sr = select(d_fd + 1, &rset, NULL, NULL, &tmp)) < 0) {
				if (errno == EINTR)
					continue;
				else
					return -1;
			} else if (sr == 0) { // timed out
				d_timeout = 1;
				return 0;
			} else		// got packet
				break;
		}
	}

	int r = read(d_fd, s, len);
	if (r < 0 || r <= idx)
		return die("RX_fd::sniffpack:", STDERR, -1);
	if (idx > 0) {
		d_cooked = string(reinterpret_cast<char *>(s), d_offset);
		// Ether header if any
		if (idx > d_offset)
			memcpy(&d_ether, reinterpret_cast<char *>(s) + d_offset, sizeof(d_ether));
		// The IP packet
		memmove(s, reinterpret_cast<char *>(s) + idx, r - idx);

	}
	return r - idx;
}


int RX_fd::timeout(const struct timeval &tv)
{
	d_tv = tv;
	d_timeout = false;
	return 0;
}


bool RX_fd::timeout()
{
	return d_timeout;
}

} // namespace usipp

