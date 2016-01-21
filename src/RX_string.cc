/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2016 by Sebastian Krahmer,
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

#include "config.h"
#include "usi++/usi++.h"

#include <string>
#include <cstring>
#include <cstdint>
#include <cerrno>


namespace usipp {

using namespace std;


RX_string::RX_string(const RX_string &rhs)
	: RX(rhs)
{
	if (this == &rhs)
		return;
	d_dev = rhs.d_dev;
	d_offset = rhs.d_offset;
	d_pkt = rhs.d_pkt;
	return;
}


RX_string &RX_string::operator=(const RX_string &rhs)
{
	if (this == &rhs)
		return *this;
	RX::operator=(rhs);
	d_dev = rhs.d_dev;
	d_offset = rhs.d_offset;
	d_pkt = rhs.d_pkt;
	return *this;
}


string &RX_string::get_l2src(string &hwaddr)
{
	hwaddr = "";
	return hwaddr;
}


string &RX_string::get_l2dst(string &hwaddr)
{
	hwaddr = "";
	return hwaddr;
}


int RX_string::init_device(const string &dev, int promisc, size_t snaplen)
{
	if (dev == "ether")
		d_offset = 14;
	d_dev = dev;
	return 0;
}


int RX_string::setfilter(const string &s)
{
	return 0;
}


string &RX_string::sniffpack(string &s)
{
	s = "";
	if (d_pkt.size() > d_offset)
		s = d_pkt.substr(d_offset);
	return s;
}


int RX_string::sniffpack(void *buf, size_t len)
{
	string s = "";
	sniffpack(s);
	if (s.size() == 0)
		return 0;

	if (len > s.size())
		len = s.size();
	memcpy(buf, s.c_str(), len);
	return len;
}


int RX_string::timeout(const struct timeval &tv)
{
	return 0;
}

bool RX_string::timeout()
{
	return 0;
}


} // namespace usipp

