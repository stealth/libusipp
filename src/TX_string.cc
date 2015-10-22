/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2015 by Sebastian Krahmer,
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

#include "usi++/TX_string.h"
#include "usi++/usi++.h"
#include <stdio.h>
#include <string>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


namespace usipp {

using namespace std;

int TX_string::sendpack(const void *buf, size_t len, struct sockaddr *s)
{
	return sendpack(string(reinterpret_cast<const char *>(buf), len));
}


int TX_string::sendpack(const std::string &payload)
{
	pkt = payload;	// thats easy!
	return static_cast<int>(pkt.size());
}


int TX_string::broadcast()
{
	return 0;
}

} // namespace


