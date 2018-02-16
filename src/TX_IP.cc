/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2018 by Sebastian Krahmer,
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

#include "usi++/TX_IP.h"
#include "usi++/usi++.h"
#include <stdio.h>
#include <string>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>		// IPPROTO_RAW


namespace usipp {

using namespace std;

int TX_IP::sendpack(const void *buf, size_t len, struct sockaddr *s)
{
   	// if not already opened a RAW-socket, do it!
	if (rawfd < 0) {
	       // open a socket
		if ((rawfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
			return die("TX_IP::sendpack::socket", PERROR, errno);

		int one = 1;

		// let us write IP-headers
		if (setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
			return die("TX_IP::sendpack::setsockopt", PERROR, errno);
	}

	int r;
	if ((r = sendto(rawfd, buf, len, 0, s, sizeof(sockaddr_in))) < 0)
		return die("TX_IP::sendpack::sendto", PERROR, errno);

	return r;
}


int TX_IP::sendpack(const std::string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


int TX_IP::broadcast()
{
	int one = 1;

	if (rawfd < 0) {
		// open a socket
		if ((rawfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
			return die("TX_IP::sendpack::socket", PERROR, errno);

		// let  us write IP-headers
		if (setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
			return die("TX_IP::sendpack::setsockopt", PERROR, errno);
	}

	if (setsockopt(rawfd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0)
		return die("TX_IP::broadcast::setsockopt", PERROR, errno);
	return 0;
}

} // namespace


