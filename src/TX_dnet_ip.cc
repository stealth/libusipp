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

#include "usi++/TX_dnet_ip.h"
#include "usi++/object.h"
#include <string>
#include <cerrno>
#include <sys/types.h>


namespace usipp {

#if defined(HAVE_LIBDNET) || defined(HAVE_LIBDUMBNET)

TX_dnet_ip::TX_dnet_ip()
{
	dip = ip_open();
	if (!dip)
		die("TX_dnet_ip::ip_open:", PERROR, errno);
}


int TX_dnet_ip::sendpack(const std::string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


int TX_dnet_ip::sendpack(const void *buf, size_t len, struct sockaddr *s)
{
	if (!dip)
		return die("TX_dnet_ip::sendpack: No IP interface opened!", STDERR, -1);

	ssize_t r = (int)ip_send(dip, buf, len);
	if (r < 0)
		return die("TX_dnet_ip::sendpack::ip_send:", PERROR, errno);
	return r;
}


int TX_dnet_ip::broadcast()
{
	return 0;
}

#endif

} // namespace

