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
 * along with psc.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string>
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include "usi++/object.h"
#include "usi++/usi++.h"

namespace usipp {

using namespace std;

int Object::die(const string &message, errorFuncs what, int error)
{
	d_error_string = message;
	d_errno = error;

	int r = error;

	if (r > 0)
		r = -r;

	if (d_use_exceptions) {
		throw usifault(message);
	}

	/* Not reached, if 'exceptions' was true */
	switch (what) {
	case PERROR:
		if (d_print_message)
			perror(message.c_str());
		else
			d_error_string += strerror(errno);
    		break;
	case STDERR:
		if (d_print_message)
			fprintf(stderr, "%s\n", message.c_str());
		break;
	case HERROR:
		if (d_print_message)
			(void)herror(message.c_str());
		break;
	case PCAP:
		if (d_print_message)
			fprintf(stderr, "%s\n", pcap_strerror(error));
		else
			d_error_string += pcap_strerror(error);
		break;
	case RETURN:
		break;

	default:
		break;
	}

	return r;
}

}

