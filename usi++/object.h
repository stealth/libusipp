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

#ifndef __object_h__
#define __object_h__

#include <string>

namespace usipp {

/* For error-handling.
 */
typedef enum {
	PERROR = 0,
	HERROR,
	PCAP,
	STDERR,
	RETURN
} errorFuncs;


/*! \class Object
 *  \brief base class for everything
 *
 *  Every class must derive from this, in order to get thread safe error
 *  handling.
 */
class Object {

private:

	std::string d_error_string;
	int d_errno;
	bool d_use_exceptions, d_print_message;

public:

	Object() : d_error_string(""), d_errno(0), d_use_exceptions(0), d_print_message(0) {}

	/*! Destructor */
	virtual ~Object() {}

	/*! Return the error string */
	const char *why() { return d_error_string.c_str(); }

	/*! Return saved error code */
	int error() { return d_errno; }

	/*! Set state of object to 'good' again */
	void error_reset() { d_error_string = ""; }

	/* Returns true if last operation(s) did not fail. */
	bool good() { return d_error_string.size() == 0; }

	/*! en/disable throwing of exceptions, rather than returning -1 on error */
	void use_exceptions(bool b) { d_use_exceptions = b; }

	/*! en/disable pringing of errors on the console (default off) */
	void print_errors(bool b) { d_print_message = b; }

protected:

	/*! only used internally by derived classes */
	int die(const std::string &, errorFuncs, int);

};

}

#endif

