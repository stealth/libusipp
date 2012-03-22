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

