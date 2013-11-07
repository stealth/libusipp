#ifndef _OBJECT_H_
#define _OBJECT_H_

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

