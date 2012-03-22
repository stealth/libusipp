/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef __tx_dnet_ip__
#define __tx_dnet_ip__

#include "TX.h"
#include "config.h"
#include "usi-structs.h"
#include <string>
#include <sys/socket.h>

#ifdef HAVE_LIBDNET
#include <dnet.h>
#endif


namespace usipp {

/*! \class TX_dnet_ip
 *  \brief libdnet raw socket TX provider
 *  \example synping.cc
 */
#ifdef HAVE_LIBDNET

class TX_dnet_ip : public TX {
private:

	ip_t *dip;

public:

	/*! Constructor */
	TX_dnet_ip();

	/*! Destructor */
	virtual ~TX_dnet_ip()
	{
		if (dip)
			ip_close(dip);
	}

	/*! See TX::tag() */
	virtual int tag() { return TX_TAG_DNET_IP; }

	/*! send a packet via libdnet (ip) */
	virtual int sendpack(const void *, size_t, struct sockaddr * = 0);

	/*! send a packet via libdnet (ip) */
	int sendpack(const std::string &);

	/*! enable broadcast sending */
	virtual int broadcast();

	/*! dummy, raw sockets dont have layer2 address */
	virtual int set_l2src(const std::string &) { return 0; }

	/*! dummy, raw sockets dont have layer2 address */
	virtual int set_l2dst(const std::string &) { return 0; }
};
#else

/* dummy wrapper; its strongly recommended to install libdnet */
class TX_dnet_ip : public TX {

public:

	/*!*/
	TX_dnet_ip(const std::string &) {}

	/*!*/
	virtual int tag() { return TX_TAG_NONE; }

	/*!*/
	virtual int sendpack(const void *vp, size_t, struct sockaddr * = 0) { return -1; }

	/*!*/
	virtual int broadcast() { return -1; }

	/*! dummy, raw sockets dont have layer2 address */
	virtual int set_l2src(const std::string &) { return -1; }

	/*! dummy, raw sockets dont have layer2 address */
	virtual int set_l2dst(const std::string &) { return -1; }
};


#endif

} // namespace usipp

#endif

