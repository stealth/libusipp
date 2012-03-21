/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef _TX_IP_H_
#define _TX_IP_H_

#include "config.h"
#include "TX.h"
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

namespace usipp {

/*! \class TX_IP
 *  \brief TX provider implementing raw sockets
 */
class TX_IP : public TX {
private:
	int rawfd;
public:

	/*! Constructor */
	TX_IP() : rawfd(-1) {}


	/*! Destructor */
	virtual ~TX_IP() { close(rawfd); }

	/*! Send a packet on raw socket (starting with IP-hdr) */
	virtual int sendpack(const void *, size_t, struct sockaddr* = 0);

	/*! Send a packet on raw socket (starting with IP-hdr) */
	int sendpack(const std::string &);

	/*! Enable broadcast option on socket */
	virtual int broadcast();

	/*! dummy, raw socket doesnt have layer2 address */
	virtual int set_l2src(const std::string &s) { return 0; }

	/*! dummy, raw socket doesnt have layer2 address */
	virtual int set_l2dst(const std::string &s) { return 0; }

};

}	// namespace
#endif

