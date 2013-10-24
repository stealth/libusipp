/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef _RX_H_
#define _RX_H_

#include "config.h"
#include "usi-structs.h"
#include "object.h"
#include <stdio.h>
#include <string>
#include <sys/types.h>


namespace usipp {

/*! \class RX
 * \brief abstract RX provider class
 *
 * Receivier provider.
 * You can implement your own classes and register objects
 * via register_rx(). You must provide at least the functions
 * below. Shipped with usi++++ is the Pcap provider.
 */
class RX : public Object {
public:

	/*! Constructor */
	RX() {}

	/*! Destrcutor */
	virtual ~RX() {}

	/*! Capture a packet from the net, string version */
	virtual std::string &sniffpack(std::string &) = 0;

	/*! Capture a packet from the network.
	 *  At most a given len. */
	virtual int sniffpack(void *, size_t) = 0;

	/*! Init a device before capturing */
	virtual int init_device(const std::string &, int, size_t) = 0;

	/*! Set a filter of what must be captured */
	virtual int setfilter(const std::string &) = 0;

	/*! set a timeout */
	virtual int timeout(const struct timeval &) = 0;

	/*! RX derived class must also tell user when timeout occurs */
	virtual bool timeout() = 0;

	/*! Get Layer2 source address */
	virtual std::string &get_l2src(std::string &) = 0;

	/*! Get Layer2 destination address */
	virtual std::string &get_l2dst(std::string &) = 0;

	/*! return some RX-unique tag, e.g. RX_PCAP etc, see usi-structs.h enum.
	 *  This is for the upper layers to check which capture layer has been
	 *  registered.
	 */
	virtual int tag() = 0;
};

} // namespace usipp
#endif

