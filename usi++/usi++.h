/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#ifndef __usipp_h__
#define __usipp_h__

enum {
	usipp_version = 199
};

#include "config.h"
#include "usi-structs.h"
#include "object.h"
#include "arp.h"
#include "datalink.h"
#include "Layer2.h"
#include "ip.h"
#include "ip6.h"
#include "icmp.h"
#include "icmp6.h"
#include "udp.h"
#include "tcp.h"
#include "TX.h"
#include "TX_dnet_ip.h"
#include "TX_dnet_eth.h"
#include "TX_IP.h"
#include "TX_IP6.h"
#include "RX.h"
#include <string>

namespace usipp {

/*! \class usifault
 *  \brief the class of which exceptions are thrown, if enabled
 */
class usifault {
	std::string fault;
public:
	/*! */
   	usifault(const std::string &s = "undef") : fault(s) {}

	/*! */
        ~usifault() {}

	/*! return error string */
	const char *why() { return fault.c_str(); }
};

extern unsigned short in_cksum(unsigned short *ptr, int len, bool may_pad);

} // namespace usipp


#endif

