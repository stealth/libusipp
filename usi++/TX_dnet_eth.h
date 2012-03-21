/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef __tx_dnet_eth_h__
#define __tx_dnet_eth_h__

#include "TX.h"
#include "config.h"
#include <sys/socket.h>

#ifdef HAVE_LIBDNET
#include "usi-structs.h"
#include <dnet.h>
#include <string>
#endif


namespace usipp {

/*!\class TX_dnet_eth
 * \brief libdnet packet socket TX provider
 * \example martian_dest_test.cc
 */
#ifdef HAVE_LIBDNET

class TX_dnet_eth : public TX {
private:

	eth_t *deth;

	ether_header ehdr;

public:

	/*! provide a dnet eth (layer 2) sender with NIC-name as argument */
	TX_dnet_eth(const std::string &);

	/*! destructor */
	virtual ~TX_dnet_eth() { eth_close(deth); };

	/*! send a packet with payload via libdnet (eth), hardware frame included */
	virtual int sendpack(const void *, size_t, struct sockaddr * = 0);

	/*! send a packet with payload via libdnet (eth), hardware frame included */
	int sendpack(const std::string &);

	/*! enable broadcasting of TX */
	virtual int broadcast();

	/*! Set ethernet source address */
	virtual int set_l2src(const std::string &);

	/*! Set ethernet destination address */
	virtual int set_l2dst(const std::string &);

	/*! Set ethernet type (ETH_P_IP, ETH_P_ARP etc).*/
	void set_type(uint16_t);

};
#else

/* dummy wrapper; its strongly recommended to install libdnet */
class TX_dnet_eth : public TX {

public:

	TX_dnet_eth(const std::string &) {}

	virtual int sendpack(const void *vp, size_t, struct sockaddr * = 0) { return -1; }

	virtual int broadcast() { return -1; }

	virtual int set_l2src(const std::string &) { return -1; }

	virtual int set_l2dst(const std::string &) { return -1; }
};

#endif

} // namespace usipp

#endif

