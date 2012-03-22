/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef __tx_h__
#define __tx_h__

#include "config.h"
#include "usi-structs.h"
#include "object.h"
#include <stdio.h>
#include <sys/socket.h>

namespace usipp {

/*!\class TX
 * \brief abstract TX provider class
 *
 * The transmitter lets you send packets on the net.
 * You can write your own and register them with
 * register_tx() but you must provide at least
 * a sendpack(), broadcast(), set_l2src() and set_l2dst() functions.
 * Shipped with USI++ is TX_IP which
 * is in fact a RAW socket, TX_IP6, TX_dnet_ip and TX_dnet_eth for dnet providers  */
class TX : public Object {
public:

	/*! Constructor */
	TX() {}

	/*! Destructor */
	virtual ~TX() {}

	/*! Do the send. You don't call this directly. IP::sendpack() etc
	 *  deliver the request to here. You need to provide a sendpack()
	 *  when you write your own TX classes.
	 */
	virtual int sendpack(const void *, size_t, struct sockaddr * = 0) = 0;

	/*! return some TX-unique tag, e.g. TX_IP etc, see usi-structs.h enum.
	 *  This is for the upper layers to check which transport layer has been
	*   registered, since some require IP checksum compuatation, and some dont.
	 */
	virtual int tag() = 0;

	/*! Must have capability to send broadcast packets. May be
	 * just a dummy.
	 */
	virtual int broadcast() = 0;

	/*! set layer2 source address (may be a dummy for RAW sockets) */
	virtual int set_l2src(const std::string &) = 0;

	/*! set layer2 destination address ((may be a dummy for RAW sockets) */
	virtual int set_l2dst(const std::string &) = 0;
};

} // namespace usipp

#endif

