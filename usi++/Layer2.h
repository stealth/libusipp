/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef __layer2_h__
#define __layer2_h__

#include "config.h"
#include "refcount.h"
#include "usi-structs.h"
#include "object.h"
#include "RX.h"
#include "TX.h"

#include <stdio.h>
#include <stdint.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>


namespace usipp {

/*! \class Layer2
 *  Describing layer 2
 * \brief Layer2 allows to register your own RX/TX providers
 */
class Layer2 : public Object {
private:
	ref_count<RX> d_rx;		// for receiving
	ref_count<TX> d_tx;		// for transmitting data
public:
	/*! Give us a Layer 2! Default to Raw IP sockets and
	 * pcap packet capturing. This may be different. You could also
	 * use ethertap devices etc. if TX/RX is implemented.
	 */
	Layer2(RX *r = NULL, TX *t = NULL);

	/*! destructor */
	virtual ~Layer2()
	{
	}

	/*! copy constructor, just makes sure RX and TX are not
	 *  deleted in destructor
	 */
	Layer2(const Layer2 &);


	/*! copy constructor, just makes sure RX and TX are not
	 *  deleted in destructor
	 */
	Layer2 &operator=(const Layer2 &);

	/*! Actually, capture a packet */
	virtual int sniffpack(void *, size_t);

	/*! Send a packet */
	virtual int sendpack(const void *buf, size_t len, struct sockaddr *s = NULL);

	/*! Send a packet */
	virtual int sendpack(const std::string &);

	/*! Initialize a device for packet capturing */
	virtual int init_device(const std::string &dev, int promisc, size_t snaplen);

	/*! Set a filter rule */
	int setfilter(const std::string &f);

	/*! Set a timeout */
	int timeout(struct timeval);

	/*! return was timeout? */
	bool timeout();

	/*! Register a new transmitter and return the argument.
	 *  Layer2{} is taking ownership (ref counting), so you must
	 *  not delete the TX object.
	 */
	TX *register_tx(TX *);


	/*! Register a new receiver and return the argument.
	 *  Layer2{} is taking ownership (ref counting), so you must
	 *  not delete the RX object.
	 */
	RX *register_rx(RX *);

	/*! return RAW TX object for fast access. You must not delete or
	 *   mess with it.
	 */
	TX *raw_tx() const
	{
		return d_tx.ptr();
	}

	/*! return RAW RX object for fast access. You must not delete or
	 *   mess with it.
	 */
	RX *raw_rx() const
	{
		return d_rx.ptr();
	}

	/*! return current TX object, ref counted */
	ref_count<TX> tx() const
	{
		return d_tx;
	}

	/*! return current RX object, ref counted */
	ref_count<RX> rx() const
	{
		return d_rx;
	}
};

} // namespace usipp
#endif

