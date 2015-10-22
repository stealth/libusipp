/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2015 by Sebastian Krahmer,
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

#ifndef usipp_layer2_h
#define usipp_layer2_h

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
	virtual std::string &sniffpack(std::string &);

	/*! Actually, capture a packet */
	virtual int sniffpack(void *, size_t);

	/*! Send a packet */
	virtual int sendpack(const void *buf, size_t len, struct sockaddr *s = NULL);

	/*! Send a packet */
	virtual int sendpack(const std::string &);

	/*! Initialize a device for packet capturing
	 */
	virtual int init_device(const std::string &dev, int promisc, size_t snaplen);

	/*! Set a filter rule */
	int setfilter(const std::string &f);

	/*! Set a timeout */
	int timeout(const struct timeval &);

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

