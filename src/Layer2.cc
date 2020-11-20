/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2020 by Sebastian Krahmer,
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
 * along with libusi++.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include "usi++/usi++.h"
#include "usi++/object.h"
#include "usi++/RX.h"
#include "usi++/TX.h"
#include "usi++/Layer2.h"
#include "usi++/datalink.h"
#include "usi++/TX_IP.h"
#include <stdio.h>
#include <memory.h>
#include <cstdint>
#include <string.h>

namespace usipp {

using namespace std;


Layer2::Layer2(RX *r, TX *t)
{
	if (!r) {
		d_rx = shared_ptr<pcap>(new (nothrow) pcap);
	} else
		d_rx = shared_ptr<RX>(r);

	if (!t) {
		d_tx = shared_ptr<TX_IP>(new (nothrow) TX_IP);
	} else
		d_tx = shared_ptr<TX>(t);
}


Layer2 &Layer2::operator=(const Layer2 &rhs)
{
	if (&rhs == this)
		return *this;
	Object::operator=(rhs);
	d_rx = rhs.rx();
	d_tx = rhs.tx();
	return *this;
}


Layer2::Layer2(const Layer2 &rhs)
	: Object(rhs)
{
	if (&rhs == this)
		return;
	d_rx = rhs.rx();
	d_tx = rhs.tx();
}


int Layer2::sendpack(const void *buf, size_t len, struct sockaddr *s)
{
	int r = d_tx->sendpack(buf, len, s);
	if (r < 0)
		return die(d_tx->why(), STDERR, d_tx->error());
	return r;
}


/* Need a sendpack with this signature for exact overloading with same signature of derived classes
 * sendpack. Some compilers warn about overloading different signatures with default argument
 */
int Layer2::sendpack(const void *buf, size_t len)
{
	int r = d_tx->sendpack(buf, len, nullptr);
	if (r < 0)
		return die(d_tx->why(), STDERR, d_tx->error());
	return r;
}


int Layer2::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


// So upper layer can potentially check for messed up short
// IP packets, wrong header length's etc.
int Layer2::bytes_received()
{
	return bytes_rcvd;
}


string &Layer2::sniffpack(string &s)
{
	int off = 0;
	s = "";
	char buf[max_packet_size] = {0};
	bytes_rcvd = this->sniffpack(buf, sizeof(buf), off);
	if (bytes_rcvd > off)
		s = string(buf + off, bytes_rcvd - off);
	return s;
}


// delegate sniff request to the receiver
int Layer2::sniffpack(void *buf, size_t len, int &off)
{
	off = 0;
	if (len > max_buffer_len || len < min_packet_size)
		return die("Layer2::sniffpack: Insane buffer len. Minimum of 1522?", STDERR, -1);

	bytes_rcvd = d_rx->sniffpack(buf, len, off);
	if (bytes_rcvd < 0)
		return die(d_rx->why(), STDERR, d_rx->error());
	return bytes_rcvd;
}


// delegate sniff request to the receiver
int Layer2::sniffpack(void *buf, size_t len)
{
	if (len > max_buffer_len || len < min_packet_size)
		return die("Layer2::sniffpack: Insane buffer len. Minimum of 1522?", STDERR, -1);

	bytes_rcvd = d_rx->sniffpack(buf, len);
	if (bytes_rcvd < 0)
		return die(d_rx->why(), STDERR, d_rx->error());
	return bytes_rcvd;
}


int Layer2::setfilter(const string &fstring)
{
	int r = d_rx->setfilter(fstring);
	if (r < 0)
		return die(d_rx->why(), STDERR, d_rx->error());
	return r;
}

const shared_ptr<TX> &Layer2::register_tx(const shared_ptr<TX> &ref)
{
	d_tx = ref;
	return d_tx;
}


TX *Layer2::register_tx(TX *t)
{
	d_tx = shared_ptr<TX>(t);
	return t;
}


const shared_ptr<RX> &Layer2::register_rx(const shared_ptr<RX> &ref)
{
	d_rx = ref;
	return d_rx;
}


RX *Layer2::register_rx(RX *r)
{
	d_rx = shared_ptr<RX>(r);
	return r;
}


int Layer2::init_device(const string &dev, int p, size_t snaplen)
{
	int r = d_rx->init_device(dev, p, snaplen);
	if (r < 0) {
		return die(d_rx->why(), STDERR, d_rx->error());
	}
	return r;
}


int Layer2::timeout(const struct timeval &tv)
{
	return d_rx->timeout(tv);
}


bool Layer2::timeout()
{
	return d_rx->timeout();
}

} // namespace usipp

