/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2013 by Sebastian Krahmer,
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
#include "usi++/refcount.h"
#include "usi++/usi++.h"
#include "usi++/object.h"
#include "usi++/RX.h"
#include "usi++/TX.h"
#include "usi++/Layer2.h"
#include "usi++/datalink.h"
#include "usi++/TX_IP.h"
#include <stdio.h>
#include <string.h>

namespace usipp {

using namespace std;


Layer2::Layer2(RX *r, TX *t)
{
	if (!r) {
		d_rx = ref_count<RX>(new pcap);
	} else
		d_rx = ref_count<RX>(r);

	if (!t) {
		d_tx = ref_count<TX>(new TX_IP);
	} else
		d_tx = ref_count<TX>(t);
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


int Layer2::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


string &Layer2::sniffpack(string &s)
{
	return d_rx->sniffpack(s);
}

// delegate sniff request to the receiver
int Layer2::sniffpack(void *buf, size_t len)
{
	int r = d_rx->sniffpack(buf, len);
	if (r < 0)
		return die(d_rx->why(), STDERR, d_rx->error());
	return r;
}


int Layer2::setfilter(const string &fstring)
{
	int r = d_rx->setfilter(fstring);
	if (r < 0)
		return die(d_rx->why(), STDERR, d_rx->error());
	return r;
}


TX *Layer2::register_tx(TX *t)
{
	d_tx = ref_count<TX>(t);
	return t;
}


RX *Layer2::register_rx(RX *r)
{
	d_rx = ref_count<RX>(r);
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

