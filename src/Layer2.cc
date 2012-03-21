/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
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
	d_rx = rhs.rx();
	d_tx = rhs.tx();
	return *this;
}


Layer2::Layer2(const Layer2 &rhs)
{
	if (&rhs == this)
		return;
	d_rx = rhs.rx();
	d_tx = rhs.tx();
}


int Layer2::sendpack(const void *buf, size_t len, struct sockaddr *s)
{
	int r = d_tx->sendpack(buf, len, s);
	return r;
}


int Layer2::sendpack(const string &payload)
{
	return sendpack(payload.c_str(), payload.size());
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


int Layer2::timeout(struct timeval tv)
{
	return d_rx->timeout(tv);
}


bool Layer2::timeout()
{
	return d_rx->timeout();
}

} // namespace usipp

