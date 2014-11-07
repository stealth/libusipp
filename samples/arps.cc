// c++ arps.cc  -lusi++ -ldnet -lpcap

#include <usi++/usi++.h>
#include <string>
#include <cstring>


using namespace usipp;
using namespace std;


int main(int argc, char **argv)
{
	struct {
		uint8_t arp_sha[6];
		uint8_t arp_spa[4];
		uint8_t arp_tha[6];
		uint8_t arp_tpa[4];
	} blob;

	string dev = "eth0";
	if (argc > 1)
		dev = argv[1];

	memset(&blob, 0, sizeof(blob));

	ARP *req = new ARP(dev), req2(dev);
	ARP *rep = new ARP(dev);

	// set src address of underlying TX
	req->set_l2src("77:88:99:aa:bb:cc");

	// Not really needed, ARP class is doing that for us
	// by itself
	req->raw_tx()->broadcast();
	req->set_op(usipp::ARPOP_REQUEST);

	memcpy(blob.arp_sha, "\x11\x22\x33\x44\x55\x66", 6);
	memcpy(blob.arp_spa, "\x01\x00\x00\x02", 4);
	memcpy(blob.arp_tpa, "\x03\x00\x00\x04", 4);

	// test assignment operators
	req2 = *req;
	delete req;
	req2.sendpack(&blob, sizeof(blob));

	rep->set_l2src("77:88:99:aa:bb:cc");

	rep->set_op(ARPOP_REPLY);
	rep->sendpack(&blob, sizeof(blob));

	delete rep;

        return 0;
}

