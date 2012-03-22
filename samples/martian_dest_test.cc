// c++ martian_dest.cc -lusi++ -lpcap -ldnet
//
// test remote machine to allow 127.0.0.1 destination from
// ethernet NIC's
#include <iostream>
#include <string>
#include <usi++/usi++.h>

using namespace std;
using namespace usipp;

int main(int argc, char **argv)
{
	string ping = "Hello";

	if (argc != 4) {
		cerr<<"Usage: "<<argv[0]<<" <hw-dst> <hw-src> <ip-src>\n";
		return 1;
	}

	ICMP icmp("127.0.0.1");
	TX_dnet_eth *eth = new TX_dnet_eth("eth0");

	eth->set_l2dst(argv[1]);
	eth->set_l2src(argv[2]);
	eth->set_type(usipp::ETH_P_IP);
	icmp.set_src(argv[3]);

	// We registered a non-IP layer TX provider which cannot
	// know about checksums, so we could force IP class calculate it before
	// passing it to TX. However, not really necessary to explicitely call
	// this, as IP class detects non-RAW socket TX providers itself.
	//icmp.checksum();
	icmp.register_tx(eth);

	icmp.set_type(ICMP_ECHO);

       	icmp.sendpack(ping);
        return 0;
}

