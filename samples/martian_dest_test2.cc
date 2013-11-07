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
	icmp.init_device("eth0", 1, 1500);

	// must be a pcap RX
	ref_count<RX> rx = icmp.rx();

	cout<<"refcount of RX: "<<rx.use()<<endl;

	// does not take ownership of pcap *
	TX_pcap_eth *eth = new TX_pcap_eth(static_cast<usipp::pcap *>(rx.ptr()));

	eth->set_l2dst(argv[1]);
	eth->set_l2src(argv[2]);
	eth->set_type(usipp::ETH_P_IP);
	icmp.set_src(argv[3]);

	// We registered a non-IP layer TX provider which cannot
	// know about checksums, so let calculate it by IP class
	icmp.checksum(1);
	icmp.register_tx(eth);

	icmp.set_type(ICMP_ECHO);

	if (icmp.sendpack(ping) < 0)
		cerr<<icmp.why()<<endl;
        return 0;
}

