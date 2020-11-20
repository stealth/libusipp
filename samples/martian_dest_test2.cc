// c++ martian_dest2.cc -lusi++ -lpcap -ldnet
//
// test remote machine to allow 127.0.0.1 destination from
// ethernet NIC's, TX_pcap_eth version.
#include <iostream>
#include <string>
#include <usi++/usi++.h>

using namespace std;
using namespace usipp;

int main(int argc, char **argv)
{
	string ping = "Hello";

	if (argc != 5) {
		cerr<<"Usage: "<<argv[0]<<" <hw-dst> <hw-src> <ip-src> <nic>\n";
		return 1;
	}

	ICMP icmp("127.0.0.1");
	icmp.init_device(argv[4], 1, 1500);

	// must be a pcap RX, init_device() already called
	auto rx = icmp.rx();

	cout<<"refcount of RX: "<<rx.use_count()<<endl;

	// does not take ownership of pcap *
	TX_pcap_eth *eth = new TX_pcap_eth(static_cast<usipp::pcap *>(rx.get()));

	eth->set_l2dst(argv[1]);
	eth->set_l2src(argv[2]);
	eth->set_type(numbers::eth_p_ip);
	icmp.set_src(argv[3]);

	// We registered a non-IP layer TX provider which cannot
	// know about checksums, so let calculate it by IP class
	icmp.checksum(1);
	icmp.register_tx(eth);

	icmp.set_type(numbers::icmp_echo);

	if (icmp.sendpack(ping) < 0)
		cerr<<icmp.why()<<endl;
        return 0;
}

