// c++ martian_dest6.cc -lusi++ -lpcap -ldnet
//
// test remote machine to allow ::1 destination from
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

	ICMP6 icmp("::1");
	TX_dnet_eth *eth = new TX_dnet_eth("eth0");

	eth->set_l2dst(argv[1]);
	eth->set_l2src(argv[2]);
	eth->set_type(ETH_P_IPV6);
	icmp.set_src(argv[3]);

	icmp.register_tx(eth);
	icmp.set_type(ICMP6_ECHO_REQUEST);

	if (icmp.sendpack(ping) < 0)
		cerr<<icmp.why()<<endl;
        return 0;
}

