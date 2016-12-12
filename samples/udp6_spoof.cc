// c++ udp6_spoof.cc -lusi++ -ldnet -lpcap

#include <iostream>
#include <usi++/usi++.h>
#include <stdlib.h>

using namespace std;
using namespace usipp;

// spoof a syslog message to a FreeBSD box.

int main(int argc, char **argv)
{

	if (argc < 3) {
		cout<<argv[0]<<" <src> <dst> [dev]\n";
		exit(1);
	}

	UDP6 udp(argv[2]);

	if (argc == 4) {
		usipp::pcap *rx = reinterpret_cast<usipp::pcap *>(udp.raw_rx());
		if (rx->init_device(argv[3], 1, usipp::max_packet_size) < 0) {
			cerr<<udp.why()<<endl;
			return 1;
		}
		TX_pcap_eth *tx = new TX_pcap_eth(rx);
		tx->set_l2src("00:22:33:44:55:66");
		tx->set_l2dst("00:11:33:44:55:66");
		tx->set_type(numbers::eth_p_ipv6);
		udp.register_tx(tx);
	}

	udp.set_srcport(1);
	udp.set_proto(17);
	udp.set_dstport(111);
	udp.set_src(argv[1]);
	udp.sendpack("\xff\xff");

        return 0;
}
