// c++ synping.cc -lusi++ -ldnet -lpcap

#include <iostream>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <memory.h>
#include <usi++/usi++.h>

using namespace std;
using namespace usipp;

// Example of using a different transport provider

int main(int argc, char **argv)
{
	char buf[min_packet_size];

	if (argc != 5) {
		cout<<"Usage: "<<argv[0]<<" <dst> <dport> <src> <device>\n";
		exit(1);
	}

#ifdef USE_TCP6
	TCP6 tcp(argv[1]);
#else
	TCP4 tcp(argv[1]);

	// Use dnet rather than raw sockets
	TX *dnet_provider = new (nothrow) TX_dnet_ip;

	auto rx = make_shared<usipp::pcap>();

	shared_ptr<TX> tx = tcp.tx();
	cout<<"TX use counter before register: "<<tx.use_count()<<endl;

	// old TX object has one user less when registering a new one
	// This transfers ownership of dnet_provider to the tcp object
	tcp.register_tx(dnet_provider);
	cout<<"old TX use counter after register: "<<tx.use_count()<<endl;

	auto &rx_ref = tcp.register_rx(rx);
	cout<<"RX use count: "<<rx_ref.use_count()<<endl;

	// We dont need to care about the old or newly registered
	// TX/RX objects, as they are ref-counted
#endif

	tcp.init_device(argv[4], 1, min_packet_size);
	tcp.setfilter("tcp and dst port 8000");

	tcp.set_flags(numbers::th_syn|numbers::th_cwr);
	tcp.set_dstport(atoi(argv[2]));
	tcp.set_srcport(8000);

	tcp.set_src(argv[3]);

	if (tcp.sendpack("") < 0)
		cerr<<tcp.why()<<endl;

	int r = tcp.sniffpack(buf, sizeof(buf));

	cout<<"TCP ack was: "<<tcp.get_ack()<<endl<<"r="<<r<<endl;

	return 0;
}

