// c++ synping.cc -lusi++ -ldnet -lpcap

#include <iostream>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <usi++/usi++.h>

using namespace std;
using namespace usipp;

// Example of using a different transport provider

int main(int argc, char **argv)
{
	char buf[100];

	if (argc != 5) {
		cout<<"Usage: "<<argv[0]<<" <dst> <dport> <src> <device>\n";
		exit(1);
	}

#ifdef USE_TCP6
	TCP6 tcp(argv[1]);
#else
	TCP4 tcp(argv[1]);

	// Use dnet rather than raw sockets
	TX *dnet_provider = new TX_dnet_ip;

	ref_count<TX> tx = tcp.tx();
	cout<<"TX use counter before register: "<<tx.use()<<endl;

	// old TX object has one user less when registering a new one
	tcp.register_tx(dnet_provider);
	cout<<"TX use counter after register: "<<tx.use()<<endl;

	// We dont need to care about the old or newly registered
	// TX objects, as they are ref-counted
#endif

	tcp.init_device(argv[4], 1, 100);
	tcp.setfilter("tcp and dst port 8000");

	tcp.set_flags(TH_SYN);
	tcp.set_dstport(atoi(argv[2]));
	tcp.set_srcport(8000);

	tcp.set_src(argv[3]);

	if (tcp.sendpack("") < 0)
		cerr<<tcp.why()<<endl;

	tcp.sniffpack(buf, 100);

	cout<<"TCP ack was: "<<tcp.get_ack()<<endl;

	return 0;
}

