// c++ udp6_spoof.cc -lusi++ -ldnet -lpcap

#include <iostream>
#include <usi++/usi++.h>
#include <stdlib.h>

using namespace std;
using namespace usipp;

// spoof a syslog message to a FreeBSD box.

int main(int argc, char **argv)
{

	if (argc < 2) {
		cout<<argv[0]<<" [src] [dst]\n";
		exit(1);
	}
	UDP6 udp(argv[2]);
        udp.set_srcport(1);
	udp.set_dstport(111);
	udp.set_src(argv[1]);
       	udp.sendpack("\xff\xff");

        return 0;
}
