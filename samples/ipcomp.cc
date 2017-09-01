// c++ ipcomp.cc -lusi++ -ldnet -lpcap

#include <iostream>
#include <usi++/usi++.h>
#include <stdlib.h>

using namespace std;
using namespace usipp;

int main(int argc, char **argv)
{

	if (argc < 2) {
		cout<<argv[0]<<" [src] [dst]\n";
		exit(1);
	}
	IPComp4 ipc(argv[2]);
	ipc.set_src(argv[1]);

	ipc.set_cpi(numbers::ipcomp_lzs);
	ipc.set_next(numbers::ipproto_udp);
       	ipc.sendpack("\xff\xff");

        return 0;
}
