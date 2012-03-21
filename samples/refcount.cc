// c++ refcount.cc -lusi++ -ldnet -lpcap
#include <iostream>
#include <string>
#include <usi++/usi++.h>


using namespace std;
using namespace usipp;

int main()
{
	ref_count<std::string> r1(new string("foo"));
	ref_count<std::string> r2 = r1;
	ref_count<std::string> r3(new string("bar"));
	r3 = r2;


	cerr<<r1->c_str()<<endl<<r2->c_str()<<endl<<r2.use()<<endl<<r3->c_str()<<endl;
	return 0;
}

