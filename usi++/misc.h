#ifndef usipp_misc_h
#define usipp_misc_h

#include <string>

namespace usipp {

extern unsigned short in_cksum(unsigned short *ptr, int len, bool may_pad);
extern std::string mac2bin(const std::string &);
extern std::string bin2mac(const std::string &);


}

#endif

