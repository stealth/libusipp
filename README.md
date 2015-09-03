USI++ README
============

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=9MVF8BRMX2CWA)

0. About
--------

usi++ (UNIX Socket Interface) is a low-level network-library for sending/receiving
IP, IP6, ARP etc. packets directly on RAW or PACKET sockets. It can also be used for
network-monitoring and rapid development of pentesting tools.

Since version 1.2 it uses the packet capture library libpcap.

To get the latest libpcap with full linux-features, you should visit

http://www.tcpdump.org

1. License
----------

usi++ comes under the GPL. See file COPYING for more
details.

A data-file for ethernet-MAC's is included. It was taken from
arpwatch.

Since USI++ is GPL there is ABSOLUTELY NO WARRANTY. YOU USE IT AT YOUR OWN RISK.

2. Install
----------


    $ autoconf
    $ ./configure
    $ make
    # make install


3. Compiling the examples
-------------------------

Usually like this:

    # c++ -std=c++11 foo.cc -lusi++ -lpcap

If you compiled usi++ with dnet support, which allows you to also
send packets at the datalink layer (not just RAW sockets), you also need to
link against -ldnet.


4. Function-description
-----------------------

Please look at the HTML-documentation of `libusi++` or at the samples.


5. Supported Platforms
----------------------

To make usi++ work properly on new Linux 2.4 kernels,
make sure you disable 'connection tracking' in kernel.
At best you compile connection tracking (if you need it for NAT)
as modules and remove them when playing with usi++.
This is because connection tracking forbids to send arbitrary
TCP or ICMP packets which don't belong to any connection.


6. BUGS/TODO
------------

The TCP-options are alpha-state. I need to play around with different
(little/big-endian) systems to figure out complete behaivior.

The STL-headerfiles shipped with redhat 6.x and freeBSD 3.3 are broken (g++3).
If you get compiler-errors when compiling ip.cc that tell you that there is
a mess with stl_alloc.h, you can copy the fixed stl_alloc.h (directory fix)
to the specified dir.


7. Background for Layer 2
-------------------------

The linklevel handling has changed. Now all classes are derived from
Layer2 {} which contains a RX and a TX object which are used for
receiving and transmitting data. The class-declarations can be found
in the coresponding .h files. These classes are abstract, this means
you must derive your own to get it working. Look at the .h files
which functions you must implemet. USI++ ships with the classes
`Pcap`, `TX_IP`, `TX_eth_dnet` etc which let you capture/send packets. They give you
basic functionality so that you can use programs that work with USI++ 1.67 or
lower as normal.
By making `RX` and `TX` abstract we make sure that `Layer2` can access
routines such as `sendpack()`. You are free to write your own RX/TX based
classes for different hardware (FDDI,...). You can change RX/TX behaivior at runtime,
so it is as flexible as possible. For example you could detect that you are
working with PPP and then you load PPP transimitter.
Have fun.


