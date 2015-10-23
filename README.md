USI++ README
============

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=9MVF8BRMX2CWA)

0. About
--------

usi++ (UNIX Socket Interface) is a low-level network-library for sending/receiving
IP, IP6, ARP etc. packets directly on RAW or PACKET sockets. It can also be used for
network-monitoring and rapid development of pentesting tools. It requires `libpcap`
and `libdnet` if you want the Layer2 DNET provider.


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


    # c++ -std=c++11 foo.cc -lusi++ -lpcap -L/usr/local/lib -I/usr/local/include


If you compiled usi++ with _dnet_ support, which allows you to also
send packets at the datalink layer (not just RAW sockets), you also need to
link against `-ldnet`. Newer _libpcap_ may already contain `pcap_inject()` so
you can also build usi++ without _libdnet_, as this function also
provides a portable way to send datalink frames.


4. Function-description
-----------------------

Please look at the HTML-documentation (generated via doxygen) of `libusi++` or at the samples.


5. Supported Platforms
----------------------

Linux, BSD, OSX.


6. BUGS/TODO
------------

None.


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


