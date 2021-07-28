pppoe-serial-bridge
===================

This program implements a bridge between PPP over Ethernet and serial
PPP.

The intended application is making serial modems (eg. 3G/4G USB sticks
that appear as serial devices) available as PPPoE access
concentrators.

(In the particular application I wrote this for, the servers making
use of the modems are in cellars where there is very little 3G/4G
signal; the modems are plugged into Raspberry PIs running off
power-over-ethernet in places where there is a better signal.)

The bridge is very naïve; it doesn't understand PPP at all and just
forwards the frames between the modem and the PPPoE client. In
particular, if the modem tries to request any of the options forbidden
in RFC2516 (FCS Alternatives, Address-and-Control-Field-Compression
and Asynchronous-Control-Character-Map) it is relying on the client to
Nak these requests. This appears to work in practice!

Dependencies
------------

Requires python 3.8, for some of the type annotations.

Requires [pyserial](https://pypi.org/project/pyserial/) and
[netifaces](https://pypi.org/project/netifaces/).

If a chatscript is required to get the modem ready to talk ppp, `chat`
must be installed in `/usr/sbin/chat`. On Debian-derived distributions
this is provided by the `ppp` package.

Running
-------

The program needs to be run with sufficient privilege to open raw
Ethernet sockets (CAP_NET_RAW), and of course must also have
permission to open the serial device.

Run as:
```
pppoe-serial-bridge.py \
   --ac-name=name-of-access-concentrator \
   --chatscript=/path/to/chatscript \
   /path/to/serial/device service-name interface-name
```

Compatibility
-------------

This program currently only runs on Linux.

Known issues
------------

Currently the program uses lots of immutable bytes() objects that will
put a lot of pressure on the memory allocator and garbage
collector. It should probably be using preallocated mutable
bytearray() objects instead.

The program will block while waiting for the chatscript to
complete. `chat` should be run in the background instead. (More of an
issue: PPPoE doesn't really have a "please wait while I connect you"
facility. The client will keep sending PADR packets until it receives
a PADS, but will give up and go back to sending PADI packets after not
very long. If we wait for the chatscript to complete before sending
the PADS, it might be too late and the client might have stopped
listening for it. If we send the PADS while the chatscript is still
running, the client will start talking PPP at us and we can't really
do much apart from throw the PPP frames away until the chatscript
completes. Eventually it will get fed up and send us a PADT and we're
right back at the beginning. Fortunately, with 3G/4G modems the
chatscript seems to complete almost instantly, and then the modem does
strange PPP-level stuff to tell the client to back off for a while,
while it actually completes the connection.)

The byte-stuffing and FCS functions should be combined and implemented
using something like cython for efficiency.

There's support in the code for the access concentrator to offer
multiple service names, but there's no configuration support for this
yet. If implemented, the command line would have to become a lot more
complicated or a config file would have to be supported.

Logging is very basic and only to stdout for now.

Contributing
------------

All contributions are welcome. See [the project at
github](https://github.com/sde1000/pppoe-serial-bridge) for issue
tracker and pull requests.

Please ensure that the program continues to pass
[flake8](https://pypi.org/project/flake8/) and [mypy
--strict](https://github.com/python/mypy) before creating a pull
request.

Copying
-------

pppoe-serial-bridge is Copyright (C) 2021 Stephen Early <steve@assorted.org.uk>

It is distributed under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see [this link](http://www.gnu.org/licenses/).
