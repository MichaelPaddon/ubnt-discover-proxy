# ubnt-discover-proxy

This is a simple proxy for relaying broadcast Ubiquiti discovery packets
(UDP port 10001) onto another network.

This code targets Python 2.7. It can run standalone on
EdgeOS version 2 devices.

## Quick Start

If you have devices on eth0 and eth1,
the command:

    # python ubnt-discover-proxy.py eth0 eth1

will listen for discovery packets broadcast on either network and rebroadcast
them to the other network.

Sometimes you can only listen and not broadcast to an interface.
For instance, if you also have devices on wg0, the command:

    # python ubnt-discover-proxy.py --listen wg0 eth0 eth1

will listen for broadcasts on wg0 but never broadcast to it.

## Usage

    usage: ubnt-discover-proxy.py [-h] [--debug] [--version] [--listen IFNAME]
                              [--broadcast IFNAME]
                              IFNAME [IFNAME ...]

    Proxy Ubiquiti discovery requests.

    positional arguments:
      IFNAME              both listen to and broadcast on these interfaces

    optional arguments:
      -h, --help          show this help message and exit
      --debug             run in foreground and produce debug output
      --version           print version number
      --listen IFNAME     only listen on this interface
      --broadcast IFNAME  only broadcast to this interface

## Limitations

The proxy learns which interface each address is on.
Therefore, if you reconfigure your network addressing, you will
need to restart the proxy.
