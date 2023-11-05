 # ubnt-discover-proxy

This is a simple proxy for relaying broadcast Ubiquiti discovery packets
(UDP port 10001) onto another network.


This code targets Python 2.7. It can run standalone on
EdgeOS version 2 devices.

## Quick Start

If your cloudkey is on eth0 and your clients are on eth1 and eth2,
the command:

    # python ubnt-discover-proxy.py --listen eth1 eth2 --broadcast eth0

will proxy discovery packets broadcast on eth1 and eth2 onto eth0.

## Usage

    usage: ubnt-discover-proxy.py [-h] [--debug] [--listen IFNAME [IFNAME ...]]
                          [--broadcast IFNAME [IFNAME ...]]

    Proxy Ubiquiti discovery requests.

    optional arguments:
    -h, --help            show this help message and exit
    --debug
    --listen IFNAME [IFNAME ...]
                          interfaces to listen on
    --broadcast IFNAME [IFNAME ...]
                          interfaces to broadcast to
