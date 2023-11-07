import argparse
import logging
import logging.handlers
import os
import select
import socket
import struct
import sys
import time
import traceback

__version__ = "0.1"

u32 = struct.Struct("!I")
ip_header = struct.Struct("!BBHHHBBHII")
udp_header = struct.Struct("!HHHH")

def udp_packet(srcaddr, srcport, dstaddr, dstport, payload):
    header_length = ip_header.size + udp_header.size
    packet = bytearray([0] * header_length)
    packet.extend(payload)
    
    ip_header.pack_into(packet, 0,
        0x45, 0x00, header_length + len(payload),
        0x0000, 0x0000,
        0x01, 0x11, 0x0000,
        u32.unpack(socket.inet_aton(srcaddr))[0],
        u32.unpack(socket.inet_aton(dstaddr))[0])

    udp_header.pack_into(packet, ip_header.size,
        srcport, dstport, udp_header.size + len(payload), 0)

    return packet

def proxy(listen_ifnames, broadcast_ifnames):
    poll = select.poll()

    listeners = {}
    for ifname in listen_ifnames:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, 25, ifname + "\0")
        s.bind(("", 10001))
        fd = s.fileno()
        poll.register(fd, select.POLLIN)
        listeners[fd] = (ifname, s)
    
    broadcasters = []
    for ifname in broadcast_ifnames:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.SOL_SOCKET, 25, ifname + "\0")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        broadcasters.append((ifname, s))

    addr_ifname = {}
    while True:
        for fd, event in  poll.poll():
            if event == select.POLLIN:
                srcifname, s = listeners[fd]
                payload, (srcaddr, srcport) = s.recvfrom(1024)
                logging.debug("discovery from %s:%s:%d",
                    srcifname, srcaddr, srcport)

                if srcaddr not in addr_ifname:
                    addr_ifname[srcaddr] = srcifname
                elif srcifname != addr_ifname[srcaddr]:
                    continue

                packet = udp_packet(srcaddr, srcport,
                    "255.255.255.255", 10001, payload)
                for dstifname, s in broadcasters:
                    if dstifname  == srcifname:
                        continue
                    logging.debug("broadcasting to %s", dstifname)
                    s.sendto(packet, ("255.255.255.255", 0))

def daemonize():
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.chdir("/")
    os.setsid()
    os.umask(022)

    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    with open("/dev/null", "r") as f:
        os.dup2(f.fileno(), sys.stdin.fileno())

    with open("/dev/null", "w") as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())

def main():
    parser = argparse.ArgumentParser(
        description = "Proxy Ubiquiti discovery requests.")
    parser.add_argument("--debug", action="store_true",
        help = "run in foreground and produce debug output")
    parser.add_argument("--version", action="version", version = __version__,
        help = "print version number")
    parser.add_argument("--listen", metavar = "IFNAME", action = "append",
        help = "only listen on this interface")
    parser.add_argument("--broadcast", metavar = "IFNAME", action = "append",
        help = "only broadcast to this interface")
    parser.add_argument("ifnames", nargs="+", metavar = "IFNAME",
        help = "both listen to and broadcast on these interfaces")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(stream = sys.stdout,
            format = "%(asctime)s: %(levelname)s: %(message)s",
            level = logging.DEBUG)
    else:
        logger = logging.getLogger()
        formatter = logging.Formatter("ubnt-discover-proxy: %(levelname)s: %(message)s")
        handler = logging.handlers.SysLogHandler(address = "/dev/log")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        daemonize()

    try:
        logging.info("starting")
        ifnames = args.ifnames or []
        listen_ifnames = args.listen or []
        broadcast_ifnames = args.broadcast or []
        proxy(ifnames + listen_ifnames, ifnames + broadcast_ifnames)
    except Exception as e:
        logging.critical("terminating: %s", str(e))
        if args.debug:
            raise

if __name__ == '__main__':
    sys.exit(main())
