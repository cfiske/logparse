#!/usr/bin/env python

from select import select
import sys, getopt, socket

opts, args = getopt.getopt(sys.argv[1:], "av")

verbose = 0

for o, a in opts:
    if o == '-v':
        verbose = 1

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(0)
sock.bind(('', 514))


packets = 0
ptotal = 0
plist = []

while True:
    try:
        data, (src_ip, port) = sock.recvfrom(8192)
        plist.append((data, src_ip, port))
        packets += 1
    except socket.error:
        if len(plist) > 0:
            print "Read %d (%d) packets" % (len(plist), packets)
            ptotal += len(plist)
            plist = []
        if verbose == 1:
            print "Host: %s Data: %s" % (src_ip, data)

    if packets > 0 and not packets % 1000:
        print "%d (%d) packets received" % (ptotal, packets)
