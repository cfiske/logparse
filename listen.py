#!/usr/bin/env python

from select import select
import sys, getopt, socket

opts, args = getopt.getopt(sys.argv[1:], "av")

verbose = 0

for o, a in opts:
    if o == '-v':
        verbose = 1

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind(('', 514))


packets = 0

while True:
    inready, outready, excready = select([sock], [], [])

    for s in inready:
        data, src_ip = s.recvfrom(8192)
        packets += 1
        if verbose == 1:
            print "Host: %s Data: %s" % (src_ip, data)
        else:
            print "%s" % (data)

    if verbose == 1 and not packets % 1000:
        print "%d packets received" % (packets)
