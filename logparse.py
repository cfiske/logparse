#!/usr/bin/env python

import re, time
from datetime import datetime


def validDate(datestring):
    try:
        datetime.strptime(datestring, "%b %d %H:%M:%S")
        return True
    except ValueError:
        print "%s is not a valid datetime" % datestring
        return False

with open("/dev/stdin") as f:
    pats = {}

    pats['pri'] = [re.compile(r'<(?P<pri>\d{1,3})>(?P<space>\s?)\w+')]

    # Date/time
    datestrings = [r'\w+ [ \d]?\d \d\d:\d\d:\d\d [A-Z]{3}:', r'\w+ [ \d]?\d \d\d:\d\d:\d\d']
    #datestrings = [r'\w+ [ \d]?\d \d\d:\d\d:\d\d']
    pats['date'] = []
    for i in datestrings:
        pats['date'].append(re.compile(r'(?P<date>' + i + r')(?P<space>\s+)\S+'))

    # Host/IP
    hoststrings = [r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r'[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.[a-z]+)', r'[a-z0-9_-]+']
    pats['host'] = []
    for i in hoststrings:
        pats['host'].append(re.compile(r'(?P<host>' + i + r')(?P<space>\s+)\S+'))

    # Rest of line
    pats['text'] = [re.compile(r'(?P<text>\S.*)(?P<space>\s*)$')]

    currentDict = {}

    for line in f:
        line.rstrip()

        # This -may- be a dangerous assumption, but anything starting with
        # a space is typically a continuation of the previous line
        if line[0].isspace():
            if currentDict:
                currentDict["text"] += ' ' + line.lstrip()
                continue

        line = '<123>' + line

        skip = 0
        for pname in ['pri', 'date', 'host', 'text']:
            #print "checking %s" % pname
            for p in pats[pname]:
                matched = p.match(line)
                if matched:
                    if pname == 'pri':
                        if currentDict:
                            print currentDict
                            currentDict = {}

                    if pname == 'date':
                        if not validDate(matched.group('date')):
                            currentDict['date'] = time.strftime("%b %d %H:%M:%S", time.gmtime())

                    if pname == 'host' and matched.group(pname).startswith('v-webapp'):
                        #print "skipping %s" % matched.group('host')
                        skip = 1
                        currentDict = {}
                        break

                    if pname == 'pri':
                        currentDict['severity'] = int(matched.group('pri')) & 7
                        currentDict['facility'] = int(matched.group('pri')) >> 3

                    currentDict[pname] = matched.group(pname)

                    #print "line: %s" % line

#                    if pname != 'text':
                        # Lop off what we've already processed
                    line = line[matched.end('space'):]

                    #currentDict = {"tag": matched.group('pri'), "date": matched.group('date'), "host": matched.group('host'), "text": matched.group('text'), "severity": logsev, "facility": logfac}
#                else:
#                    print "did not match %s: %s" % (pname, line)
            else:
                continue
            break

        if skip == 0:
            if len(line) > 0:
                print "still some line left: %s" % line

            if currentDict == {}:
                print "matched nothing: %s" % line
                if currentDict:
                    print currentDict
                    currentDict = {}

