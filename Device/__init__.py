import re

class Device(object):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Generic'
        self.logPatterns = {}

    def getName(self):
        return self.name

    def getVendor(self):
        return self.vendor

    def matchLogPattern(self, message):
        for p in self.logPatterns:
            matched = p.match(message['message'])

            if matched:
                pattern = self.logPatterns[p]
                if self.verbose is True:
                    print "matched pattern id %s with text: %s" % (pattern['id'], message['message'])

                # Add the fields defined in the default pattern spec
                for k in pattern:
                    message[k] = pattern[k]

                # Add any fields named in the regex for this pattern
                for k in p.groupindex:
                    message[k] = matched.group(k)

                # Matched, so no need to keep looking
                return 1

        return 0

    def getLogPatterns(self):
        return self.logPatterns

    # Log patterns for parser matching
    # - msg_id = Unique-per-class message identifier tag
    # - msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
    #               'ignore' means the message will be discarded unprocessed
    # - msg_ttl = For stateless messages, indicates message is only valid
    #             for msg_ttl seconds
    # - msg_keys = List of message tokens which make up the instance key
    #
    # If 'pattern' is a list, multiple patterns can be matched with the same
    # criteria (if 2 different messages are equivalent in meaning)
    #
    # The unique message key will be comprised of:
    # [(vendor + msg_id), msg_state, msg_keys]
    def addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):

        # Compiled patterns list
        cpatterns = []

        if isinstance(pattern, list) and len(pattern) > 0:
            for p in pattern:
                cpatterns.append(re.compile(p))
        elif isinstance(pattern, str) and len(pattern) > 0:
            cpatterns.append(re.compile(pattern))
        else:
            print "error: pattern must not be empty or blank. skipping"
            return 0

        if isinstance(msg_id, (str, int)):
            msg_id = self.vendor + '-' + str(msg_id)
        else:
            print "error: msg_id must be type str or int. skipping: %s" % (pattern)
            return 0

        if not isinstance(msg_state, int):
            print "warning: msg_state must be type int. defaulting to stateless: %s" % (pattern)
            msg_state = 3

        if not isinstance(msg_ttl, int):
            print "warning: msg_ttl must be type int. defaulting to 0: %s" % (pattern)
            msg_ttl = 0

        if not isinstance(msg_keys, list):
            print "warning: msg_keys must be type list. defaulting to empty: %s" % (pattern)
            msg_keys = []

        pattern_dict = {}
        pattern_dict['id'] = msg_id
        pattern_dict['state'] = msg_state
        pattern_dict['ttl'] = msg_ttl
        pattern_dict['key_fields'] = msg_keys

        for cp in cpatterns:
            if cp in self.logPatterns:
                print "warning: duplicate pattern. skipping: (%s) %s" % (self.logPatterns[cp]['id'], pattern)
            else:
                self.logPatterns[cp] = pattern_dict

        return 1


class A10(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'A10'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>HMON)\]<\d+> (partition-id<\d+> <\S+> )?SLB server (?P<instance>\S+) \(\d+\.\d+\.\d+\.\d+\) ((TCP|UDP) )?port (?P<port>\d+) (of group (?P<group>\S+) )?is (down|disabled)', 100, 2, 0, ['group','instance','port'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>HMON)\]<\d+> (partition-id<\d+> <\S+> )?SLB server (?P<instance>\S+) \(\d+\.\d+\.\d+\.\d+\) ((TCP|UDP) )?port (?P<port>\d+) (of group (?P<group>\S+) )?is up', 100, 1, 0, ['group','instance','port'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>HMON)\]<\d+> (partition-id<\d+> <\S+> )?SLB server (?P<instance>\S+) \(\d+\.\d+\.\d+\.\d+\) is down', 101, 2, 0, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>HMON)\]<\d+> (partition-id<\d+> <\S+> )?SLB server (?P<instance>\S+) \(\d+\.\d+\.\d+\.\d+\) is up', 101, 1, 0, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>GSLB)\]<\d+> (partition-id<\d+> <\S+> )?GSLB Server - (?P<instance>\S+) \(\d+\.\d+\.\d+\.\d+\) changes state from Up to \S+', 102, 2, 0, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>GSLB)\]<\d+> (partition-id<\d+> <\S+> )?GSLB Server - (?P<instance>\S+) \(\d+\.\d+\.\d+\.\d+\) changes state from \S+ to Up', 102, 1, 0, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>ACOS)\]<\d+> (partition-id<\d+> <\S+> )?Service (?P<service>\S+) on virtual [Ss]erver (?P<instance>\S+) port (?P<port>\d+) is down', 103, 2, 0, ['instance','service','port'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>ACOS)\]<\d+> (partition-id<\d+> <\S+> )?Service (?P<service>\S+) on virtual [Ss]erver (?P<instance>\S+) port (?P<port>\d+) is up', 103, 1, 0, ['instance','service','port'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>ACOS)\]<\d+> (partition-id<\d+> <\S+> )?Virtual server (?P<instance>\S+) is down', 104, 2, 0, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>ACOS)\]<\d+> (partition-id<\d+> <\S+> )?Virtual server (?P<instance>\S+) is up', 104, 1, 0, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>HMON)\]<\d+> (partition-id<\d+> <\S+> )?Service-group (?P<instance>\S+) is down', 105, 2, 0, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>HMON)\]<\d+> (partition-id<\d+> <\S+> )?Service-group (?P<instance>\S+) is up', 105, 1, 0, ['instance'])

        self.addLogPattern(r'^a10logd: \[(?P<msg_type>MGMT)\]<\d+> Certificate file (?P<instance>\S+) (is going to|has) expired?', 204, 3, 0, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>MGMT)\]<\d+> Certificate check failed\. Send Email failed', 205, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>MGMT)\]<\d+> Certificate check finished successfully', 206, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>ACOS)\]<\d+> HTTP header \(len=\d+\) .+ is too long', 207, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>ACOS)\]<\d+> HTTP request contains more than \d+ headers', 208, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>ACOS)\]<\d+> Invalid HTTP header \(len=\d+\)', 209, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>ACOS)\]<\d+> HTTP line too long \(len is \d+\)', 210, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>ACOS)\]<\d+> Station movement threshold of \d+ per second on VLAN (?P<vlan>\d+) has exceeded', 211, 0, 600, ['vlan'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SSL)\]<\d+> enc buff should be \d+ during handshake', 212, 0, 600, [])

        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> NTP server (?P<instance>\S+) is in (polling state|sync with system)', 300, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> Session ID \d+ (for user \"(?P<user>\S+)\" from \S+ )?(is now closed|has timed out)', 301, 0, 600, ['user'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> Local authentication failed\(user: (?P<user>\S+)\): ', 302, 0, 600, ['user'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> The user, (?P<user>\S+), from the remote host, \S+, failed in the (CLI|web) authentication.', 302, 0, 600, ['user'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> Tacacs\+ authentication failed\(user: (?P<user>\S+)\): ', 302, 0, 600, ['user'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> A (cli|web) session for user \"(?P<user>\S+)\" from \S+ has been opened', 303, 0, 600, ['user'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>CLI)\]<\d+> FIPS mode has been set in rimacli', 304, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>CLI)\]<\d+> handler signal \S+', 305, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> Control CPU Usage is over threshold limit\(\d+\)', 306, 2, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> Control CPU Usage is OK\.', 306, 1, 600, [])

        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> Error receiving TACACS\+ \S+ RESPONSE from server (?P<instance>\S+): ', 308, 0, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> Connection error with TACACS\+ server (?P<instance>\S+): ', 309, 0, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> Contact with tacplus server failed', 309, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> tacplus authen (state:|msg=)', 310, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> System Temperature \d+ is (over|under) threshold limit\(\d+\)', 311, 2, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> System Temperature \d+ is OK\.', 311, 1, 600, [])

        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> Running configuration successfully saved', 313, 0, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>SYSTEM)\]<\d+> User \"(?P<user>\S+)\" with session ID \d+ successfully saved the running configuration', 313, 0, 600, ['user'])

        self.addLogPattern(r'^a10logd: \[(?P<msg_type>AXMON)\]<\d+> Enabled load-sharing on packets to data CPU \d+', 400, 2, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>AXMON)\]<\d+> Stopped load-sharing on packets to data CPU \d+', 400, 1, 600, [])

        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> Established connection from vBlade (?P<instance>\S+):\d+', 402, 3, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> (vBlade h|H)andshake completed( with vBlade (?P<instance>\S+):\d+)?', 403, 3, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> Handshake successful', 403, 3, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> peer closed connection prematurely', 404, 3, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> (vBlade (?P<instance>\d+), )?handshake successful', 405, 3, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> (vBlade (?P<instance>\d+), )?handshake, (received?|send) (\d+ )?msg', 406, 0, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> vBlade\(device (?P<instance>\d+)\) is gone', 407, 3, 0, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> vBlade thread stopped', 408, 3, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> vBlade thread: peer gone, reconnect', 409, 3, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> vBlade daemon SIGALRM is not blocked', 410, 3, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> vMaster\(device (?P<instance>\d+)\) is gone:lack of heartbeats', 411, 3, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> Choosing device (?P<instance>\d+) as vMaster', 412, 3, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> Enter vBlade state', 413, 3, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> Enter vMaster state', 414, 3, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> Enter vMaster-Candidate state', 415, 3, 600, [])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> Giving up vMastership to device (?P<instance>\d+)', 415, 3, 600, ['instance'])
        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VCS)\]<\d+> Try to connect vMaster \S+:\d+ from vBlade', 416, 3, 600, [])

        self.addLogPattern(r'^a10logd: \[(?P<msg_type>VPN)\]<\d+> IPSec tunnel (?P<instance>\d+) update SA,', 500, 0, 600, [])


class Arista(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Arista'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^XcvrAgent: %(?P<msg_type>TRANSCEIVER-4-AUTHENTICATION_PROTOCOL_FAILED): The transceiver for interface (?P<port>\S+) is not responding as expected during authentication', 100, 0, 600, [])
        self.addLogPattern(r'^Stp: %(?P<msg_type>SPANTREE-4-RXDOT1QPKT): A non-standard IEEE BPDU packet was received and discarded on interface (?P<port>\S+) \(source mac [0-9a-f:]+\)', 101, 3, 0, ['port'])
        self.addLogPattern(r'^PortSec: %(?P<msg_type>ETH-4-HOST_FLAPPING): Host [0-9a-f:]+ in VLAN (?P<vlan>\d+) is flapping between interface \S+ and interface \S+', 102, 3, 0, ['vlan'])
        self.addLogPattern(r'^Lag\+LacpAgent: %(?P<msg_type>LACP-4-(ACTOR|PARTNER)_CHURN): LACP (Actor|Partner) Churn Detected on (?P<port>\S+)', 103, 3, 0, ['port'])

        self.addLogPattern(r'^(?P<msg_type>\S+): last message repeated', 200, 0, 600, [])

        self.addLogPattern(r'^IgmpSnooping: %(?P<msg_type>IGMPSNOOPING-6-NO_IGMP_QUERIER): No IGMP querier detected in VLAN (?P<vlan>\d+). IGMP report received from \S+ on (?P<port>\S+) for \S+', 300, 3, 0, ['vlan','port'])

        self.addLogPattern(r'^Ebra: %(?P<msg_type>LINEPROTO-5-UPDOWN): Line protocol on Interface (?P<port>\S+), changed state to down', 400, 2, 0, ['port'])
        self.addLogPattern(r'^Ebra: %(?P<msg_type>LINEPROTO-5-UPDOWN): Line protocol on Interface (?P<port>\S+), changed state to up', 400, 1, 0, ['port'])

        self.addLogPattern(r'^(?P<msg_type>initblockdev): dosfsck on \S+ \S+ exited with \d+', 500, 0, 600, [])
        self.addLogPattern(r'^SuperServer: %(?P<msg_type>SYS-4-CLI_SCHEDULER_ABORT): Execution of scheduled CLI execution job \'\S+\' was aborted due to an error:', 501, 0, 600, [])


class Brocade(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Brocade'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^ACL: ACL: list (?P<instance>\S+) denied (udp|tcp) \S+\(\S+\)\(Ethernet (?P<port>\S+) \S+\) -> (\S+)\(\S+\)', 100, 0, 600, ['instance'])
        self.addLogPattern(r'^Security: ssh login by (?P<user>\S+) from src IP \S+ to ', 101, 0, 600, ['user'])
        self.addLogPattern(r'^Security: ssh logout by (?P<user>\S+) from src IP \S+ from ', 102, 0, 600, ['user'])
        self.addLogPattern(r'^Security: SSH access by user (?P<user>\S+) from src IP \S+ rejected', 103, 0, 600, ['user'])
        self.addLogPattern(r'^SNMP: Auth\. failure, intruder IP:  \S+', 104, 0, 600, [])

        self.addLogPattern(r'^INFO: port (?P<port>\S+) latched remote fault', 200, 0, 600, ['port'])
        self.addLogPattern(r'^System: Interface ethernet (?P<port>\S+), state down', 201, 2, 0, ['port'])
        self.addLogPattern(r'^System: Interface ethernet (?P<port>\S+), state up', 201, 1, 0, ['port'])
        self.addLogPattern(r'^System: Module (?P<instance>\S+) powered (off|on)', 202, 3, 0, ['instance'])
        self.addLogPattern(r'^System: Set fan speed to .+', 203, 3, 600, [])
        self.addLogPattern(r'^System: Stack unit \d+ Fan speed changed', 203, 3, 600, [])

        self.addLogPattern(r'^RSTP: VLAN VLAN: (?P<vlan>\S+)  Port (?P<port>\S+) - STP State \S+', 200, 0, 600, ['vlan','port'])


class Cisco(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Cisco'
        self.logPatterns = {}


class F5(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'F5'
        self.logPatterns = {}
        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^(notice|info|err|warn|crit) (?P<process>syslog-ng)\[\d+\]: (?P<msg_type>.+);', 100, 3, 600, ['process'])
        self.addLogPattern(r'^(notice|info|err|warn|crit) (?i)(?P<msg_type>crond)\[\d+\]: \((?P<instance>.+)\) \S+ \(', 101, 0, 600, ['instance'])
        self.addLogPattern(r'^(notice|info|err|warn|crit) (?P<msg_type>run-parts)\(\S+\)\[\d+\]: (starting|finished) (?P<instance>\S+)', 101, 0, 600, ['instance'])
        self.addLogPattern(r'^(notice|info|err|warn|crit) (?P<msg_type>tmm\d?)\[\d+\]: Rule (?P<instance>\S+) ', 102, 0, 600, ['instance'])
        self.addLogPattern(r'^(notice|info|err|warn|crit) (tmsh|mcpd)\[\d+\]: \S+: (?P<msg_type>AUDIT) - ', 103, 0, 600, [])
        self.addLogPattern(r'^(notice|info|err|warn|crit) logger: \[(?P<msg_type>\S+)\]', 104, 0, 600, [])


class Force10(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Force10'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^([A-Z]{2}T: )?%[A-Z0-9_-]+: ?\d %KERN-2-INT: (?P<msg_type>soc_l2x_thread): DMA failed:', 100, 3, 600, [])
        self.addLogPattern(r'^([A-Z]{2}T: )?%[A-Z0-9_-]+: ?\d %KERN-2-INT: (?P<msg_type>_soc_xgs3_mem_dma): \S+ failed', 101, 0, 600, [])

        self.addLogPattern(r'^([A-Z]{2}T: )?%[A-Z0-9_-]+: ?\d %(?P<msg_type>IFMGR-5-OSTATE_DN): Changed interface state to down: (?P<port>.+)$', 200, 2, 0, ['port'])
        self.addLogPattern(r'^([A-Z]{2}T: )?%[A-Z0-9_-]+: ?\d %(?P<msg_type>IFMGR-5-OSTATE_UP): Changed interface state to up: (?P<port>.+)$', 200, 1, 0, ['port'])
        self.addLogPattern(r'^([A-Z]{2}T: )?%[A-Z0-9_-]+: ?\d %(?P<msg_type>ARPMGR-6-MAC_CHANGE): IP-4-ADDRMOVE: IP address (?P<instance>\S+) is moved', 201, 3, 0, ['instance'])

        self.addLogPattern(r'^([A-Z]{2}T: )?%[A-Z0-9_-]+: ?\d %(?P<msg_type>CHMGR-2-FAN_SPEED_CHANGE): Fan speed changed to \d %', 300, 0, 600, [])


class Linux(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Linux'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^stats-loader-production: E, \[.+\] ERROR -- : Error while calculating rate: ', 1000, 0, 0, [])
        self.addLogPattern(r'^raptor_production: ', 1001, 0, 0, [])
        self.addLogPattern(r'^CSCOacs_', 1002, 0, 0, [])


class Juniper(Device):

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.vendor = 'Juniper'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^RT_FLOW: (?P<msg_type>RT_FLOW_SESSION_CREATE): session created ', 100, 0, 600, [])
        self.addLogPattern(r'^RT_FLOW: (?P<msg_type>RT_FLOW_SESSION_DENY): session denied ', 101, 0, 600, [])
        self.addLogPattern(r'^RT_FLOW: (?P<msg_type>RT_FLOW_SESSION_CLOSE): session closed ', 102, 0, 600, [])
        self.addLogPattern(r'^RT_FLOW: (?P<msg_type>FLOW_REASSEMBLE_SUCCEED): Packet merged source (?P<source>\S+) destination (?P<destination>\S+) ipid ', 103, 3, 600, ['destination'])
        self.addLogPattern(r'^RT_FLOW: (?P<msg_type>FLOW_REASSEMBLE_FAIL): FCB ageout before all fragments arrive, source (?P<source>\S+) destination (?P<destination>\S+) ipid ', 104, 3, 600, ['destination'])
        self.addLogPattern(r'^junos-alg: (?P<msg_type>RT_ALG_WRN_CFG_NEED): MSRPC ALG detected packet from (?P<source>\S+)/\d+ which need extra policy config ', 105, 3, 600, ['source'])

        self.addLogPattern(r'^/kernel: (?P<msg_type>tcp_auth_ok): Packet from (?P<peer_ip>(\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)):\d{1,5} (unexpectedly has|missing) MD5 digest', 1000, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>jsr_jsm_update_hold_timeo): bucket created for bgp timeout', 1001, 3, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>ex92xx_fib_cnt) \d+', 1002, 3, 600, [])
        self.addLogPattern(r'^/kernel: hw.chassis.startup_time update to \d+', 1003, 0, 600, [])
        self.addLogPattern(r'^/kernel: .*vks.*', 1004, 0, 600, [])
        self.addLogPattern(r'^(/|\(FPC Slot \d+, PIC Slot \d+\) SPC\d+_PIC\d+ )kernel: (?P<msg_type>KERN_ARP_ADDR_CHANGE): arp info overwritten for (?P<instance>\S+) from ', 1005, 0, 600, ['instance'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>MTU) for (?P<instance>\S+) (reduced|increased) ', 1006, 0, 600, ['instance'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>iff_handle_ifa_delete): deletion of address on ', 1007, 0, 600, ['instance'])
        self.addLogPattern(r'^/kernel: : port status changed', 1008, 0, 600, [])

        self.addLogPattern(r'^/kernel: (?P<msg_type>ae_bundlestate_ifd_change): bundle (?P<port>\S+): bundle IFD minimum bandwidth or minimum links not met, .+', 1010, 3, 0, ['port'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>ae_linkstate_ifd_change): MDOWN received for interface (?P<port>\S+), member of (?P<instance>\S+)', 1011, 2, 0, ['port','instance'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>ae_linkstate_ifd_change): MUP received for interface (?P<port>\S+), member of (?P<instance>\S+)', 1011, 1, 0, ['port','instance'])

        self.addLogPattern(r'^/kernel: Percentage memory available\(\d+\)less than threshold\(\d+\s?%\)', 1013, 3, 0, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>jsr_prl_recv_ack_msg)\(\): received PRL ACK message on non-active socket', 1014, 3, 600, [])
        self.addLogPattern(r'^/kernel:  Filter idx: \d+ ifl index \d+ Interface  ?(?P<port>\S+)', 1015, 3, 600, ['port'])
        self.addLogPattern(r'^/kernel:  Packet in FW : [0-9a-f]+', 1016, 3, 600, ['port'])
        self.addLogPattern(r'^/kernel: (?P<port>\S+): get tlv ppfeid \d+', 1017, 3, 0, ['port'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>GENCFG): op \d+ \(.+\) failed; ', 1018, 3, 600, [])
        self.addLogPattern(r'^/kernel: (?P<process>exec_elf32_imgact): Running BTLB binary without the BTLB_FLAG env set', 1019, 0, 600, ['process'])
        self.addLogPattern(r'^/kernel: SMB read failed addr .+', 1020, 0, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>veriexec): fingerprint for dev \S+, file \S+', 1021, 0, 600, [])
        self.addLogPattern(r'^/kernel: (?P<process>PCF8584)\((RD|WR)\): \S+', 1022, 0, 600, [])
        self.addLogPattern(r'^/kernel: pointchange for TLV type \S+ opcode \S+ not supported', 1023, 0, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>KERN_ARP_ADDR_CHANGE): \S+ info overwritten for \S+ from \S+ to \S+', 1024, 0, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>KERN_ARP_DUPLICATE_ADDR): duplicate IP address \S+! sent from address: \S+', 1025, 3, 600, [])
        self.addLogPattern(r'^/kernel: Filter Already exist in hardware', 1026, 0, 600, [])
        self.addLogPattern(r'^init: (?P<msg_type>\S+) \(PID \d+\) exited', 1027, 2, 600, [])
        self.addLogPattern(r'^init: (?P<msg_type>\S+) \(PID \d+\) started', 1027, 1, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>KERN_LACP_INTF_STATE_CHANGE): lacp_update_state_userspace: cifd (?P<port>\S+) - (?P<portstate>(DETACHED|ATTACHED)) state - .+', 1028, 2, 0, ['port'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>KERN_LACP_INTF_STATE_CHANGE): lacp_update_state_userspace: cifd (?P<port>\S+) - (?P<portstate>CD state) - .+', 1028, 1, 0, ['port'])

        self.addLogPattern(r'^master failed to clean up hw entry', 1100, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>dfwc|cosd)(\[\d{1,5}\])?: waiting for lock, Process', 1101, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>dfwc|cosd)(\[\d{1,5}\])?: lock acquired by ', 1102, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>dfwc|cosd)(\[\d{1,5}\])?: Failed to get mapping from kernel blob ', 1103, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>dfwc|cosd)(\[\d{1,5}\])?: dfwlib_pm_sem_release: PID<\d+> released the lock', 1104, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>flowd_octeon_hm): flowd_srx_i2c_read: (Failed r|R)eading i2c data, dev \S+ group \S+', 1105, 0, 600, [])

        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CHILD_START): .* \'(?P<process>.+)\'', 3000, 0, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CHILD_STATUS): .* \'(?P<process>.+)\', .*', 3001, 0, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CMDLINE_READ_LINE): User \'(?P<user>.+)\', command \'(?P<command>[^\']+)', 3002, 3, 600, ['user','command'])
        self.addLogPattern(r'^sshd: (?P<msg_type>SSHD_LOGIN_FAILED): Login failed for user \'(?P<user>\S+)\' from ', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: error: PAM: authentication error for (?P<user>\S+) from ', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Failed password for (?P<user>\S+) from ', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^sshd: (?P<msg_type>SSHD_LOGIN_ATTEMPTS_THRESHOLD): Threshold for unsuccessful authentication attempts \(\d+\) reached by user \'(?P<user>\S+)\'', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_AUTH_EVENT): Authenticated user \'(?P<user>\S+)\' at ', 3004, 2, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Accepted \S+ for (?P<user>\S+) from ', 3004, 2, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_LOGIN_EVENT): User \'(?P<user>[^\']+)\' login, class ', 3004, 2, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_LOGOUT_EVENT): User \'(?P<user>[^\']+)\' logout', 3004, 1, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_JUNOSCRIPT_CMD): User \'(?P<user>[^\']+)\' used JUNOScript client to run command \'(?P<command>[^\']+)', 3006, 3, 600, ['user','command'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_NETCONF_CMD): User \'(?P<user>[^\']+)\' used NETCONF client to run command \'(?P<command>[^\']+)', 3007, 3, 600, ['user','command'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_DBASE_LOGIN_EVENT): User \'(?P<user>[^\']+)\' entering configuration mode', 3008, 2, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_DBASE_LOGOUT_EVENT): User \'(?P<user>[^\']+)\' exiting configuration mode', 3008, 1, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_COMMIT): User \'(?P<user>[^\']+)\' requested \'commit\' operation', 3010, 2, 0, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_COMMIT_COMPLETED): commit complete', 3010, 1, 0, [])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_COMMIT_PROGRESS): Commit operation in progress: ', 3011, 3, 600, ['user'])

        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_COMMIT_CONFIRMED_REMINDER): \'commit confirmed\' must be confirmed', 3013, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>UI_CLI_IDLE_TIMEOUT): Idle timeout for user \'(?P<user>[^\']+)\' exceeded and session terminated', 3014, 0, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CFG_AUDIT)_(NEW|SET|OTHER): User \'(?P<user>[^\']+)\' (activate|deactivate|set|update|delete|rename|override|rollback)', 3015, 3, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_OPEN_TIMEOUT): Timeout connecting to peer \'(?P<process>[^\']+)\'', 3016, 3, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_READ_TIMEOUT): Timeout on read of peer \'(?P<process>[^\']+)\'', 3017, 3, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_LOAD_EVENT): User \'(?P<user>[^\']+)\' is performing a ', 3018, 3, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CHILD_STATUS): Cleanup child \'(?P<process>[^\']+)\', PID \d+', 3019, 0, 600, ['process'])
        self.addLogPattern(r'^(mgd|dcd|file)\[\d{1,5}\]: (?P<msg_type>UI_CONFIGURATION_ERROR): Process: (?P<process>[^\']+), path:', 3020, 0, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_LOAD_JUNOS_DEFAULT_FILE_EVENT): Loading the default config from ', 3021, 3, 600, [])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>load-update) (start|done)', 3022, 0, 600, [])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CHILD_SIGNALED): Child received signal: PID \d+, signal .+, command=\'(?P<process>\S*)\'', 3023, 0, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CHILD_EXITED): Child exited: PID \d+, status \d+, command \'(?P<process>[^\']+)\'', 3024, 0, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_COMMIT_NOT_CONFIRMED): Commit was not confirmed;', 3025, 3, 0, [])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_TACPLUS_ERROR): TACACS\+ failure:', 3026, 3, 0, [])
        self.addLogPattern(r'^(?P<process>sshd)(\[\d+\])?: (?P<msg_type>tac_send_authen): Network read error: ', 3027, 0, 600, [])
        self.addLogPattern(r'^(?P<process>sshd)(\[\d+\])?: \((?P<msg_type>pam_sm_authenticate)\): DEBUG: ', 3028, 0, 600, [])
        self.addLogPattern(r'^(?P<process>cli)(\[\d+\])?: (?P<msg_type>login_getclass): ', 3029, 3, 600, [])

        self.addLogPattern(r'^sshd\[\d{1,5}\]: Received disconnect from ', 3058, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Connection closed by ', 3058, 0, 600, [])
        self.addLogPattern(r'^inetd\[\d{1,5}\]: (?P<process>\S+)\[\d{1,5}\]: exited, status \d+', 3058, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<process>inetd)\[\d{1,5}\]: accept \(for \S+\): Software caused connection abort', 3058, 0, 600, ['process'])
        self.addLogPattern(r'^(/usr/sbin/)?(?P<msg_type>cron)\[\d{1,5}\]: \((?P<user>\S+)\) CMD \(\s*(?P<process>\S.*)\)', 3059, 0, 600, ['user','process'])
        self.addLogPattern(r'^ifinfo: pif_get_ifd IFD \S+', 3060, 0, 600, [])
        self.addLogPattern(r'^(gkmd|file): Exit at main \d+', 3061, 0, 600, [])
        self.addLogPattern(r'^autoconfd: shmlog: unable to create argtype:', 3062, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: (?P<msg_type>tac_send_authen): unexpected EOF ', 3063, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: subsystem request for netconf by user (?P<user>.+)', 3064, 0, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: subsystem request for netconf failed, subsystem not found', 3065, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: error: Received disconnect from \S+: ', 3066, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: fatal: Read from socket failed: ', 3066, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Disconnecting: Too many password failures for (?P<user>\S+) ', 3067, 0, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: unlink\(\): failed to delete ', 3068, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Postponed \S+ for \S+ from (?P<host>\S+)', 3069, 0, 600, ['host'])

        self.addLogPattern(r'^jddosd\[\d{1,5}\]: (?P<msg_type>DDOS_PROTOCOL_VIOLATION_SET): Protocol (?P<protocol>.+) is violated at (?P<instance>fpc \d+) for \d+ times', 3067, 2, 0, ['protocol','instance'])
        self.addLogPattern(r'^jddosd\[\d{1,5}\]: (?P<msg_type>DDOS_PROTOCOL_VIOLATION_CLEAR): Protocol (?P<protocol>.+) has returned to normal. Violated at (?P<instance>fpc \d+) for \d+ times', 3067, 1, 0, ['protocol','instance'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFDD_TRAP_SHOP_STATE)_DOWN: local discriminator: \d+, new state: down, interface: (?P<port>\S+), peer addr: (?P<peer_ip>\S+)', 3068, 2, 0, ['port','peer_ip'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFDD_TRAP_SHOP_STATE)_UP: local discriminator: \d+, new state: up, interface: (?P<port>\S+), peer addr: (?P<peer_ip>\S+)', 3068, 1, 0, ['port','peer_ip'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFD Session) (?P<peer_ip>\S+) \(IFL \d+\) state Up -> \S+ LD/RD\(\d+/\d+\)', 3069, 2, 0, ['peer_ip'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFD Session) (?P<peer_ip>\S+) \(IFL \d+\) state \S+ -> Up LD/RD\(\d+/\d+\)', 3069, 1, 0, ['peer_ip'])
        self.addLogPattern(r'^dcd\[\d{1,5}\]: (?P<msg_type>parse_mix_rate_parent_ae) : ifd (?P<instance>\S+) no configured link-speed', 3070, 3, 0, ['instance'])
        self.addLogPattern(r'^/usr/sbin/sampled\[\d{1,5}\]: (?P<process>sampled_read_config): trace_file is 0x[0-9a-f]+, parse_only is \d', 3071, 3, 0, ['process'])
        self.addLogPattern(r'ffp\[\d{1,5}\]: \"dynamic-profiles\": No change to profiles', 3075, 3, 0, [])
        self.addLogPattern(r'^/usr/sbin/sampled\[\d{1,5}\]: (?P<process>sighup_event): trace_file is 0x[0-9a-f]+', 3076, 3, 0, ['process'])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: kernel time sync enabled \d+', 3080, 3, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: kernel time sync status \d+', 3080, 3, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: ntpd \d+\.\d+\.\d+', 3081, 0, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: precision = \d+\.\d+ usec', 3082, 0, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: Listening on interface \S+', 3083, 0, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: frequency initialized \d+\.\d+ PPM', 3084, 0, 600, [])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: synchronized to (?P<peer_ip>\S+), stratum=\d', 3085, 3, 600, ['peer_ip'])
        self.addLogPattern(r'^xntpd(\[\d{1,5}\])?: kernel time sync disabled \d+', 3086, 2, 600, [])
        self.addLogPattern(r'^dcd\[\d{1,5}\]: (?P<msg_type>DCD_PARSE_WARN)_(IDENTICAL_SUBNET|INCOMPATIBLE_CFG): \S+', 3087, 3, 600, [])
        self.addLogPattern(r'^dcd\[\d{1,5}\]: Warning: identical local address', 3087, 3, 600, [])

        self.addLogPattern(r'^pfed: (?P<msg_type>PFED_NOTIF_GLOBAL_STAT_UNKNOWN): Unknown global notification stat:', 3090, 0, 600, [])
        self.addLogPattern(r'^pfed: downward spike received from pfe for ', 3091, 0, 600, [])
        self.addLogPattern(r'^pfed: (?P<msg_type>PFED_NOTIFICATION_STATS_FAILED): Unable to retrieve notification statistics', 3092, 3, 600, [])

        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_TRAP_QUEUED): Adding trap to (?P<instance>\S+) to destination queue', 3100, 0, 0, ['instance'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_SEND_FAILURE): trap_io_send_trap_now: send to \((?P<instance>\S+)\) failure:', 3101, 3, 0, ['instance'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_TRAP_QUEUE_MAX_ATTEMPTS): trap_dq_send_traps: after \d+ attempts, deleting \d+ traps queued to (?P<instance>\S+)', 3102, 3, 0, ['instance'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_AUTH_FAILURE): nsa_(log_community|initial_embedcomm): unauthorized SNMP community from (?P<instance>\S+)', 3103, 3, 0, ['instance'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_AUTH_RESTRICTED_ADDRESS): nsa_initial_callback: request from address (?P<instance>\S+) not allowed', 3103, 3, 0, ['instance'])
        self.addLogPattern(r'^mib2d\[\d{1,5}\]: (?P<msg_type>SNMP_TRAP_LINK_DOWN): ifIndex (?P<ifindex>\d+), ifAdminStatus \S+, ifOperStatus down\(2\), ifName (?P<port>\S+)', 3104, 2, 0, ['ifindex','port'])
        self.addLogPattern(r'^mib2d\[\d{1,5}\]: (?P<msg_type>SNMP_TRAP_LINK_UP): ifIndex (?P<ifindex>\d+), ifAdminStatus \S+, ifOperStatus up\(1\), ifName (?P<port>\S+)', 3104, 1, 0, ['ifindex','port'])

        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>LIBJSNMP_NS_LOG_WARNING): WARNING: AgentX session, \S+, noticed request timeout', 3106, 3, 0, [])
        self.addLogPattern(r'^mib2d\[\d{1,5}\]: (?P<msg_type>LIBJSNMP_NS_LOG_INFO): INFO: ns_subagent_open_session: NET-SNMP version \S+ AgentX subagent connected', 3107, 3, 600, [])
        self.addLogPattern(r'^mib2d\[\d{1,5}\]: (?P<msg_type>LIBJSNMP_NS_LOG_ERR): ERR: snmpd: send_trap: Failure in sendto', 3108, 3, 600, [])

        self.addLogPattern(r'^(?P<msg_type>jl2tpd): jl2tpd: main: \*\*\* jl2tpd running \*\*\*', 3200, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>jl2tpd): jl2tpd: main: L2tp config check instantiation', 3201, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>jl2tpd): L2TP running with debug events enabled', 3202, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>l2cpd)\[\d{1,5}\]: (?P<process>lldp_server_reinit)\(\) reinit server', 3203, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>l2cpd)\[\d{1,5}\]: (?P<process>L2CPD): SNMP Filter Interface configuration success', 3203, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>l2cpd)\[\d{1,5}\]: INFRA var init done so returning', 3204, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>l2cpd)\[\d{1,5}\]: (?P<process>l2cpd) disabling pnac module', 3205, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>l2cpd)\[\d{1,5}\]: INFRA init done so returning', 3206, 0, 600, [])
        self.addLogPattern(r'^(?P<msg_type>l2cpd)\[\d{1,5}\]: task_reconfigure reinitializing done', 3207, 0, 600, ['process'])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: (?P<msg_type>LLDP_NEIGHBOR_DOWN): A neighbor of interface (?P<port>\S+) has gone down\.', 3208, 2, 600, ['port'])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: (?P<msg_type>LLDP_NEIGHBOR_UP): A neighbor has come up for interface (?P<port>\S+)\.', 3208, 1, 600, ['port'])

        self.addLogPattern(r'^(?P<msg_type>chassisd)\[\d{1,5}\]: (?P<process>CHASSISD_BLOWERS_SPEED)_FULL: Fans and impellers being set to full speed', 3210, 2, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>chassisd)\[\d{1,5}\]: (?P<process>CHASSISD_BLOWERS_SPEED)(_MEDIUM)?: Fans and impellers (are now running at normal|being set to intermediate) speed', 3210, 1, 600, ['process'])

        self.addLogPattern(r'^(?P<msg_type>chassisd)\[\d{1,5}\]: (?P<process>fpc_pic_process_pic_power_off_config):\d+ :No FPC in slot (?P<instance>\d+), skipping', 3212, 3, 600, ['process','instance'])
        self.addLogPattern(r'^(?P<msg_type>chassisd)\[\d{1,5}\]: (?P<process>CHASSISD_PARSE_COMPLETE): Using new configuration', 3213, 3, 600, ['process'])
        self.addLogPattern(r'^\S+: invoke-commands: Executed \S+, output to \S+ in text format', 3214, 0, 600, [])
        self.addLogPattern(r'^\S+: transfer-file: Transferred \S+', 3215, 0, 600, [])
        self.addLogPattern(r'^(?P<process>chassisd)\[\d{1,5}\]: (?P<msg_type>CHASSISD_PEM_INPUT_BAD): status failure for power supply (?P<instance>\d+)', 3216, 3, 600, ['instance'])
        self.addLogPattern(r'^(?P<process>chassisd)\[\d{1,5}\]: (?P<msg_type>CHASSISD_SNMP_TRAP\d?): SNMP trap generated: (?P<instance>.+) [Ff]ailed \(', 3217, 0, 600, ['instance'])
        self.addLogPattern(r'^(?P<process>chassisd)\[\d{1,5}\]: (?P<msg_type>CHASSISD_VOLTAGE_SENSOR_INIT): Unable to initialize voltage sensor for (?P<instance>FPC \d+)', 3218, 3, 600, ['instance'])

        self.addLogPattern(r'^lacpd\[\d{1,5}\]: (?P<msg_type>LACPD_TIMEOUT): (?P<port>\S+): lacp current while timer expired', 3300, 3, 600, ['port'])
        self.addLogPattern(r'^lacpd\[\d{1,5}\]: (?P<msg_type>LACP_INTF_DOWN): (?P<port>\S+): Interface marked down', 3301, 3, 600, ['port'])

        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_PATH_BANDWIDTH_CHANGE): MPLS path\s+\(lsp (?P<instance>\S+)\) bandwidth changed, path bandwidth \d+ bps', 4000, 0, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_PATH_DOWN): MPLS path\s+down on LSP (?P<instance>\S+)', 4001, 2, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_PATH_UP): MPLS path\s+up on LSP (?P<instance>\S+) path bandwidth \d+ bps', 4001, 1, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_BANDWIDTH_CHANGE): MPLS LSP (?P<instance>\S+) bandwidth changed, lsp bandwidth \d+ bps', 4100, 0, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_DOWN): MPLS LSP (?P<instance>\S+) down on (?P<path>\S+)', 4101, 2, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_UP): MPLS LSP (?P<instance>\S+) up on (?P<path>\S+) Route ', 4102, 1, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_CHANGE): MPLS LSP (?P<instance>\S+) change on (?P<path>\S+) Route ', 4103, 3, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_RSVP_INCORRECT_FLOWSPEC): Bandwidth in PATH Tspec greater than RESV flowspec for Session: (?P<instance>.+\) Proto \d+) Sender: ', 4104, 3, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_LDP_NBRDOWN): LDP neighbor (?P<instance>\S+) \((?P<port>\S+)\) is down', 4105, 2, 0, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_LDP_NBRUP): LDP neighbor (?P<instance>\S+) \((?P<port>\S+)\) is up', 4105, 1, 0, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_OSPF_NBR(UP|DOWN)): OSPF neighbor (?P<instance>\S+) \(realm ospf-v2 (?P<port>\S+) area \d+\.\d+\.\d+\.\d+\) state changed from \S+ to [^(Full|2Way)]+', 4106, 2, 600, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_OSPF_NBR(UP|DOWN)): OSPF neighbor (?P<instance>\S+) \(realm ospf-v2 (?P<port>\S+) area \d+\.\d+\.\d+\.\d+\) state changed from \S+ to (Full|2Way)', 4106, 1, 600, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_RSVP_NBRDOWN): RSVP neighbor (?P<instance>\S+) down on interface (?P<port>\S+) nbr-type \S+', 4107, 2, 0, ['instance','port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_RSVP_NBRUP): RSVP neighbor (?P<instance>\S+) up on interface (?P<port>\S+) nbr-type \S+', 4107, 1, 0, ['instance','port'])

        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_RT_PATH_LIMIT_REACHED): Number of paths \(\d+\) in table (?P<instance>\S+) still exceeds or equals configured maximum', 4150, 3, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>KRT ADD) for (?P<instance>\S+) => \{ \} failed', 4151, 3, 600, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_KRT_Q_RETRIES): Route (Table )?Update: ', 4152, 3, 600, [])

        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_listen_accept): Connection attempt from unconfigured neighbor: (?P<peer_ip>\S+)\+\d{1,10}', 4200, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_[a-z0-9_]+)(:\d+)?: NOTIFICATION sent to (?P<peer_ip>\S+)\+\d{1,10} \(proto\): code \d+ \(', 4201, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_[a-z0-9_]+)(:\d+)?: NOTIFICATION sent to (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\): code \d+ \(', 4201, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_UNUSABLE_NEXTHOP): bgp_nexthop_sanity: peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\) next hop ', 4202, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_nexthop_sanity): peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\) next hop ', 4202, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_standby_socket_read_internal):\d+: NOTIFICATION received from (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\): code \d+ \(', 4203, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_read_v4_message):\d+: NOTIFICATION received from (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\): code \d+ \(', 4203, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv_open): peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\): received NOTIFICATION code \d+ \(', 4203, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv): peer (?P<peer_ip>\S+)\+\d{1,10} \(proto\): .+', 4204, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv): peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\): .+', 4204, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv): read from peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\) failed: .+', 4204, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (BGP_NO_INCOMING_INTERFACE_FOUND: )?(?P<msg_type>bgp_listen_accept): Connection received from (?P<peer_ip>\S+), .+', 4205, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_pp_recv): dropping (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\), connection collision', 4206, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_pp_recv): rejecting connection from (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\), peer in state ', 4206, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>trace_(on|rotate)): (tracing|rotating)', 4207, 0, 0, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: ((?P<msg_type>BGP_WRITE_WOULD_BLOCK): )?bgp_send: sending \d+ bytes to (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\) blocked', 4208, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_WRITE_FAILED): bgp_send: sending \d+ bytes to (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\) failed', 4209, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_BGP_NEIGHBOR_STATE_CHANGED): BGP peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\) changed state from Established to (?P<peer_state>\S+)', 4210, 2, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_BGP_NEIGHBOR_STATE_CHANGED): BGP peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\) changed state from \S+ to (?P<peer_state>Established)', 4210, 1, 0, ['peer_ip','peer_asn'])

        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_RESET_PENDING_CONNECTION): (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\): reseting pending active connection', 4212, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_PREFIX_THRESH_EXCEEDED): (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\): Configured maximum prefix-limit threshold\(\d+\) exceeded', 4213, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>task_process_events): no write/connect method for BGP(_\d+)?_(?P<peer_asn>\d+)(_|\.)(?P<peer_ip>(\d+\.\d+\.\d+\.\d+|[0-9a-f:]+))\+\d+ socket', 4214, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>[\d\.]{1,11})\): reseting pending active connection', 4215, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>task_connect): (task \S+ )?addr ', 4216, 0, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (BGP_CONNECT_FAILED: )?(?P<msg_type>bgp_connect_start): connect (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\S+)\): ', 4216, 3, 600, ['peer_ip','peer_asn'])

        self.addLogPattern(r'^(rpd|l2cpd)\[\d{1,5}\]: (?P<msg_type>(RPD|JTASK)_TASK_REINIT): Reinitializing', 4250, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>L2CKT) acquiring mastership for primary', 4251, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>L2VPN) acquiring mastership for primary', 4252, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>task_reconfigure) reinitializing done', 4253, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: EVENT <?(MTU)? ?(Delete|Add|Instance)? ?(Flags|SNMP Index)? ?(Bandwidth)? ?(?P<msg_type>UpDown)?>? (?P<port>\S+) index \d+( (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)(/\d+)? -> (zero-len|null|\d+\.\d+\.\d+\.\d+))? <Up( Broadcast)?( PointToPoint)?( Multicast)?( Localup)?>', 4254, 2, 0, ['port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: EVENT <?(MTU)? ?(Delete|Add|Instance)? ?(Flags|SNMP Index)? ?(Bandwidth)? ?(?P<msg_type>UpDown)?>? (?P<port>\S+) index \d+( (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)(/\d+)? -> (zero-len|null|\d+\.\d+\.\d+\.\d+))? <(Broadcast)?( PointToPoint)?( Multicast)?( Localup)?>', 4254, 1, 0, ['port'])

        self.addLogPattern(r'^rpd\[\d{1,5}\]: EVENT <?(?P<msg_type>Bandwidth)?>? (?P<port>\S+) index \d+( (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)/\d+ -> (zero-len|null))? <(Up )?(Broadcast)?( PointToPoint)?( Multicast)?( Localup)?>', 4256, 3, 0, ['port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: \*STP Change\*, notify to other modules', 4257, 0, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: STP handler: (Stp index=\d+|IFD =\S+), op=\S+, state=(Disc|Forw)arding', 4258, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: IF: Skipped marking address (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+) on ifl (?P<port>\S+) as UP', 4259, 3, 600, ['port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>KRT Ifstate): Received IP(v4|v6)? address (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+) on ifl (?P<port>\S+)\.', 4260, 3, 600, ['port'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: Decode ifd (?P<interface>\S+) index \d+: ifdm_flags \S+', 4261, 3, 600, ['interface'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: Synchronized commit processing', 4262, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: Read ddl top handle \S+', 4263, 3, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: task state:  <.+>', 4264, 0, 600, [])

        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\) link \d+) (?P<msg_type>SFP laser) bias current low  (warning|alarm) set', 4300, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\) link \d+) (?P<msg_type>SFP laser) bias current low  (warning|alarm) cleared', 4300, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\)\(\d+\)): (?P<msg_type>SFP\+?) unplugged', 4301, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\)\(\d+\)): (?P<msg_type>SFP\+?) plugged in', 4301, 1, 0, ['instance'])
        self.addLogPattern(r'^\S+ (?P<msg_type>SFP\+?) removed from port (?P<port>\S+)', 4302, 3, 0, ['port'])
        self.addLogPattern(r'^\S+ (?P<msg_type>SFP\+?) found on port (?P<port>\S+)', 4303, 3, 0, ['port'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\) link \d+) (?P<msg_type>SFP (output|receive) power) low  (warning|alarm) set', 4304, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\) link \d+) (?P<msg_type>SFP (output|receive) power) low  (warning|alarm) cleared', 4304, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\) link \d+) (?P<msg_type>SFP syslog throttling): disabling syslogs for ', 4305, 2, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\) link \d+) (?P<msg_type>SFP syslog throttling): enabling syslogs for ', 4305, 1, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\) link \d+) (?P<msg_type>SFP voltage (high|low)) ? alarm set', 4306, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\) link \d+) (?P<msg_type>SFP voltage (high|low)) ? alarm cleared', 4306, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) XMCHIP\(\d+\): XXLCE\d+: Port Alarms: Detected Ethernet MAC Local Fault Delta Event for Port \d+ \((?P<port>\S+)\)', 4307, 2, 0, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) XMCHIP\(\d+\): XXLCE\d+: Port Alarms: Cleared Ethernet MAC Local Fault Delta Event for Port \d+ \((?P<port>\S+)\)', 4307, 1, 0, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) XMCHIP\(\d+\): XXLCE\d+: Port Alarms: Detected Ethernet MAC Remote Fault Delta Event for Port \d+ \((?P<port>\S+)\)', 4308, 2, 0, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) XMCHIP\(\d+\): XXLCE\d+: Port Alarms: Cleared Ethernet MAC Remote Fault Delta Event for Port \d+ \((?P<port>\S+)\)', 4308, 1, 0, ['instance','port'])

        self.addLogPattern(r'^(?P<instance>\S+ JBCM\(\d+/\d+\)):(?P<msg_type>jbcm_sfp_eeprom_read): read sfp eeprom of \S+ failed', 4314, 0, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\)\(\d+\)), (?P<msg_type>SFP\+?) \d+: not Juniper supported', 4315, 0, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>(fpc\d+ C?MIC|\S+ JBCM)\(\d+/\d+\)) (?P<msg_type>SFP\+?) PHY \d+ is de-allocated', 4316, 0, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>vsc8248_firmware_variable_rd_wr): cmic-vsc8248-(\S+): channel:\d+ vsc8248 firmware control register: ', 4317, 0, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>cmic_vsc8248_set_app_mode): error setting app mode for CMIC', 4318, 0, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ CMIC\(\d+/\d+\)\(\d+\)): (?P<msg_type>error) setting', 4319, 0, 600, ['instance'])

        self.addLogPattern(r'^(?P<instance>\S+) Next-hop resolution requests from interface (?P<port>\d+) throttled ', 4400, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>pic_xmchip_wanio_dfe_tuning_op):(?P<port>\S+) - (En|Dis)able DFE (adaptive )?tuning ', 4401, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>cmic_phy_dfe_tuning_state): ?(?P<port>\S+) - DFE coarse/fine tuning completes', 4402, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>PFE_FW_SYSLOG_IP6)_(GEN|ICMP|TCP_UDP): FW: (?P<port>\S+)\s+D \S+ SA \S+', 4403, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>CMT): fpc \d+ hsl type \d+', 4404, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>cmic_plat_dfe_coarse_tuning)_(start|stop): CMIC\(\d+/\d+\) (start|stop) DFE (adaptive )?tuning for (?P<port>\S+)', 4405, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>cmic_vsc8248_ready_for_dfe): CMIC\(\d+/\d+\)\(\d\) - VSC8248 EDC FW unexpectedly in state \d+', 4406, 3, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) SYSLOG: \d+ messages? lost, message queue overflowed', 4407, 3, 600, [])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>PQ3_IIC\(WR\)):', 4408, 3, 0, [])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>mic_i2c_reg_get) - ', 4409, 3, 0, [])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>mic_sfp_phy_read):MIC\(\d+/\d+\) - ', 4409, 3, 0, [])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>mic_sfp_phy_mdio_sgmii_lnk_op): ', 4409, 3, 0, [])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>ifp) (?P<port>\S+) ifd_mdown', 4410, 2, 0, ['port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>mic_mac_periodic):(?P<port>\S+): ifd_mup', 4410, 1, 0, ['port'])

        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>MQchip) \d+ XE \d+ Throttle: ', 4412, 3, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>LBCM-L2,pfe_bcm_l2_mac_add\(\)),\d+:', 4413, 3, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>cmic_optic_check_non_nebs_all): CMIC\(\d+/\d+\) link \d+', 4414, 3, 0, ['instance'])


        self.addLogPattern(r'^\W*last message repeated', 4440, 0, 0, [])

        self.addLogPattern(r'^\(FPC Slot \d+, PIC Slot \d+\) (?P<instance>SPC\d+_PIC\d+) last message repeated \d+ times', 4450, 0, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>\S+) utm_usp_ipc_lic_handler: license state\(\d+\) set', 4451, 0, 600, ['instance'])
        self.addLogPattern(r'^(\(FPC Slot \d+, PIC Slot \d+\) SPC\d+_PIC\d+ )?kmd\[\d{1,5}\]: (?P<msg_type>KMD_PM_SA_ESTABLISHED): Local gateway: \S+, Remote gateway: (?P<instance>\S+),', 4452, 3, 600, ['instance'])
        self.addLogPattern(r'^(\(FPC Slot \d+, PIC Slot \d+\) SPC\d+_PIC\d+ )?kmd\[\d{1,5}\]: (?P<msg_type>KMD_VPN_DOWN_ALARM_USER): VPN (?P<instance>\S+) from \d+\.\d+\.\d+\.\d+ is down\.', 4453, 2, 600, ['instance'])
        self.addLogPattern(r'^(\(FPC Slot \d+, PIC Slot \d+\) SPC\d+_PIC\d+ )?kmd\[\d{1,5}\]: (?P<msg_type>KMD_VPN_UP_ALARM_USER): VPN (?P<instance>\S+) from \d+\.\d+\.\d+\.\d+ is up\.', 4453, 1, 600, ['instance'])
        self.addLogPattern(r'^(\(FPC Slot \d+, PIC Slot \d+\) SPC\d+_PIC\d+ )?kmd\[\d{1,5}\]: (?P<msg_type>IKE negotiation failed) with error: [^\.]+\. IKE Version: \d+, VPN: (?P<instance>\S+) Gateway: ', 4455, 2, 600, ['instance'])
        self.addLogPattern(r'^(\(FPC Slot \d+, PIC Slot \d+\) SPC\d+_PIC\d+ )?kmd\[\d{1,5}\]: (?P<msg_type>IKE Phase-1: \S+ Policy) lookup failed', 4456, 3, 600, [])
        self.addLogPattern(r'^(\(FPC Slot \d+, PIC Slot \d+\) SPC\d+_PIC\d+ )?kmd\[\d{1,5}\]: (?P<msg_type>KMD_VPN_PV_PHASE1): IKE Phase-1 Failure: .+ \[spi=(?P<instance>\S+), src', 4457, 3, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>node\d\.fpc\d+) (?P<msg_type>ipc_msg_write): IPC message type: \d+, subtype: \d+ exceeds MTU', 4458, 3, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>node\d\.fpc\d+) (?P<msg_type>trinity_pio): .+error.+', 4459, 3, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>node\d\.fpc\d+) LUCHIP\(\d+\): pio_handle\(0x[0-9a-f]+\); \S+\(\) failed', 4460, 3, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>node\d\.fpc\d+) LUCHIP\(\d+\) IDMEM\[\d+\] read error', 4461, 3, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>node\d\.cpp\d+ swanhill\d+): XLR flow_held_mbuf \d+, raise above \d+, \d+th time', 4462, 2, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>node\d\.cpp\d+ swanhill\d+): XLR flow_held_mbuf \d+, drop below \d+, exhaustion', 4462, 1, 600, ['instance'])

        self.addLogPattern(r'^(?P<process>eswd)\[\d{1,5}\]: Bridge Address: add [0-9a-f]+:[0-9a-f+]', 4500, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<process>eventd): sendto: No buffer space available', 4501, 0, 600, ['process'])

        self.addLogPattern(r'^PERF_MON: (?P<process>RTPERF_CPU)_THRESHOLD_EXCEEDED: (?P<instance>FPC \d+ PIC \d+) CPU utilization exceeds threshold', 4600, 2, 600, ['process','instance'])
        self.addLogPattern(r'^PERF_MON: (?P<process>RTPERF_CPU)_USAGE_OK: (?P<instance>FPC \d+ PIC \d+) CPU utilization returns to normal', 4600, 1, 600, ['process','instance'])

        self.addLogPattern(r'^(?P<process>\S+)\[\d+\]: (?P<msg_type>LICENSE_EXPIRED_KEY_DELETED): License key "(?P<instance>.+)" has expired', 4700, 3, 600, ['process','instance'])
        self.addLogPattern(r'^(?P<process>\S+)\[\d+\]: (?P<msg_type>LICENSE_EXPIRED): License for feature (?P<instance>\S+) expired', 4701, 3, 600, ['process','instance'])
        self.addLogPattern(r'^(?P<process>alarmd)\[\d+\]: (?P<msg_type>Alarm) set: (?P<instance>.+) color=(?P<color>\S+), class=(?P<alarm>\S+), reason=', 4702, 2, 0, ['process','instance'])
        self.addLogPattern(r'^(?P<process>alarmd)\[\d+\]: (?P<msg_type>Alarm) cleared: (?P<instance>.+) color=(?P<color>\S+), class=(?P<alarm>\S+), reason=', 4702, 1, 0, ['process','instance'])
        self.addLogPattern(r'^(?P<process>craftd)\[\d+\]: \s*(?P<msg_type>\S+ alarm) set, (?P<instance>.+)', 4703, 2, 0, ['process','instance'])
        self.addLogPattern(r'^(?P<process>craftd)\[\d+\]: (?P<msg_type>\S+ alarm) cleared, (?P<instance>.+)', 4703, 1, 0, ['process','instance'])

