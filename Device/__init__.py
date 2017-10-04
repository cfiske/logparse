import re

class Device(object):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Generic'
        self.logPatterns = {}

    def getName(self):
        return self.name

    def getVendor(self):
        return self.vendor

    def matchLogPattern(self, message):
        for p in self.logPatterns:
            matched = p.match(message['text'])

            if matched:
                pattern = self.logPatterns[p]
                if pattern['state'] == 0:
                    # Return instantly on ignored messages
                    #print "discarding - matched pattern id %s with text: %s" % (pattern['id'], message['text'])
                    message['state'] = 0
                    return 1

                #print "matched pattern id %s with text: %s" % (pattern['id'], message['text'])
                for k in pattern:
                    message[k] = pattern[k]

                # Matched, so stop
                return 1

        print "warning: no pattern matched for host [%s] text: %s" % (message['host'], message['text'])

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
        pattern_dict['keys'] = msg_keys

        for cp in cpatterns:
            if cp in self.logPatterns:
                print "warning: duplicate pattern. skipping: (%s) %s" % (self.logPatterns[cp]['id'], pattern)
            else:
                self.logPatterns[cp] = pattern_dict

        return 1


class A10(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'A10'
        self.logPatterns = {}


class Arista(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Arista'
        self.logPatterns = {}


class Brocade(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Brocade'
        self.logPatterns = {}


class Cisco(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Cisco'
        self.logPatterns = {}


class F5(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'F5'
        self.logPatterns = {}


class Force10(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Force10'
        self.logPatterns = {}


class Linux(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Linux'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^stats-loader-production: E, \[.+\] ERROR -- : Error while calculating rate: ', 1000, 0, 0, [])


class Juniper(Device):

    def __init__(self, name):
        self.name = name
        self.vendor = 'Juniper'
        self.logPatterns = {}

        # addLogPattern(self, pattern, msg_id, msg_state, msg_ttl, msg_keys):
        # msg_id = Unique value identifying a specific message
        # msg_state = Type of message - 0=ignore, 1=up, 2=down, 3=stateless
        # msg_keys = List of tokens which make up the instance key
        self.addLogPattern(r'^/kernel: (?P<msg_type>tcp_auth_ok): Packet from (?P<peer_ip>\d+\.\d+\.\d+\.\d+):\d{1,5} unexpectedly has MD5 digest', 1000, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>tcp_auth_ok): Packet from (?P<peer_ip>\d+\.\d+\.\d+\.\d+):\d{1,5} missing MD5 digest', 1000, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^/kernel: (?P<msg_type>jsr_jsm_update_hold_timeo): bucket created for bgp timeout', 1001, 3, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>ex92xx_fib_cnt) \d+', 1002, 3, 600, [])
        self.addLogPattern(r'^/kernel: hw.chassis.startup_time update to \d+', 1003, 0, 600, [])
        self.addLogPattern(r'^/kernel: .*vks.*', 1004, 0, 600, [])
        self.addLogPattern(r'^/kernel: (?P<msg_type>KERN_ARP_ADDR_CHANGE): arp info overwritten for (?P<instance>\S+) from ', 1005, 0, 600, ['instance'])
        self.addLogPattern(r'^master failed to clean up hw entry', 1005, 0, 600, [])
        self.addLogPattern(r'^mgd\[\d{1,5}\]: (?P<msg_type>UI_CHILD_START): .* \'(?P<process>.+)\'', 3000, 0, 600, ['process'])
        self.addLogPattern(r'^mgd\[\d{1,5}\]: (?P<msg_type>UI_CHILD_STATUS): .* \'(?P<process>.+)\', .*', 3001, 0, 600, ['process'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_CMDLINE_READ_LINE): User \'(?P<user>.+)\', command \'(?P<command>[^\']+)', 3002, 3, 600, ['user','command'])
        self.addLogPattern(r'^sshd: (?P<msg_type>SSHD_LOGIN_FAILED): Login failed for user \'(?P<user>\S+)\' from ', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: error: PAM: authentication error for (?P<user>\S+) from ', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Failed password for (?P<user>\S+) from ', 3003, 3, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_AUTH_EVENT): Authenticated user \'(?P<user>\S+)\' at ', 3004, 2, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Accepted \S+ for (?P<user>\S+) from ', 3004, 2, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_LOGIN_EVENT): User \'(?P<user>[^\']+)\' login, class ', 3004, 2, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_LOGOUT_EVENT): User \'(?P<user>[^\']+)\' logout', 3006, 1, 600, ['user'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_JUNOSCRIPT_CMD): User \'(?P<user>[^\']+)\' used JUNOScript client to run command \'(?P<command>[^\']+)', 3006, 3, 600, ['user','command'])
        self.addLogPattern(r'^(mgd|file)\[\d{1,5}\]: (?P<msg_type>UI_NETCONF_CMD): User \'(?P<user>[^\']+)\' used NETCONF client to run command \'(?P<command>[^\']+)', 3007, 3, 600, ['user','command'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Received disconnect from ', 3008, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: Connection closed by ', 3008, 0, 600, [])
        self.addLogPattern(r'^inetd\[\d{1,5}\]: (?P<process>\S+)\[\d{1,5}\]: exited, status \d+', 3008, 0, 600, ['process'])
        self.addLogPattern(r'^/usr/sbin/(?P<msg_type>cron)\[\d{1,5}\]: \((?P<user>\S+)\) CMD \(\s*(?P<process>\S.*)\)', 3009, 0, 600, ['user','process'])
        self.addLogPattern(r'^xntpd\[\d{1,5}\]: kernel time sync enabled \d+', 3010, 0, 600, [])
        self.addLogPattern(r'^gkmd: Exit at main \d+', 3011, 0, 600, [])
        self.addLogPattern(r'^autoconfd: shmlog: unable to create argtype:', 3012, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: (?P<msg_type>tac_send_authen): unexpected EOF ', 3013, 0, 600, [])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: subsystem request for netconf by user (?P<user>.+)', 3014, 0, 600, ['user'])
        self.addLogPattern(r'^sshd\[\d{1,5}\]: subsystem request for netconf failed, subsystem not found', 3015, 0, 600, [])
        self.addLogPattern(r'^pfed: (?P<msg_type>PFED_NOTIF_GLOBAL_STAT_UNKNOWN): Unknown global notification stat:', 3016, 0, 600, [])
        self.addLogPattern(r'^jddosd\[\d{1,5}\]: (?P<msg_type>DDOS_PROTOCOL_VIOLATION_SET): Protocol (?P<protocol>.+) is violated at (?P<instance>fpc \d+) for \d+ times', 3017, 2, 0, ['protocol','instance'])
        self.addLogPattern(r'^jddosd\[\d{1,5}\]: (?P<msg_type>DDOS_PROTOCOL_VIOLATION_CLEAR): Protocol (?P<protocol>.+) has returned to normal. Violated at (?P<instance>fpc \d+) for \d+ times', 3018, 1, 0, ['protocol','instance'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFDD_TRAP_SHOP_STATE)_DOWN: local discriminator: \d+, new state: down, interface: (?P<port>\S+), peer addr: (?P<peer_ip>\S+)', 3019, 2, 0, ['port','peer_ip'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFDD_TRAP_SHOP_STATE)_UP: local discriminator: \d+, new state: up, interface: (?P<port>\S+), peer addr: (?P<peer_ip>\S+)', 3020, 1, 0, ['port','peer_ip'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFD Session) (?P<peer_ip>\S+) \(IFL \d+\) state Up -> \S+ LD/RD\(\d+/\d+\) Up time:', 3021, 2, 0, ['peer_ip'])
        self.addLogPattern(r'^bfdd\[\d{1,5}\]: (?P<msg_type>BFD Session) (?P<peer_ip>\S+) \(IFL \d+\) state \S+ -> Up LD/RD\(\d+/\d+\)', 3022, 1, 0, ['peer_ip'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_TRAP_QUEUED): Adding trap to (?P<instance>\S+) to destination queue', 3100, 0, 0, ['instance'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_SEND_FAILURE): trap_io_send_trap_now: send to \((?P<instance>\S+)\) failure:', 3101, 3, 0, ['instance'])
        self.addLogPattern(r'^snmpd\[\d{1,5}\]: (?P<msg_type>SNMPD_TRAP_QUEUE_MAX_ATTEMPTS): trap_dq_send_traps: after \d+ attempts, deleting \d+ traps queued to (?P<instance>\S+)', 3102, 3, 0, ['instance'])
        self.addLogPattern(r'^(?P<msg_type>jl2tpd): jl2tpd: main: \*\*\* jl2tpd running \*\*\*', 3200, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>jl2tpd): jl2tpd: main: L2tp config check instantiation', 3201, 0, 600, ['process'])
        self.addLogPattern(r'^(?P<msg_type>jl2tpd): L2TP running with debug events enabled', 3202, 0, 600, ['process'])
        self.addLogPattern(r'^l2cpd\[\d{1,5}\]: (?P<process>lldp_server_reinit)\(\) reinit server', 3203, 0, 600, ['process'])
        self.addLogPattern(r'^chassisd\[\d{1,5}\]: (?P<process>CHASSISD_BLOWERS_SPEED)_FULL: Fans and impellers being set to full speed', 3204, 2, 600, [])
        self.addLogPattern(r'^chassisd\[\d{1,5}\]: (?P<process>CHASSISD_BLOWERS_SPEED)(_MEDIUM)?: Fans and impellers (are now running at normal|being set to intermediate) speed', 3205, 1, 600, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_PATH_BANDWIDTH_CHANGE): MPLS path\s+\(lsp (?P<instance>\S+)\) bandwidth changed, path bandwidth \d+ bps', 4000, 0, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_PATH_DOWN): MPLS path\s+down on LSP (?P<instance>\S+)', 4001, 2, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_PATH_UP): MPLS path\s+up on LSP (?P<instance>\S+) path bandwidth \d+ bps', 4002, 1, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_BANDWIDTH_CHANGE): MPLS LSP (?P<instance>\S+) bandwidth changed, lsp bandwidth \d+ bps', 4100, 0, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_DOWN): MPLS LSP (?P<instance>\S+) down on (?P<path>\S+)', 4101, 2, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_UP): MPLS LSP (?P<instance>\S+) up on (?P<path>\S+) Route ', 4102, 1, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_MPLS_LSP_CHANGE): MPLS LSP (?P<instance>\S+) change on (?P<path>\S+) Route ', 4103, 3, 0, ['instance'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_listen_accept): Connection attempt from unconfigured neighbor: (?P<peer_ip>\S+)\+\d{1,5}', 4200, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_[a-z0-9_]+)(:\d+)?: NOTIFICATION sent to (?P<peer_ip>\S+)\+\d{1,5} \(proto\): code \d+ \(', 4201, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_[a-z0-9_]+)(:\d+)?: NOTIFICATION sent to (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): code \d+ \(', 4201, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_UNUSABLE_NEXTHOP): bgp_nexthop_sanity: peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) next hop ', 4202, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_nexthop_sanity): peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) next hop ', 4202, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_standby_socket_read_internal):\d+: NOTIFICATION received from (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): code \d+ \(', 4203, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_read_v4_message):\d+: NOTIFICATION received from (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): code \d+ \(', 4203, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv_open): peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): received NOTIFICATION code \d+ \(', 4203, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv): peer (?P<peer_ip>\S+)\+\d{1,5} \(proto\): .+', 4204, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv): peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): .+', 4204, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_recv): read from peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) failed: .+', 4204, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_listen_accept): Connection received from (?P<peer_ip>\S+), .+', 4205, 3, 0, ['peer_ip'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_pp_recv): dropping (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\), connection collision', 4206, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>bgp_pp_recv): rejecting connection from (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\), peer in state ', 4206, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>trace_(on|rotate)): (tracing|rotating)', 4207, 0, 0, [])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_WRITE_WOULD_BLOCK): bgp_send: sending \d+ bytes to (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) blocked', 4208, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_WRITE_FAILED): bgp_send: sending \d+ bytes to (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) failed', 4209, 3, 0, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_BGP_NEIGHBOR_STATE_CHANGED): BGP peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) changed state from Established to (?P<peer_state>\S+)', 4210, 2, 0, ['peer_ip','peer_asn', 'peer_state'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>RPD_BGP_NEIGHBOR_STATE_CHANGED): BGP peer (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\) changed state from \S+ to (?P<peer_state>Established)', 4211, 1, 0, ['peer_ip','peer_asn', 'peer_state'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_RESET_PENDING_CONNECTION): (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): reseting pending active connection', 4212, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^rpd\[\d{1,5}\]: (?P<msg_type>BGP_PREFIX_THRESH_EXCEEDED): (?P<peer_ip>\S+) \((Ex|In)ternal AS (?P<peer_asn>\d{1,5})\): Configured maximum prefix-limit threshold\(\d+\) exceeded', 4213, 3, 600, ['peer_ip','peer_asn'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP laser) bias current low  alarm set', 4300, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP laser) bias current low  alarm cleared', 4301, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\)\(\d+\)): (?P<msg_type>SFP\+) unplugged', 4302, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\)\(\d+\)): (?P<msg_type>SFP\+) plugged in', 4303, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP (output|receive) power) low  (warning|alarm) set', 4304, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP (output|receive) power) low  (warning|alarm) cleared', 4305, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP syslog throttling): disabling syslogs for ', 4306, 2, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP syslog throttling): enabling syslogs for ', 4307, 1, 600, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP voltage (high|low)) ? alarm set', 4308, 2, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+ C?MIC\(\d+/\d+\) link \d+) (?P<msg_type>SFP voltage (high|low)) ? alarm cleared', 4309, 1, 0, ['instance'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) Next-hop resolution requests from interface (?P<port>\d+) throttled ', 4400, 1, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>pic_xmchip_wanio_dfe_tuning_op):(?P<port>\S+) - (En|Dis)able DFE (adaptive )?tuning ', 4401, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>cmic_phy_dfe_tuning_state):(?P<port>\S+) - DFE coarse/fine tuning completes', 4402, 3, 600, ['instance','port'])
        self.addLogPattern(r'^(?P<instance>fpc\d+) (?P<msg_type>PFE_FW_SYSLOG_IP6)_(GEN|ICMP): FW: (?P<port>\S+)\s+D \S+ SA \S+', 4403, 3, 600, ['instance','port'])


