import optparse,sys
from scapy.all import *
def icmp(host):
    try:
        ans, unans = sr(IP(dst=host) / ICMP(), inter=0.05, timeout=2)
        for s, r in ans:
            print "{0} is alive (TTL = {1})".format(str(r.src), str(r.ttl))
    except Exception, e:
        print e
def arp(host):
    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), inter=2,timeout=5)
        for s,r in ans:
            print "{0} is the MAC address for host {1}".format(r.src, r.psrc)
    except Exception, e:
        print e
if __name__ == '__main__':
    try:
        parser = optparse.OptionParser('usage: ' + sys.argv[0] + ' -H <target ip>')
        parser = optparse.OptionParser()
        parser.add_option('-I', dest='host', help='specify IP address or subnet like 192.168.1.1-100 for ICMP Ping')
        parser.add_option('-A', dest='host', help='specify IP address or subnet like 192.168.1.1-100 for ARP ping')
        (options, args) = parser.parse_args()
        host = options.host
        if options.host is not None:
            if sys.argv[1] == "-I":
                icmp(host)
            if sys.argv[1] == "-A":
                arp(host)
        else:
            print parser.usage

    except Exception, e:
print e