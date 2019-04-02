import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.compat import compat_ord
import struct
import socket
import csv
import datetime
def ip_to_str(address):
    return socket.inet_ntoa(address)
def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

pack = open('Data_Pack.pcap', 'rb')
pcap = dpkt.pcap.Reader(pack)
c = csv.writer(open("data.csv", "wb"))
header = ("Date", "Time" , "Source Mac " , "Destination Mac" ,"Source Ip" , "Destination Ip" , "Length" , "Protocol" , "Source port" , "Destination port" , "HTTP" , "DNS")


c.writerow(header)
for ts, buf in pcap:
    http = None
    dhcp = None
    dns_ans = None 
    proto =''
    S_port=''
    D_port=''
    timestamp = str(datetime.datetime.utcfromtimestamp(ts))
    Date = timestamp[:10]
    Time = timestamp[10:]
    eth = dpkt.ethernet.Ethernet(buf)
    Source_mac=mac_addr(eth.src)
    Destination_mac=mac_addr(eth.dst) 

    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue
    ip = eth.data
    do_not_fragment = bool(dpkt.ip.IP_DF)
    more_fragments = bool(dpkt.ip.IP_MF)
    fragment_offset = bool(dpkt.ip.IP_OFFMASK)
    Source_ip = "%s" % ip_to_str(ip.src)
    Destination_ip = "%s" % ip_to_str(ip.dst)
    Length = "%d" % (ip.len)
    Protocol = ip.p
    

    if Protocol==6:
	proto = "TCP"
        tcp=ip.data
        S_port=tcp.sport
        D_port=tcp.dport


        if D_port == 80 and len(tcp.data) > 0:
 	    http = dpkt.http.Request(tcp.data)
            htp = http.uri
            httpb = http.headers['user-agent']


    elif Protocol==17:
        proto = "UDP"
        udp = ip.data
        S_port=udp.sport
        D_port=udp.dport
        if udp.dport == 53 and udp.sport == 53:
       		 dns = dpkt.dns.DNS(udp.data)
       		 for answer in dns.an:
       		    if answer.type == 1: 
       		      dns_ans=answer.name


    elif Protocol==1:
        proto = "ICMP"

    data = (Date , Time , Source_mac , Destination_mac , Source_ip, Destination_ip, Length,  proto , S_port , D_port , repr(http) , dns_ans)
    c.writerow(data)
