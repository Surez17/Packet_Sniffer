import socket, sys
from struct import *
import textwrap
import struct
import time
from scapy.all import *
from Tkinter import *                                           
from tkFileDialog  import askopenfilename,asksaveasfilename                                                      
import tkMessageBox     
                                         


PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1

class Pcap:

 def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
  self.pcap_file = open(filename, 'wb') 
  self.pcap_file.write(struct.pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER, PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))

 def writelist(self, data=[]):
  for i in data:
   self.write(i)
  return

 def write(self, data):
  ts_sec, ts_usec = map(int, str(time.time()).split('.'))
  length = len(data)
  self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
  self.pcap_file.write(data)

 def close(self):
  self.pcap_file.close()


def mac_addr (byte_addr) :
   addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(byte_addr[0]) , ord(byte_addr[1]) , ord(byte_addr[2]), ord(byte_addr[3]), ord(byte_addr[4]) , ord(byte_addr[5]))
   return addr



src_mac =''
dest_mac =''	
protocol=''
def sniff():
	try:
	    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()
	p=Pcap('Data_Pack.pcap')
        
	while True:
	    packet = s.recvfrom(65565)
	    p.write(packet[0])
	    packet = packet[0]
	    eth_length = 14
	    eth_header = packet[:eth_length]
	    eth = unpack('!6s6sH' , eth_header)
	    eth_protocol = socket.ntohs(eth[2])
            
    	    
            
	    if eth_protocol == 8 :
		dest_mac = mac_addr(packet[0:6])
		src_mac = mac_addr(packet[6:12])
		protocol = str(eth_protocol)
		print 'Source MAC : ' + src_mac + ' Destination MAC : ' + dest_mac + ' Protocol : ' + protocol + '\n'		
		ip_header = packet[eth_length:20+eth_length]
		iph = unpack('!BBHHHBBH4s4s' , ip_header)
		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF
		iph_length = ihl * 4
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);
		print  'Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr) + ' \n '   
	       
	        def closed():
	           s.close()

		if protocol == 6 :
		    t = iph_length + eth_length
		    tcp_header = packet[t:t+20]
		    tcph = unpack('!HHLLBBHHH' , tcp_header)
		    source_port = tcph[0]
		    dest_port = tcph[1]
		    sequence = tcph[2]
		    acknowledgement = tcph[3]
		    doff_reserved = tcph[4]
		    tcph_length = doff_reserved >> 4
		    print ' Protocol : TCP  Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + '\n'		   
		    h_size = eth_length + iph_length + tcph_length * 4
		    data_size = len(packet) - h_size
		    data = packet[h_size:]
		      
	 
		
		elif protocol == 1 :
		    u = iph_length + eth_length
		    icmph_length = 4
		    icmp_header = packet[u:u+4]	 		    
		    icmph = unpack('!BBH' , icmp_header)		     
		    icmp_type = icmph[0]
		    code = icmph[1]
		    checksum = icmph[2]		     
		    print ' Protocol : ICMP Type  \n ' 		    		     
		    h_size = eth_length + iph_length + icmph_length
		    data_size = len(packet) - h_size
		     
	
	 
	      
		elif protocol == 17 :
		    u = iph_length + eth_length
		    udph_length = 8
		    udp_header = packet[u:u+8]	 		
		    udph = unpack('!HHHH' , udp_header)		     
		    source_port = udph[0]
		    dest_port = udph[1]
		    length = udph[2]
		    checksum = udph[3] 
		    print ' Protocol : UDP Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + '\n'
		    h_size = eth_length + iph_length + udph_length

		
def ret():                
	return 'Source MAC : ' + src_mac + ' Destination MAC : ' + dest_mac + ' Protocol : ' + protocol + '\n'
		
		    
		    

if __name__=='__main__':
	    sniff()

