import os
import sys
import math
import string
import operator 
from typing import List
from distutils import debug
from optparse import OptionParser

##########################################################
##########################################################
# Written by Tim Eberhard
# For bugs or feature additions please contact:
# xmin0s@gmail.com
#
# How to use Session Analyzer:
#	1)Login to your SRX and save off the session table:
#		show security flow session | save sessiontable.txt
#
#	2)Then copy off the session table to your local box and load it into the SRX Session Analyzer program.
#	3)Select the filters and the number of results you wish to be displayed
#	4)Hit the Analyze Session table button. 
#	5)Enjoy!
##########################################################
##########################$$sw00w#########################

"""
Just a quick example of a session to parse. 11.2r2.5
juniper@SRX240Template> show security flow session
Session ID: 42598, Policy name: self-traffic-policy/1, Timeout: 1782, Valid
  In: 172.16.10.1/53024 --> 172.16.10.2/179;tcp, If: .local..0, Pkts: 11557, Bytes: 710954
  Out: 172.16.10.2/179 --> 172.16.10.1/53024;tcp, If: ge-0/0/14.0, Pkts: 11553, Bytes: 710746
"""


versionnum = "1.0 Beta"

#Basic stuff to use for later. This is static and should never change.
protocolnum = {0:" HOPOPT ", 1: "ICMP", 2: "IGMP", 3: "GGP ", 4: "IP ", 5: "ST ", 6: "TCP ", 7: "CBT ", 8: "EGP ", 9: "IGP ", 10: "BBN-RCC-MON ", 11: "NVP-II ", 12: "PUP ", \
13: "ARGUS ", 14: "EMCON ", 15: "XNET ", 16: "CHAOS ", 17: "UDP ", 18: "MUX ", 19: "DCN-MEAS ", 20: "HMP ", 21: "PRM ", 22: "XNS-IDP ", 23: "TRUNK-1 ", 24: "TRUNK-2 ", \
25: "LEAF-1 ", 26: "LEAF-2 ", 27: "RDP ", 28: "IRTP ", 29: "ISO-TP4 ", 30: "NETBLT ", 31: "MFE-NSP ", 32: "MERIT-INP ", 33: "DCCP ", 34: "3PC ", 35: "IDPR ", 36: "XTP ", \
37: "DDP ", 38: "IDPR-CMTP ", 39: "TP++ ", 40: "IL ", 41: "IPv6 ", 42: "SDRP ", 43: "IPv6-Route ", 44: "IPv6-Frag ", 45: "IDRP ", 46: "RSVP ", 47: "GRE ", 48: "DSR ", \
49: "BNA ", 50: "ESP ", 51: "AH ", 52: "I-NLSP ", 53: "SWIPE ", 54: "NARP ", 55: "MOBILE ", 56: "TLSP ", 57: "SKIP ", 58: "IPv6-ICMP ", 59: "IPv6-NoNxt ", 60: "IPv6-Opts ", \
61: "any ", 62: "CFTP ", 63: "any ", 64: "SAT-EXPAK ", 65: "KRYPTOLAN ", 66: "RVD ", 67: "IPPC ", 68: "any ", 69: "SAT-MON ", 70: "VISA ", 71: "IPCV ", 72: "CPNX ", \
73: "CPHB ", 74: "WSN ", 75: "PVP ", 76: "BR-SAT-MON ", 77: "SUN-ND ", 78: "WB-MON ", 79: "WB-EXPAK ", 80: "ISO-IP ", 81: "VMTP ", 82: "SECURE-VMTP ", 83: "VINES ", \
84: "TTP ", 85: "NSFNET-IGP ", 86: "DGP ", 87: "TCF ", 88: "EIGRP ", 89: "OSPFIGP ", 90: "Sprite-RPC ", 91: "LARP ", 92: "MTP ", 93: "AX.25 ", 94: "IPIP ", 95: "MICP ", \
96: "SCC-SP ", 97: "ETHERIP ", 98: "ENCAP ", 99: "any ", 100: "GMTP ", 101: "IFMP ", 102: "PNNI ", 103: "PIM ", 104: "ARIS ", 105: "SCPS ", 106: "QNX ", 107: "A/N ", \
108: "IPComp ", 109: "SNP ", 110: "Compaq-Peer ", 111: "IPX-in-IP ", 112: "VRRP ", 113: "PGM ", 114: "any ", 115: "L2TP ", 116: "DDX ", 117: "IATP ", 118: "STP ", \
119: "SRP ", 120: "UTI ", 121: "SMP ", 122: "SM ", 123: "PTP ", 124: "ISIS over IPv4 ", 125: "FIRE ", 126: "CRTP ", 127: "CRUDP ", 128: "SSCOPMCE ", 129: "IPLT ", \
130: "SPS ", 131: "PIPE ", 132: "SCTP ", 133: "FC ", 134: "RSVP-E2E-IGNORE ", 135: "Mobility Header  ", 136: "UDPLite ", 137: "MPLS-in-IP ", \
138-252: "Unassigned ", 253: "Use for experimentation and testing ", 254: "Use for experimentation and testing ", 255: "Reserved"}


from pydantic import BaseModel

class SRCIP(BaseModel):
	connections: int
	srcip: str
	percentage: float

class DSTIP(BaseModel):
	connections: int
	dstip: str
	percentage: float

class SourcePort(BaseModel):
	connections: int
	port_num: int
	percentage: float

class DestPort(BaseModel):
	connections: int
	port_num: int
	percentage: float

class proto(BaseModel):
	connections: str
	protocol: str
	percentage: float

class Policy(BaseModel):
	connections: int
	policy: str
	percentage: float

class Interface(BaseModel):
	connections: int
	interface: str
	percentage: float

class Packet(BaseModel):
	srcip: str
	destip: str
	srcport: str
	destport: str
	packets: int

class Bytes(BaseModel):
	srcip: str
	destip: str
	srcport: str
	destport: str
	bytes: int

def openconfig(devicepath):
    """Just as it sounds, opens up the configuration file
    then does a readlines on it. Yes..I like readlines. It just works"""
    global devconfig
    with open(devicepath, "r") as devfile:
        devconfig = devfile.readlines()
        return devconfig

#try:
#sessiondata = openconfig(FLAGS.sessiontabledump)
try:
	portnumx = open("port_list.txt", "r")
	portnums = portnumx.read()
	portnum = eval(portnums)
except:pass #If port_list.txt isn't present, oh well..
#except:
#	print("No session file found Please add one with:  -f <filename.\n \n \n")
#	sys.exit()

# Try to load the number to display. Otherwise set to 10
#try: 
#	numdisplayed = int(numdisplayed)
#except:
#	numdisplayed = 10


def analyze_session_table(sessiondata, numdisplayed, resulttype):
	"""Takes a session table and reports back top talkers. Pretty simple."""
	srclist = list()
	dstlist = list()
	srcportlist = list()
	destportlist = list()
	policylist = list()
	protocollist = list()
	interfacelist = list()
	xferlist = list()
	xferbytelist = list()
	sessionslist = list()
	
	#Counters for later use.
	source_ips = 0
	dest_ips = 0
	dest_ports = 0
	source_ports = 0
	policies = 0
	protocols = 0
	interfaces = 0
	sessions = 0
	
	for connection in sessiondata:
		if "Session ID:" in connection:
			#Policy name
			try:
				policy = connection.split("Policy name:")[1].split(",")[0]
				policylist.append(policy)
				policies = policies  + 1	#For every session increase 1
				if debug == "debug":
					print("DEBUG: (policy)",policy)
			except:pass

		if "Timeout:" in connection:
			try:
				timeout = connection.split("Timeout:")[1].split(",")[0]
				sessionslist.append(timeout)
				sessions = sessions + 1
				if debug == "debug":
					print("DEBUG:(timeout)",timeout)
			except:pass
			
			
		#parse to see if this is the inbound portion of the session.	
		if "In:" in connection:
			#Source IP
			try:
				srcip = connection.split(":")[1].split("/")[0]
				srclist.append(srcip)
				source_ips = source_ips + 1
				if debug == "debug":
					print ("DEBUG: (srcip)",srcip)
			except:pass
			
			#Dest IP
			try:
				dstip = connection.split("-->")[1].split("/")[0]
				dstlist.append(dstip)
				dest_ips = dest_ips + 1	#For every session increase 1
				if debug == "debug":
					print("DEBUG: (dstip)",dstip)
			except:pass
			
			#Source Port
			try:
				srcport = connection.split("/")[1].split()[0]
				srcportlist.append(srcport)
				source_ports = source_ports + 1	#For every session increase 1
				if debug == "debug":
					print("DEBUG: (srcport)",srcport)
			except:pass

			#Dest Port
			try:
				destport = connection.split("/")[2].split(";")[0]
				destportlist.append(destport)
				dest_ports = dest_ports + 1	#For every session increase 1
				if debug == "debug":
					print("DEBUG: (destport)",destport)
			except:pass

			#Protocol
			try:
				protocol = connection.split(";")[1].split(",")[0]
				protocollist.append(protocol)
				protocols = protocols  + 1	#For every session increase 1
				if debug == "debug":
					print("DEBUG: (protocol)",protocol)
			except:pass			
			
			#Interface
			try:
				interface = connection.split("If:")[1].split(",")[0]
				interfacelist.append(interface)
				interfaces = interfaces  + 1	#For every session increase 1
				if debug == "debug":
					print("DEBUG: (interface)",interface)
			except:pass			

			#Packets
			try:
				packets = connection.split("Pkts:")[1].split(",")[0]
				#need to grab the previous lines configuration here or the last source/dest in their respective lists
				xferpaks = int(packets), srclist[-1], dstlist[-1], srcportlist[-1], destportlist[-1]
				xferlist.append(xferpaks)
			except:pass			
	
			#Bytes
			try:
				bytes = connection.split("Bytes:")[1].split(",")[0]
				#need to grab the previous lines configuration here or the last source/dest in their respective lists
				xferbytes = int(bytes), srclist[-1], dstlist[-1], srcportlist[-1], destportlist[-1]
				xferbytelist.append(xferbytes)
			except:pass	
                
		#parse to see if this is the outbound portion of the session.
		if "Out:" in connection:
				#Interface
			try:
				interface = connection.split("If:")[1].split(",")[0]
				interfacelist.append(interface)
				interfaces = interfaces  + 1	#For every session increase 1
				if debug == "debug":
					print("DEBUG: (interface)",interface)
			except:pass			

			#Packets
			try:
				packets = connection.split("Pkts:")[1].split(",")[0]
				#need to grab the previous lines configuration here or the last source/dest in their respective lists
				xferpaks = int(packets), srclist[-1], dstlist[-1], srcportlist[-1], destportlist[-1]
				xferlist.append(xferpaks)
			except:pass			
	
		#Bytes
			try:
				bytes = connection.split("Bytes:")[1].split(",")[0]
				#need to grab the previous lines configuration here or the last source/dest in their respective lists
				xferbytes = int(bytes), srclist[-1], dstlist[-1], srcportlist[-1], destportlist[-1]
				xferbytelist.append(xferbytes)
			except:pass	
			
	########################################################################################################################		
	########################################################################################################################		
	########################################################################################################################	
	#Sort the data we processed.
	
	#top talkers - timeout
	counts={}
	sessionslist.sort()
	for s in sessionslist:
			if s in counts:
					counts[s] += 1
			else:
					counts[s] = 1
	alist = counts
	sessionl =  [(v,k) for k,v in alist.items()]
	sessionl.sort()
	sessionl.reverse()
	sessionl = [(k,v) for v,k in sessionl]
	total_sessions = sessions
	

	#top talkers - source ip
	counts = {}
	srclist.sort()
	for s in srclist: #Count IP's
			if s in counts:
					counts[s] += 1
			else:
					counts[s] = 1
	alist = counts
	srcipl = [(v, k) for k, v in alist.items()]
	srcipl.sort()
	srcipl.reverse()
	srcipl = [(k, v) for v, k in srcipl]
	total_source_ips = source_ips


	#top talkers - dest ip
	counts = {}
	dstlist.sort()
	for s in dstlist: #Count IP's
			if s in counts:
					counts[s] += 1
			else:
					counts[s] = 1
	alist = counts
	dstipl = [(v, k) for k, v in alist.items()]
	dstipl.sort()
	dstipl.reverse()
	dstipl = [(k, v) for v, k in dstipl]
	total_dest_ips = dest_ips


	#top ports - source
	counts = {}
	srcportlist.sort()
	for s in srcportlist: #Count ports
			if s in counts:
					counts[s] += 1
			else:
					counts[s] = 1
	alist = counts
	srcportl = [(v, k) for k, v in alist.items()]
	srcportl.sort()
	srcportl.reverse()
	srcportl = [(k, v) for v, k in srcportl]
	total_source_ports = source_ports

	#top ports - dest
	counts = {}
	destportlist.sort()
	for s in destportlist: #Count ports
			if s in counts:
					counts[s] += 1
			else:
					counts[s] = 1
	alist = counts
	destportl = [(v, k) for k, v in alist.items()]
	destportl.sort()
	destportl.reverse()
	destportl = [(k, v) for v, k in destportl]
	total_dest_ports = dest_ports

	#top talkers - Policies
	counts = {}
	policylist.sort()
	for s in policylist: #Count IP's
			if s in counts:
					counts[s] += 1
			else:
					counts[s] = 1
	alist = counts
	policyl = [(v, k) for k, v in alist.items()]
	policyl.sort()
	policyl.reverse()
	policyl = [(k, v) for v, k in policyl]
	total_policies = policies


	#top talkers - Protocols
	counts = {}
	protocollist.sort()
	for s in protocollist: #Count IP's
			if s in counts:
					counts[s] += 1
			else:
					counts[s] = 1
	alist = counts
	protocoll = [(v, k) for k, v in alist.items()]
	protocoll.sort()
	protocoll.reverse()
	protocoll = [(k, v) for v, k in protocoll]
	total_protocols = protocols


	#top talkers - Interfaces
	counts = {}
	interfacelist.sort()
	for s in interfacelist: #Count IP's
			if s in counts:
					counts[s] += 1
			else:
					counts[s] = 1
	alist = counts
	interfacel = [(v, k) for k, v in alist.items()]
	interfacel.sort()
	interfacel.reverse()
	interfacel = [(k, v) for v, k in interfacel]
	total_interfaces = interfaces


	#Top Talkers - Packets
	xferlist.sort()
	xferlist.reverse() 

	#Top Talkers - Bytes
	xferbytelist.sort()
	xferbytelist.reverse()
            
	########################################################################################################################		
	########################################################################################################################		
	########################################################################################################################	
	#Print shit off here.
	
	#print("\n"*2)
	#print("-SRX Session Analyzer-")
	#print("-Written By Tim Eberhard-")       
	#print("-Version:%s -\n\n\n" %versionnum)   
    
    
	if resulttype == "srcip":
		output: List[SRCIP] = []
		for i,j in srcipl[:numdisplayed]:				
			pp = int(j)
			source_ips_percent = pp/total_source_ips
			item = SRCIP(connections=pp, srcip = i,percentage = round(source_ips_percent * 100,2))
			output.append(item.dict())
		return output

					
	if resulttype == "dstip":
		output: List[DSTIP] = []
		for i,j in dstipl[:numdisplayed]:				
			pp = int(j)
			dest_ips_percent = pp/total_dest_ips
			item = DSTIP(connections=pp, dstip = i,percentage = round(dest_ips_percent * 100,2))
			output.append(item.dict())
		return output					

	if resulttype == "srcport":
		output: List[SourcePort] = []
		for i,j in srcportl[:numdisplayed]:				
			pp = int(j)
			source_ports_percent = pp/total_source_ports
			item = SourcePort(connections=pp, port_num=int(i),percentage =round(source_ports_percent*100,2) )
			output.append(item.dict())
		return output
		
	if resulttype == "dstport":
		output: List[DestPort] = []
		for i,j in destportl[:numdisplayed]:				
			pp = int(j)
			dest_ports_percent = pp/total_dest_ports
			item = DestPort(connections = pp, port_num=int(i),percentage=round(dest_ports_percent*100,2))
			output.append(item.dict())
		return output
				
	if resulttype == "protocol":
		output: List[proto] = []
		for i,j in protocoll[:numdisplayed]:				
			pp = int(j)
			protocol_percent = pp/total_protocols
			item = proto(connections = pp, protocol=i ,percentage=round(protocol_percent*100, 2))
			output.append(item.dict())
				#print("%s    -       %s    (%s Percent)" %(pp, i, round(protocol_percent*100, 2)))
		return output
		
	if resulttype == "policy":
		output: List[Policy] = []		
		for i,j in policyl[:numdisplayed]:				
			pp = int(j)
			policies_percent = pp/total_policies
			item = Policy(connections=pp,policy=i,percentage=round(policies_percent*100, 2))
			#print("%s	-	%s    (%s Percent)"%(pp, i, round(policies_percent*100, 2)))
			output.append(item.dict())
		return output


	if resulttype =="interface":
		output: List[Interface] = []		
		for i,j in interfacel[:numdisplayed]:				
			pp = int(j)
			interfaces_percent = pp/total_interfaces
			item = Interface(connections=pp,interface=i,percentage=round(interfaces_percent*100, 2))
			#print("%s	-	%s    (%s Percent)"%(pp, i, round(interfaces_percent*100, 2)))
			output.append(item.dict())
		return output
		
	if resulttype == "packet":
		output: List[Packet] = []		
		for line in xferlist[:numdisplayed]:
			item = Packet(srcip=line[1], destip=line[2], srcport=line[3], destport=line[4], packets=line[0])				
			#print("%s \t\t %s \t\t %s \t\t\t %s \t\t %s \n"%(line[1],line[2], line[3], line[4], line[0]))
			output.append(item.dict())
		return output
		
	if resulttype == "bytes":
		output: List[Bytes] = []
		for line in xferbytelist[:numdisplayed]:
			item = Bytes(srcip=line[1], destip=line[2], srcport=line[3], destport=line[4], bytes=line[0])					
			#print("%s \t\t %s \t\t %s \t\t\t %s \t\t %s \n"%(line[1],line[2], line[3], line[4], line[0]))
			output.append(item.dict())
		return output			
#analyze_session_table(sessiondata, numdisplayed,resulttype)				
