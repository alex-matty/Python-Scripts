#Import required modules
from scapy.all import *
import socket
import argparse
import re

#Script that checks for open ports in an specified IP
#Has to be run with root privileges
#By MEGANUKE

#Colors, to make a pretty layout
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white

#Create argument parser, help function and syntax
parser = argparse.ArgumentParser(description="A mini Port Scanner written in Python, easy and fast! work with both IPs or URLs")
parser.add_argument('-i', '--ip', help='URL or IP to check (If URL is provided do not provide protocol)')
parser.add_argument('-p', '--port', help='Port or range of ports to check(Single elements comma separated, Range provided with a dash)')
parser.add_argument('-s', '--scan', help='Type of scan (TCP or UDP')
parser.add_argument('-a', '--avoid', help='Skip ping scan. Treat host as Alive (Optional)', action='store_true')

args = parser.parse_args()

#Map the provided arguments with its variables
userIP = args.ip
ports = args.port
tcpOrUdp = args.scan
tcpOrUdp = tcpOrUdp.upper()
skip_scan = args.avoid

#A pretty banner to start the layout!
print( B + '''
            _       _  _____                                             
           (_)     (_)/ ____|                                            
  _ __ ___  _ _ __  _| (___   ___ __ _ _ __  _ __   ___ _ __ _ __  _   _ 
 | '_ ` _ \| | '_ \| |\___ \ / __/ _` | '_ \| '_ \ / _ \ '__| '_ \| | | |
 | | | | | | | | | | |____) | (_| (_| | | | | | | |  __/ |_ | |_) | |_| |
 |_| |_| |_|_|_| |_|_|_____/ \___\__,_|_| |_|_| |_|\___|_(_)| .__/ \__, |
                                                            | |     __/ |
                                                            |_|    |___/''')
print("%sBy MEGANUKE\n" % (W))

print("----------------------------------------------------------------")
print("[-] IP or URL: " + userIP)
print("[-] Scan Type: " + tcpOrUdp)
print("[-] Port(s): " + ports)
if skip_scan == True:
	print("[-] Skip Ping Check: Yes")
print("----------------------------------------------------------------\n")

#If URL is provided resolve to its IP address to be able to work with it
if re.match('[a-z]', userIP):
	dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=userIP))
	answer = sr1(dns_req, verbose=False)
	print(Y + "URL: " + W + userIP + Y + "\nIP: " + W + answer[DNS].an.rdata + "\n")
	userIP = answer[DNS].an.rdata

#Separate ports in a list depending on the way they've been provided
if ',' in ports:
	ports=ports.split(',')
elif '-' in ports:
	ports=ports.split('-')
	ports=range(int(ports[0]),int(ports[1])+1)

#Check if user has provided the skip ping flag and choose whether or not to ping the host
if skip_scan == True:
	print("Skipping Ping Check. Treating host as alive...")
	response=0
else:
	#Ping the IP to check if it's alive
	print("Trying to PING " + userIP)
	TIMEOUT=4
	packet = IP(dst=userIP)/ICMP()
	response = sr1(packet, timeout=TIMEOUT, verbose=False)
	if response is not None:
		response = response[ICMP].code
		print (userIP + " is up!\n")
	elif response == None:
		print("Unable to PING, exiting... \n")
		quit()

#If PING response equals 0 or if user choose to skip PING, set response variable to 0 and start the scan
if response == 0:
	
	if tcpOrUdp == "TCP":
		#Scan selected TCP ports
		for port in ports:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			socket.setdefaulttimeout(1)

			result = s.connect_ex((userIP,int(port)))
			if result == 0:
				print (Y + "TCP Port {} is open".format(port), end='\n')
			s.close()

	elif tcpOrUdp == "UDP":
		#Scan selected UDP ports
		for port in ports:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			socket.setdefaulttimeout(1)

			result = s.connect_ex((userIP,int(port)))
			if result == 0:
				print (Y + "Port {} is open".format(port))
			s.close()