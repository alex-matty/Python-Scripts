from scapy.all import *
import socket

#Script that checks for open ports in an specified IP
#Has to be run with root privileges
#By MEGANUKE

#Get the IP
userIP = input("IP to check: ")

#Ping the IP to check if it's alive // Change it to scapy	
TIMEOUT = 2

packet = IP(dst=userIP)/ICMP()
response = sr1(packet, timeout=TIMEOUT)

if response == None:
	print (userIP + " is up!")


	#Ask the range of ports to check
	firstPort = int(input("First port to check: "))
	lastPort = int(input("Last port to check: "))

	tcpOrUdp = input("TCP or UDP port scan: ")
	tcpOrUdp = tcpOrUdp.upper()

	if tcpOrUdp == "TCP":

		#Scan selected TCP ports
		for port in range(firstPort,lastPort):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			socket.setdefaulttimeout(1)

			result = s.connect_ex((userIP,port))
			if result == 0:
				print ("TCP Port {} is open".format(port))
			s.close()

	elif tcpOrUdp == "UDP":

		#Scan selected UDP ports
		#NOTE: CHECK WHY IT SAYS EVERY PORT IS OPEN
		for port in range(firstPort,lastPort):
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			socket.setdefaulttimeout(1)

			result = s.connect_ex((userIP,port))
			if result == 0:
				print ("Port {} is open".format(port))
			s.close()

else:
	print (userIP + " is not responding!")