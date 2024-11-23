import pyfiglet
import sys
import socket
import time
import threading
from datetime import datetime
from scapy.all import IP, TCP, sr1, conf

#ASCII is american standard code of information interchange
#th emodulw pyfiglet is used to generate grafical image of the given string and 
# figlet_format is a key word in pyfiglet library it convert the string that we provided and turns into ASCII art.

ascii_banner = pyfiglet.figlet_format("PORT SCANNER",font="slant")
print(ascii_banner)

# sys.argv is a list which has its first value as executing file port_scanner.py[0] and the elements are added from the second index.
if len(sys.argv) == 2:
	
	# the gethostbyname translate hostname to IPv4
	target = socket.gethostbyname(sys.argv[1]) 
else:
	print("Invalid amount of Argument")

print("-" * 50)
print("Scanning Target: " + target)
print("Scanning started at: " + str(datetime.now()))
print("-" * 50)

conf.use_pcap = True 	
def detect_os(ip):
    try:
		#sends the packet to the particular IP address
		#creates a packets for a destined IP and it is attach with TCP, and dport=80(http) is used for to
		#send the packets to the specfied port cuz port 80 which is commonly opened in many devices.
        pkt = IP(dst=ip)/TCP(dport=80, flags="S")  # flags='s' create SYN packet
        resp = sr1(pkt, timeout=2, verbose=0) #send the packets to the IP,  if the reponse from the target address within the 2sec timout 
		#and the repose id stored in the resp, if not it return None.
        if resp:
			#it retrive the ttl(Time to Live) value and stores in the ttl.
            ttl = resp.ttl
            if ttl <= 64:
				#Basically the linux based os have the default ttl value till 64.
                print(f"OS Detection: Target {ip} is likely running on a Linux-based OS.")
            elif ttl > 64 and ttl <= 128:
				#windows has ttl from (65 to 128)
                print(f"OS Detection: Target {ip} is likely running on a Windows-based OS.")
            else:
                print(f"OS Detection: Target {ip} OS is unknown or Unable to Detect.")
        else:
            print(f"OS Detection: No response from {ip}.")
    except Exception as e:
        print(f"Error in OS detection: {e}")

#calling the func
detect_os(target)
print("-"*55)
try:
	print("1. Search for Only Opened Ports (Slow)\n2. search for Ports in Range (Recommended)\n3. Quick Scan (Fast)")
	choice = int(input("[1/2/3]: "))
	if choice == 1:
		print("Estimated Time to scan (1024) ports is 1-2min!")
		print("Waiting for response........\n")
		# will scan ports between 1 to 1024 common ports and registered ports
		start = time.time()
		for port in range(1,1024):
			#AF_INET means ipv4 address and SOCK_STREAM specifies the TCP
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			#it set the time for any type of operation should be done in 2 seconds
			socket.setdefaulttimeout(2)
			
			# it try to connect to the specific IP address and if it connects it return the vlaue '0'
			result = s.connect_ex((target,port))

			with open("scan_result.txt","a") as f:
				if result ==0:
					service = socket.getservbyport(port, "tcp")
					print(f"Port {port} is open ({service})")
					f.write(f"\nPort {port} is open ({service}) on the host {target}")
				s.close()
		if result != 0:
			print(f"-->No ports are opened on {target}<--")
		end =time.time()
		print(f"-->Time taken {end-start:.2f} seconds!<--")

	elif choice == 2:
		start_port_1 = int(input("Enter the starting port: "))
		end_port_1 = int(input("Enter the ending port: "))
		print("-"*54)
		print(f"Scanning ports from {start_port_1} to {end_port_1} on Target {target}")
		print("-"*54)
		print("Waiting for response.....")
		# will scan ports between 1 to 65,535
		starttime=time.time()
		for port in range(start_port_1,end_port_1+1):
			#AF_INET means ipv4 address and SOCK_STREAM specifies the TCP
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			#it set the time for any type of operation should be done in 2 seconds
			socket.setdefaulttimeout(2)
			
			# it try to connect to the specific IP address and port if it connects it return the vlaue '0'
			result = s.connect_ex((target,port))

			with open("scan_result.txt","a") as f:
				if result ==0:
					service = socket.getservbyport(port, "tcp")
					print(f"Port {port} is open ({service})")
					f.write(f"\nPort {port} is open ({service}) on the host {target}")
				else:
					print(f"port {port} is closed or filtered")
				s.close()
		endtime=time.time()
		print(f"-->Time take {endtime-starttime:.2f} seconds<--")

	elif choice==3:
		start_port_2 = int(input("Enter the starting port: "))
		end_port_2 = int(input("Enter the end port: "))
		#its a normal port scanning code you would see in the choice 1 section
		def scan_port(ip, port):
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(1)
				result = s.connect_ex((ip, port))
				if result == 0:
					print(f"Port {port} is OPEN")
				else:
					print(f"Port {port} is CLOSED")
				s.close()
			except socket.error as e:
				print(f"Error scanning port {port}: {e}")

		def quick_scan(ip, port_range):
			print(f"Starting quick scan on {ip}")
			
			#creates a list to store the threads
			threads = []
			for port in range(port_range[0], port_range[1] + 1):
				thread = threading.Thread(target=scan_port, args=(ip, port)) #it createa a new thread by using threading.Thread 
				threads.append(thread)
				thread.start()
			
			# Wait for all threads to complete
			for thread in threads:
				thread.join()
		port_range = (start_port_2,end_port_2)
		ip=target
		quick_scan(ip, port_range)
	else:
		print("Invalid Input")
		sys.exit(1)

except KeyboardInterrupt:
		print("\nKeyboard Interrupt")
		print("Exiting Program !!!!")
		sys.exit()
#if host name is not able to convert into the ip gaierror will occur
except socket.gaierror:
		print("\n Hostname Couldn't be Convert into Ip (or) Ivalid Host name !!!!")
		sys.exit()
#if th target server in not responded
except socket.error:
		print("\n Target Server not responding !!!!")
		sys.exit()
