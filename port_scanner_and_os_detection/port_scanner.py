import pyfiglet
import sys
import socket
from datetime import datetime
from tqdm import tqdm
from scapy.all import IP, TCP, sr1, conf

#ASCII is american standard code of information interchange
#th emodulw pyfiglet is used to generate grafical image of the given string and 
# figlet_format is a key word in pyfiglet library it convert the string that we provided and turns into ASCII art.

ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)

# sys.argv is a list which has its first value as executing file port_scanner.py[0] and the elements are added from the second index.
if len(sys.argv) == 2:
	
	# the gethostbyname translate hostname to IPv4
	target = socket.gethostbyname(sys.argv[1]) 
else:
	print("Invalid amount of Argument")

# Add Banner 
print("-" * 50)
print("Scanning Target: " + target)
print("Scanning started at: " + str(datetime.now()))
print("-" * 50)

conf.use_pcap = True 	
def detect_os(ip):
    try:
        pkt = IP(dst=ip)/TCP(dport=80, flags="S")  # Create SYN packet
        resp = sr1(pkt, timeout=2, verbose=0)      # Send packet and wait for response
        if resp:
            ttl = resp.ttl
            if ttl <= 64:
                print(f"OS Detection: Target {ip} is likely running a Linux-based OS.")
            elif ttl > 64 and ttl <= 128:
                print(f"OS Detection: Target {ip} is likely running a Windows-based OS.")
            else:
                print(f"OS Detection: Target {ip} OS is unknown.")
        else:
            print(f"OS Detection: No response from {ip}.")
    except Exception as e:
        print(f"Error in OS detection: {e}")

# Example usage
detect_os(target)

try:
	start_port = int(input("Enter the starting port: "))
	end_port = int(input("Enter the ending port: "))
	print("-"*54)
	print(f"Scanning ports from {start_port} to {end_port} on Target {target}")
	print("-"*54)
	print("Waiting for response.....")
	# will scan ports between 1 to 65,535
	for port in range(start_port,end_port+1):
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

except KeyboardInterrupt:
		print("\n Exiting Program !!!!")
		sys.exit()
except socket.gaierror:
		print("\n Hostname Could Not Be Resolved !!!!")
		sys.exit()
except socket.error:
		print("\n Server not responding !!!!")
		sys.exit()
