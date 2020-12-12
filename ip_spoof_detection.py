from scapy.all import *
from IPy import IP as IPTEST
import argparse
import sys

ttl_values = {}
# Threshold for maximum difference in TTL values
THRESHOLD = 10

# Parses packets received and passes source IP 
def get_ttl(pkt):
	try:
		if pkt.haslayer(IP):
			src = pkt.getlayer(IP).src
			ttl = pkt.getlayer(IP).ttl
			check_ttl(src, ttl)

	except:
		pass


# Checks if the TTL is within the maximum threshold
def check_ttl(src, ttl):
	if IPTEST(src).iptype() == "PRIVATE":
		return

	if not src in ttl_values:
		icmp_pkt = sr1(IP(dst=src)/ICMP(), retry=0, verbose=0, timeout=1)
		ttl_values[src] = icmp_pkt.ttl

	if abs(int(ttl_values[src]) - int(ttl)) > THRESHOLD:
		print(f"[!] Detected possible spoofed packet from [{src}]")
		print(f"[!] Received TTL: {ttl}, Actual TTL: {ttl_values[src]}")



# Sniffs traffic on the specified interface. 
# Grabs the src IP and TTL from the network traffic then compares the TTL with an ICMP echo reply. 
# If the difference in TTL is greater than THRESHOLD a warning will be printed.
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", dest="interface", help="Specify the interface to capture network traffic e.g 'eth0'")

	if len(sys.argv) != 3:
		parser.print_help(sys.stderr)
		sys.exit(1)

	args = parser.parse_args()
	iface = args.interface

	print(f"[*] Sniffing traffic on interface [{iface}]")
	sniff(prn=get_ttl, iface=iface)


if __name__ == "__main__":
	main()
