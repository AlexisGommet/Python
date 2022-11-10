import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
import time
import argparse
import threading
from ipaddress import IPv4Network

def print_exec_time():
    
    exec_time = time.time() - start

    if exec_time < 10:
        print(f"\nExecution time: {int(round(exec_time, 3) * 1000)}ms\n")
    else:
        print(f"\nExecution time: {round(exec_time, 2)}s\n")
        
def get_args():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', help='Scan mode (ICMP/ARP)')
    parser.add_argument("--verbose", help="increase output verbosity",action="store_true")
    parser.add_argument('-i', '--IP', dest='address', help='Target IP Address/Adresses')
    args = parser.parse_args()
    
    if args.mode == 'arp' and args.mode == 'icmp':
        parser.error("Choose only one mode")
        
    if args.mode != 'arp' and args.mode != 'icmp':
        parser.error("Please specify a valid scan mode")
        
    if (args.mode == 'arp' or args.mode == 'icmp') and not args.address:
        parser.error("Please specify an IP Address or Addresses")
        
    return args

def arp_scan(ip):

    # IP = "192.168.1.1/24"
    # Create ARP packet
    arp = ARP(pdst=ip)
    # Create Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Put ARP request inside ethernet frame
    packet = ether/arp
    # Send packet and get result
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []

    for sent, received in result:
        clients.append({'IP': received.psrc, 'MAC': received.hwsrc})

    print(f"\nLive network hosts:\n\nIP{' ' * 16}MAC")

    for client in clients:
        print("{:18}{}".format(client['IP'], client['MAC']))
     
def icmp_request(host):
    
    resp = sr1(IP(dst=str(host))/ICMP(),timeout=2, verbose=0)
    
    if resp is None:
        list.append({'host': str(host), 'status': 'not responding'})
    elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
        list.append({'host': str(host), 'status': 'blocking'})
    else:
        list.append({'host': str(host), 'status': 'responding'})
    
    
def icmp_scan(ip): 
    
    addresses = IPv4Network(ip)

    # Send ICMP ping request, wait for answer
    for host in addresses:
        if (host not in (addresses.network_address, addresses.broadcast_address)):
            # Skip network and broadcast addresses

            thread = threading.Thread(target=icmp_request, args=(host,))
            threads.append(thread)
            thread.start()
            
    for thread in threads:
        thread.join()
    
    print('Scan results:\n')  
          
    for resp in list:
        
        if resp['status'] == 'not responding' and args.verbose:
            print(f"{resp['host']} is down or not responding")
        elif resp['status'] == 'blocking' and args.verbose:
            print(f"{resp['host']} blocks ICMP")
        elif resp['status'] == 'responding':
            print(f"{resp['host']} is responding")

        
start = time.time()

threads = []
list = []

args = get_args()

print('Starting scan...\n') 

if args.mode == 'arp':
    arp_scan(args.address)
elif args.mode == 'icmp':
    icmp_scan(args.address)
    
print_exec_time()
