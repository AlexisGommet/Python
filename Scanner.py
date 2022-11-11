import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, TCP, sr
import time
import argparse
import threading
from ipaddress import IPv4Network
import random

def print_exec_time():
    
    exec_time = time.time() - start

    if exec_time < 10:
        print(f"\nExecution time: {int(round(exec_time, 3) * 1000)}ms\n")
    else:
        print(f"\nExecution time: {round(exec_time, 2)}s\n")
        
def get_args():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', help='Scan mode (ICMP/ARP)')
    parser.add_argument("--verbose", help="Increase output verbosity",action="store_true")
    parser.add_argument("-p", dest='port', help="Scan the ports of live hosts, 1 for basic scan, 2 for extensive scan", type=int, required = False, default = 0)
    parser.add_argument('-i', '--IP', dest='address', help='Target IP Address/Adresses')
    args = parser.parse_args()
        
    if args.mode != 'arp' and args.mode != 'icmp':
        parser.error("Please specify a valid scan mode")
        
    if (args.mode == 'arp' or args.mode == 'icmp') and not args.address:
        parser.error("Please specify an IP Address or Addresses")
        
    if args.port != 0 and args.port != 1 and args.port != 2:
        parser.error("Choose a valid port scan")
        
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
        
    if args.port:
        
        hosts = []
        
        for client in clients:
            hosts.append(client['IP'])
            
        port_scan(hosts)
     
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
            
    if args.port:
        
        hosts = []
        
        for resp in list:
            if resp['status'] == 'responding':
                hosts.append(resp['host'])
            
        port_scan(hosts)
            
def port_scan(hosts):

    port_range = []
    
    if args.port == 1:
        port_range = range(1, 600)
        print('\nScanning ports 1-600...\n')
    else:
        port_range = range(1, 65535)
        print('\nScanning ports 1-65535...\n')
        
    for host in hosts:  
        print(f'\nHost {host}\n')     
        for dst_port in port_range:           
            thread = threading.Thread(target=port_request, args=(host,dst_port,))
            threads.append(thread)
            thread.start()
            
    for thread in threads:
        thread.join()
            
                    
def port_request(host, dst_port):
    src_port = random.randint(1025,65534)
            
    # Send SYN flag
    resp = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,verbose=0)

    if resp is None:
        if args.verbose:
            print(f"{host}:{dst_port} is filtered (silently dropped)")

    elif(resp.haslayer(TCP)):
        if(resp.getlayer(TCP).flags == 0x12):
            
            # Close connection with RST flag                    
            sr(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),timeout=1,verbose=0)
            
            print(f"{host}:{dst_port} is open")

        elif (resp.getlayer(TCP).flags == 0x14) and args.verbose:
            print(f"{host}:{dst_port} is closed")

    elif(resp.haslayer(ICMP)):
        if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13] and args.verbose):
            print(f"{host}:{dst_port} is filtered (silently dropped)")
        
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
