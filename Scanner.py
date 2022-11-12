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
    parser.add_argument("-p", dest='port', help="Scan the ports of live hosts, 1 for basic scan, 2 for extensive scan", type=int, required = False, default = 0)
    parser.add_argument('-i', '--IP', dest='address', help='Target IP Address/Adresses')
    args = parser.parse_args()
        
    if args.mode not in ['icmp', 'arp']:
        parser.error("Please specify a valid scan mode")
        
    if not args.address:
        parser.error("Please specify an IP Address or Addresses")
        
    if args.port not in [0, 1, 2]:
        parser.error("Choose a valid port scan")
        
    return args

def arp_scan(ip):

    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []

    for _, received in result:
        clients.append({'IP': received.psrc, 'MAC': received.hwsrc})

    print(f"\nLive network hosts:\n\nIP{' ' * 16}MAC")

    for client in clients:
        print("{:18}{}".format(client['IP'], client['MAC']))
        
    if args.port in [1, 2]:
        
        hosts = []
        
        for client in clients:
            hosts.append(client['IP'])
            
        port_scan(hosts)
     
def icmp_request(host):
    
    resp = sr1(IP(dst=str(host))/ICMP(),timeout=2, verbose=0)
    
    if ((resp is not None) and (not (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]))):
        list.append(str(host))
    
    
def icmp_scan(ip): 
    
    addresses = IPv4Network(ip)

    for host in addresses:
        if (host not in (addresses.network_address, addresses.broadcast_address)):

            thread = threading.Thread(target=icmp_request, args=(host,))
            threads.append(thread)
            thread.start()
            
    for thread in threads:
        thread.join()
    
    print('Live network hosts:\n')  
          
    for host in list:        
        print(host)
            
    if args.port in [1, 2]:
            
        port_scan(list)
            
def port_scan(hosts):

    port_range = []
    
    if args.port == 1:
        port_range = range(1, 600)
        print('\nScanning ports 1-600...\n')
    else:
        port_range = range(1, 65535)
        print('\nScanning ports 1-65535...\n')
        
    for host in hosts:  
        print(f'\nOpen ports of host {host}\n')     
        for dst_port in port_range:           
            thread = threading.Thread(target=port_request, args=(host,dst_port,))
            threads.append(thread)
            thread.start()
            
    for thread in threads:
        thread.join()
            
                    
def port_request(host, dst_port):
    src_port = random.randint(1026,65534)
            
    # Send SYN flag
    resp = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,verbose=0)

    if(resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12):
            
        # Close connection with RST flag                    
        sr(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),timeout=1,verbose=0)
        print(dst_port)
        
start = time.time()

threads = []
list = []

args = get_args()

print('\nStarting scan...\n') 

if args.mode == 'arp':
    arp_scan(args.address)
elif args.mode == 'icmp':
    icmp_scan(args.address)
    
print_exec_time()
