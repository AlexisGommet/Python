from scapy.all import ARP, Ether, srp
import time
import argparse

def print_exec_time():
    
    exec_time = time.time() - start

    if exec_time < 10:
        print(f"\nExecution time: {int(round(exec_time, 3) * 1000)}ms\n")
    else:
        print(f"\nExecution time: {round(exec_time, 2)}s\n")
        
def get_args():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('arp', help='ARP Scan')
    parser.add_argument('-i', '--IP', dest='address', help='Target IP Address/Adresses')
    args = parser.parse_args()

    if not args.arp:
        parser.error("Please specify options")
        
    if args.arp and not args.address:
        parser.error("Please specify an IP Address or Addresses")
        
    return args

def arp_scan(IP):
    
    # IP = "192.168.1.1/24"
    # Create ARP packet
    arp = ARP(pdst=IP)
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
        
start = time.time()

args = get_args()

if args.arp:
    arp_scan(args.address)
    
print_exec_time()
