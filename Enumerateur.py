import argparse
import requests
from pathlib import Path
import time
import threading
import math

parser = argparse.ArgumentParser()
parser.add_argument("domain", help="nom de domaine a enumerer")
parser.add_argument("dico", help="display a square of a given number")
parser.add_argument("fichiertxt", help="fichier où écrire les sous-domaines valides")
args = parser.parse_args()
dico = Path(args.dico)
domain = args.domain
fichiertxt = args.fichiertxt
sdomainestrouve = []
threads = []
index = 1
tdebut = time.time()

def do_request(url,line):
    try:
        requete = requests.get(url, timeout=3)
        if requete.status_code == 200:
            sdomainestrouve.append(line.replace("http://", ""))
    except requests.exceptions.RequestException as e:
        pass

def enumerateur(domain, line):
    line = line.replace("\n", "").replace(".", "")   
    url = (f"http://{line}.{domain}")
    thread = threading.Thread(target=do_request, args=(url,line,))
    threads.append(thread)
    thread.start()

with open(dico, "r", encoding="utf-8") as dico:
    for line in dico:
        enumerateur(domain, line)
        print(index)
        index+=1

for thread in threads:
    thread.join()

print("\nSous-domaines trouvés :\n")            
for i in sdomainestrouve:
    print(i)

tfin = time.time()
minutes = math.floor((tfin-tdebut)/60)
secondes = round(tfin-tdebut)-(minutes*60)
print("\nTemps d'exécution : "+ str(minutes) + " minutes " + str(secondes) +" secondes\n")
print("Nombres de sous-domaines trouvés : " + str(len(sdomainestrouve)))

with open(fichiertxt, "w", encoding="utf-8") as mon_fichier:
    for i in sdomainestrouve:
        mon_fichier.write(i + "\n")
