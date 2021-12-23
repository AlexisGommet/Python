import argparse
import requests
from pathlib import Path
import time
import math

parser = argparse.ArgumentParser()
parser.add_argument("domain", help="nom de domaine a enumerer")
parser.add_argument("dico", help="display a square of a given number")
args = parser.parse_args()

dico = Path(args.dico)
domain = args.domain

sdomainestrouve = []
threads = []

tdebut = time.time()

with open(dico, "r") as dico:
    for line in dico:
        line = line.replace("\n", "").replace(".", "")   
        url = (f"http://{line}.{domain}")
        print(url.replace("http://", ""))
        try:
            requete = requests.get(url, timeout=3)
            if requete.status_code == 200:
                sdomainestrouve.append(line.replace("http://", ""))
        except requests.exceptions.RequestException as e:
            pass


print("\nSous-domaines trouvés :\n")            
for i in sdomainestrouve:
    print(i)

tfin = time.time()
minutes = math.floor((tfin-tdebut)/60)
secondes = round(tfin-tdebut)-(minutes*60)
print("\nTemps d'exécution : "+ str(minutes) + " minutes " + str(secondes) +" secondes")