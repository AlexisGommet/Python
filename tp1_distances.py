miles = float(input("Entrez une distance en miles\n"))

metres = round(miles * 1.609 * 1000)

if(metres > 10000):
    print("\nC'est loin")
elif(metres > 5000):
    print("\nÇa va")
else:
    print("\nC'est près")
if metres == 69 or metres == 690 or metres == 6900 or metres == 69000:
    print("\nNice!")

print("""\nUtilisez le système impérial détruit des vaisseaux spatiaux, parlez-en à votre américain\n\n
https://fr.wikipedia.org/wiki/Mars_Climate_Orbiter#Perte_de_la_sonde_(23_septembre_1999)\n""")