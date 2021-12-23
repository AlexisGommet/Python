from pathlib import Path

root_dir = Path("./crypte.txt")

text = input("\nTexte à écrire : ").strip()

texte_crypte = ""

for i in text:
    texte_crypte += chr(ord(i)+3)

with open(root_dir ,"w", encoding="utf-8") as fichier:
    fichier.write(texte_crypte)

print("\nTexte crypté : "+ texte_crypte)

texte_decrypte = ""

with open(root_dir, encoding="utf-8") as fichier2:
    for ligne in fichier2:
        for i in ligne:
            texte_decrypte += chr(ord(i)-3)

print("\nTexte décrypté : "+ texte_decrypte + "\n")