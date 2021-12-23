def palindrome():

    text = input("Entrez un texte\n")

    espace = input("Prendre en compte les espaces? oui/non\n").lower()

    while espace != "oui" and espace != "non":
        print("Erreur, veuillez entrez oui ou non")
        espace = input("Prendre en compte les espaces? oui/non\n").lower()

    fin = ""

    if espace == "non":
        text = text.replace(" ", "")

    for i in reversed(text):
        fin += i
    
    match(text == fin):
        case True:
            if espace == "non":
                return "Palindrome (sans prise en compte des espaces)"
            else:
                return "Palindrome (avec prise en compte des espaces)"
        case False:
            if espace == "non":
                return "Pas un palindrome (sans prise en compte des espaces)"
            else:
                return "Pas un palindrome (avec prise en compte des espaces)"

print(palindrome())