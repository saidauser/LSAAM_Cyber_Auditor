import json
import os
import datetime

def sauvegarder_dans_inventaire(ip, mac, ports):
    nom_fichier = "inventaire.json"
    nouvelle_donnee = {
        "ip": ip,
        "mac": mac,
        "derniere_vue": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "ports_ouverts": ports
    }

    if os.path.exists(nom_fichier):
        with open(nom_fichier, "r", encoding="utf-8") as f:
            inventaire = json.load(f)
    else:
        inventaire = {}

    if mac not in inventaire:
        print("   [!] NOUVEL ASSET DÉTECTÉ : ",ip)
    
    inventaire[mac] = nouvelle_donnee

    with open(nom_fichier, "w", encoding="utf-8") as f:
        json.dump(inventaire, f, indent=4, ensure_ascii=False)