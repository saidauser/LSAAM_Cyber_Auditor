import json
import os
from datetime import datetime

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


        print("=========================================================================")
        print("      LSAAM - LOCAL SECURITY AUDITOR & ASSETS MONITORING        ")
        print("=========================================================================")


liste_machines = decouverte_reseau(plage_reseau)

if not liste_machines:
    print("\n Aucune machine n'a répondu. Fin de l'audit.")
else:
    date_heure = datetime.now().strftime("%d-%m-%Y %H_%M_%S")
    nom_fichier_unique =f"rapport_audit_{date_heure}.txt"

with open(nom_fichier_unique, "w", encoding="utf-8") as f:
    f.write("RAPPORT D'AUDIT DU "+date_heure+"\n")
    f.write("="*50 + "\n\n")

    for machine in liste_machines:     
            liste_ports_ouverts = audit_ports(machine["ip"])
        
            sauvegarder_inventaire_json(machine["ip"], machine["mac"], liste_ports_ouverts)
           
            f.write("CIBLE : " + machine['ip'] + "(MAC: "+machine['mac']+") \n")
            if  liste_ports_ouverts:
                for ligne in liste_ports_ouverts:
                    f.write(ligne+"\n")
            else:
                f.write("  Aucun service critique détecté.\n")
            f.write("-" * 30 + "n\n")

    print("\n" + "="*50)
    print(" AUDIT TERMINÉ !")
    print("   -> Mémoire mise à jour : ",nom_fichier)
    print("   -> Rapport généré : ",nom_fichier_unique)
    print("="*50) 
