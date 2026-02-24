from scapy.all import ARP, Ether, srp, conf
import socket
import json
import os
from datetime import datetime


conf.iface = "VMware Virtual Ethernet Adapter for VMnet1"
plage_reseau = "192.168.154.0/24"
nom_fichier = "inventaire.json"



def decouverte_reseau(ip_range):
    print("[1] Recherche des machines sur ",ip_range)
    requete_arp = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquet_complet = broadcast / requete_arp
    
    reponses = srp(paquet_complet, timeout=2, verbose=False)[0]
    
    machines_trouvees = []
    
    print(len(reponses)," machine(s) détectée(s).")
    
    for envoye, recu in reponses:
        machine = {"ip": recu.psrc, "mac": recu.hwsrc}
        machines_trouvees.append(machine)
        print("* Trouvé :",recu.psrc, "| MAC : ",recu.hwsrc)
        
    return machines_trouvees

def audit_ports(ip_cible):
    print("\n[2] Analyse des services sur ",ip_cible)
    resultats_machine = []
    
    ports_communs = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        25: "SMTP",         
        53: "DNS",
    }

    for port, service in ports_communs.items():
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.settimeout(0.5)
        resultat = soc.connect_ex((ip_cible, port))
        
        if resultat == 0:
            info = f" Port {port} {service} OUVERT"
            print(info ,"\n")
            resultats_machine.append(info)
            if port in [21, 23]:
                alerte = f"    !ALERTE : {service} n'est pas chiffré (Risque d'écoute) ! \n"
                print("  ",alerte)
                resultats_machine.append(alerte)
        soc.close()
    
    return resultats_machine

def sauvegarder_inventaire_json(ip, mac, ports):
    nom_fichier = "inventaire.json"
    
    if os.path.exists(nom_fichier) and os.path.getsize(nom_fichier) > 0:
        try:
            with open(nom_fichier, "r", encoding="utf-8") as f:
                inventaire = json.load(f)
        except json.JSONDecodeError:
            inventaire = {}
    else:
        inventaire = {}

    if mac not in inventaire:
        print("\n[!] NOUVEL ASSET DÉTECTÉ : ",ip)
    
    inventaire[mac] = {
        "ip": ip,
        "mac": mac,
        "derniere_vue": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "services": ports
    }

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