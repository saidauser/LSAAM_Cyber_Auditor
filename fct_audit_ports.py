import socket

def audit_ports(ip_cible):
    print("\n[?] Analyse des services sur ",ip_cible,"...")
    ports_communs = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL"
    }

    for port, service in ports_communs.items():
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.settimeout(1)
        resultat = soc.connect_ex((ip_cible, port))
        
        if resultat == 0:
            print("  Port ", port , "(" ,service ,"),: OUVERT")
            if port == 23 or port == 21:
                print("       /!\\ Risque détecté : ", service ," n'est pas chiffré !")
        
        soc.close()