from scapy.all import ARP, Ether, srp

def decouverte_reseau(ip_range):
    print("--- Recherche des machines sur ",ip_range,"---")
    requete_arp = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquet_complet = broadcast / requete_arp
    reponses = srp(paquet_complet, timeout=2, verbose=False,iface=12)[0]
    print("Machines trouvées :")
    for envoyé, reçu in reponses:
       print("IP:", reçu.psrc ,"|", "MAC:",reçu.hwsrc)
    liste_ips = []
    for element in reponses:
        liste_ips.append(element[1].psrc)
    return liste_ips 
       
