from scapy.all import arping, conf

conf.iface = 12 # On garde ton index 12
print("Tentative avec la fonction native arping...")
arping("192.168.154.0/24")