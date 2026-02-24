from scapy.all import show_interfaces, conf


print("--- Liste des interfaces détectées ---")
show_interfaces()

print(f"\nInterface par défaut actuelle : {conf.iface}")
from scapy.all import conf
print(conf.use_pcap) 