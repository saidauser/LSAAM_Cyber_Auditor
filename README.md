# LSAAM_Cyber_Auditor
Outil d ' Audit  réseau automatisé en Python ( Découverte ARP & Scan de services TCP).
LSAAM est un outil d'audit de sécurité développé en Python dans le cadre de ma premiere année tant que étudiante en Cybersécurité ;

## L'analogie de l'immeuble :
l'objectif de ce projet est l'automatisation de la decouverte des équipements dans un réseau local et l'identification des services vulnérables en vue de réduire la surface d'attaque ,
Pour comprendre le fonctionnement , on fait une simple annalogie de l'immeuble ;
**Addresse IP : c'est l'addresse de l'immeuble 
**Les ports : se sont les numéros du bureaux à l'interieur de l'immeuble 
**Scan : c'est l'inspécteur qui fait le tour de nuit autour de  l'immeuble 
**l'Audit : vérifier si le service dériere la porte est sécurisé (SSH,SFTP) ou pas (TELNET,FTP)

## fonctionnalités : 
-Découverte :Scan ARP (couche 2) via la biblio Scapy pour une détection invisible par le pare-feu 
-Auditing : Scan des ports TCP  via la biblio Socket pour identifier les services actif 
-Alerte de vulnérabilité :Detection automatique des services non chiffrées 
-Asset Management :** Base de données au format `JSON` pour mémoriser les machines du parc.
-Reporting : Génération de rapports d'audit détaillés et horodatés.


## Environnement de test : 
le travail a été réaliser dans un environnement virtualisé et isolé (VM) :
-attaquant =machine Hote windows 11
-cible=deux machines vertuelles ; Métasploitable et ubuntu desktop 
                         ## Rélisé par : 
                         Saida.E , Etudiante en Cybersécurité @ENSA 
                         





