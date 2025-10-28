# Projet1

#  Projet1 : Analyse et Visualisation du Trafic Réseau ( fichier SkypeIRC télechargé sur Wireshark)

Ce mini projet d'Ingénierie Système et Réseaux a pour objectif d'analyser un fichier de capture de trafic réel (`.cap`) afin d'établir une distribution statistique des protocoles (TCP, UDP, DNS, etc.) et de générer une visualisation des résultats.

Le projet a servi de preuve de concept pour la maîtrise des outils d'analyse de signaux réseau et de manipulation de données (Data Science) en environnement Python.

##  Outils et Technologies Utilisés


-Python 3 : Langage de développement principal. 
-Scapy :Librairie d'analyse et de manipulation de paquets réseau, utilisée pour lire le fichier `.cap`. 
-Pandas : Analyse et traitement statistique des données brutes extraites (comptage de protocoles d un tableau issu de l'analyse). 
-Matplotlib : Génération du graphique en secteurs pour la visualisation. 
-Git & GitHub : Gestion de version et hébergement du code. 

##  Fonctionnalités du Script (`analyse_protocole.py`)

1.  **Lecture Robuste :Utilisation du chemin absolu (`r'C:\...'`) pour garantir l'exécution sur tout environnement Windows(j'ai eu des problèmes d exécution quand je n'utilisais pas le chemin absolu).
2.  **Extraction Précise :*Identification du protocole de plus haut niveau grace à la fonction (`paquet.lastlayer().name`) pour des statistiques pertinentes (DNS, TCP, Raw, etc.).
3.  **Visualisation Non-Graphique :** Utilisation du *backend* Matplotlib `'Agg'` pour générer un fichier PNG sans dépendre d'une interface graphique (idéal pour les serveurs et terminaux comme CMD).
4.  **Rapport :** Génération automatique de l'image `distribution_protocoles_reels.png` dans le dossier `doc/`.

## Structure du Projet
Nous avons 3 dossiers:
code
  analyse_protocole.py--> script python qui fais l anaylse et le traitement du fichier SkypeIRC
data
  SkypeIRC.cap --> Le fichier de capture réseau à analyser
doc
  distribution_protocoles_reels.png ---> Résultat du graphique 

