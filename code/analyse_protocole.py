import pandas as pd
import matplotlib.pyplot as plt
import os
import matplotlib
# Utilisation du backend 'Agg' pour éviter les erreurs graphiques dans le terminal
matplotlib.use('Agg')

# Import de Scapy, la librairie la plus stable pour la lecture de fichiers .cap
from scapy.all import rdpcap 

# ----------------- CONFIGURATION DU PROJET RESET -----------------
# Chemin d'accès à votre fichier de capture SkypeIRC.cap
# '..' remonte d'un dossier (de 'code' à 'Projet1') pour trouver 'data/'
CAPTURE_FILE = r'C:\Users\arezk\Documents\Projet1\data\SkypeIRC.cap'

# ----------------- FONCTION 1 : ANALYSE DU TRAFIC RÉEL (SCAPY) -----------------
def analyser_trafic_reel():
    """ Lit le fichier .cap avec Scapy et stocke les protocoles dans un DataFrame. """
    
    protocol_list = []
    print(f"Tentative d'analyse du fichier : {CAPTURE_FILE}...")
    
    try:
        # Scapy lit le fichier .cap en une seule fois (rdpcap = read pcap)
        paquets = rdpcap(CAPTURE_FILE)

        # Boucle (loop) qui parcourt chaque paquet dans le fichier
        for paquet in paquets:
            # On utilise paquet.summary() qui donne une description textuelle du paquet.
            # On prend le deuxième mot de cette description, qui est généralement le protocole de niveau 3/4.
            # Exemple de summary: 'IP / TCP 192.168.1.1:1234 > 8.8.8.8:80 [S]'
            # Le deuxième mot est ici 'TCP'
            protocol_name = paquet.lastlayer().name
            protocol_list.append(protocol_name.strip()) 
            
        print(f"Analyse réussie : {len(paquets)} paquets lus.")
        
        # Créer le tableau de données Pandas (DataFrame) pour l'analyse statistique
        df = pd.DataFrame(protocol_list, columns=['Protocole'])
        return df
        
    except FileNotFoundError:
        print(f"\n!!! ERREUR : Fichier {CAPTURE_FILE} non trouvé. !!!")
        print("Vérifiez que le fichier SkypeIRC.cap est bien dans le dossier data/.")
        return pd.DataFrame()
        
    except Exception as e:
        # Gère d'autres erreurs potentielles (format de fichier corrompu, etc.)
        print(f"\n!!! ERREUR LORS DE L'ANALYSE : {e} !!!")
        return pd.DataFrame()


# ----------------- FONCTION 2 : COMPTAGE ET VISUALISATION (PANDAS/MATPLOTLIB) -----------------
def analyser_et_visualiser(df):
    """ Compte les protocoles (Pandas) et crée le graphique (Matplotlib). """
    
    if df.empty:
        return
        
    # 1. COMPTAGE (Pandas - Le cœur de l'analyse statistique)
    # value_counts() compte combien de fois chaque protocole apparaît
    comptage = df['Protocole'].value_counts()
    
    print("\n--- Répartition des Protocoles Réels ---")
    print(comptage)
    
    # 2. VISUALISATION (Matplotlib - Création du graphique)
    plt.figure(figsize=(8, 8))
    # kind='pie' pour un diagramme en secteurs; autopct pour afficher les pourcentages
    comptage.plot(kind='pie', autopct='%1.1f%%', startangle=90, cmap='viridis')
    plt.title(f'Distribution du Trafic Réseau ({df.shape[0]} paquets)')
    plt.ylabel('')
    
    # 3. Sauvegarder l'image pour GitHub
    # Sauvegarde le graphique dans le dossier Projet1/doc/
    plt.savefig('../doc/distribution_protocoles_reels.png') 
    print(f"\nGraphique sauvegardé dans : doc/distribution_protocoles_reels.png")


# ----------------- EXECUTION DU SCRIPT (Point de départ) -----------------
if __name__ == "__main__":
    # Crée le dossier doc/ s'il n'existe pas (nécessaire pour la sauvegarde du graphique)
    if not os.path.exists('../doc'):
        os.makedirs('../doc')
        
    data_frame = analyser_trafic_reel()
    if not data_frame.empty:
        analyser_et_visualiser(data_frame)
    else:
        print("Analyse des données annulée.")