import pandas as pd
import matplotlib.pyplot as plt
import os
import matplotlib
from scapy.all import rdpcap 

# ----------------- CONFIGURATION DU PROJET RESET -----------------
# !!! IMPORTANT !!! UTILISER LE CHEMIN ABSOLU VALIDÉ POUR TROUVER LE FICHIER.
# Le 'r' devant la chaîne indique à Python de lire le chemin littéralement (raw string).
CAPTURE_FILE = r'C:\Users\arezk\Documents\Projet1\data\SkypeIRC.cap' 

# Utilisation du backend 'Agg' pour générer l'image sans ouvrir de fenêtre graphique (nécessaire en CMD/Git Bash)
matplotlib.use('Agg') 


# ----------------- FONCTION 1 : ANALYSE DU TRAFIC RÉEL (SCAPY) -----------------
def analyser_trafic_reel():
    """ Lit le fichier .cap avec Scapy et stocke les protocoles. """
    
    protocol_list = []
    print(f"Tentative d'analyse du fichier : {CAPTURE_FILE}...")
    
    try:
        # Scapy lit le fichier .cap en une seule fois (rdpcap = read pcap)
        paquets = rdpcap(CAPTURE_FILE)

        # Boucle qui parcourt chaque paquet dans le fichier
        for paquet in paquets:
            # Utilise la dernière couche pour identifier le protocole (TCP, UDP, DNS, etc.)
            protocol_name = paquet.lastlayer().name
            protocol_list.append(protocol_name.strip()) 
            
        print(f"Analyse réussie : {len(paquets)} paquets lus.")
        
        # Créer le tableau de données Pandas (DataFrame) pour l'analyse statistique
        df = pd.DataFrame(protocol_list, columns=['Protocole'])
        return df
        
    except FileNotFoundError:
        print(f"\n!!! ERREUR : Fichier {CAPTURE_FILE} non trouvé. !!!")
        print("Vérifiez que le chemin absolu dans le script est correct.")
        return pd.DataFrame()
        
    except Exception as e:
        print(f"\n!!! ERREUR LORS DE L'ANALYSE : {e} !!!")
        return pd.DataFrame()


# ----------------- FONCTION 2 : COMPTAGE ET VISUALISATION (PANDAS/MATPLOTLIB) -----------------
def analyser_et_visualiser(df):
    """ Compte les protocoles (Pandas) et crée le graphique (Matplotlib). """
    
    if df.empty:
        return
        
    # 1. COMPTAGE (Pandas)
    comptage = df['Protocole'].value_counts()
    
    print("\n--- Répartition des Protocoles Réels ---")
    print(comptage)
    
    # 2. VISUALISATION (Matplotlib)
    plt.figure(figsize=(8, 8))
    comptage.plot(kind='pie', autopct='%1.1f%%', startangle=90, cmap='viridis')
    plt.title(f'Distribution du Trafic Réseau ({df.shape[0]} paquets)')
    plt.ylabel('')
    
    # 3. Sauvegarder l'image dans le dossier 'doc/' (au même niveau que 'code/')
    # Ceci est le chemin relatif le plus simple pour la sauvegarde
    plt.savefig('../doc/distribution_protocoles_reels.png') 
    print(f"\nGraphique sauvegardé dans : doc/distribution_protocoles_reels.png")
    

# ----------------- EXECUTION DU SCRIPT (Point de départ) -----------------
if __name__ == "__main__":
    
    # On crée le dossier 'doc/' à la racine du projet ('../doc') s'il n'existe pas.
    # Ceci est fait ici pour s'assurer que le chemin de sauvegarde existe.
    if not os.path.exists('../doc'):
        os.makedirs('../doc')
        
    data_frame = analyser_trafic_reel()
    if not data_frame.empty:
        analyser_et_visualiser(data_frame)
    else:
        print("Analyse des données annulée.")