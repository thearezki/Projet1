import pandas as pd
import matplotlib.pyplot as plt
import os
import matplotlib
from scapy.all import rdpcap 

# ----------------- CONFIGURATION ET DÉPENDANCES -----------------
# Chemin ABSOLU vers le fichier de capture .cap.
# L'utilisation de 'r' (raw string) garantit une lecture correcte sous Windows.
CAPTURE_FILE = r'C:\Users\arezk\Documents\Projet1\data\SkypeIRC.cap' 

# Force Matplotlib à utiliser le backend 'Agg' (non-graphique) pour sauvegarder l'image sans ouvrir de fenêtre.
matplotlib.use('Agg') 


# ----------------- FONCTION 1 : ANALYSE DU TRAFIC RÉEL (SCAPY) -----------------
def analyser_trafic_reel():
    """ Lit le fichier .cap avec Scapy, extrait les protocoles de haut niveau, et retourne un DataFrame Pandas. """
    
    protocol_list = []
    print(f"Tentative d'analyse du fichier : {CAPTURE_FILE}...")
    
    try:
        # Lecture synchrone du fichier .cap.
        paquets = rdpcap(CAPTURE_FILE)

        # Itération sur chaque paquet pour extraire l'information du protocole.
        for paquet in paquets:
            # Extraction du nom du protocole de la dernière couche (TCP, UDP, DNS, etc.)
            protocol_name = paquet.lastlayer().name
            protocol_list.append(protocol_name.strip()) 
            
        print(f"Analyse réussie : {len(paquets)} paquets lus.")
        
        # Création du DataFrame pour l'analyse statistique.
        df = pd.DataFrame(protocol_list, columns=['Protocole'])
        return df
        
    except FileNotFoundError:
        print(f"\n!!! ERREUR : Fichier {CAPTURE_FILE} non trouvé. Vérifiez le chemin absolu.")
        return pd.DataFrame()
        
    except Exception as e:
        print(f"\n!!! ERREUR LORS DE L'ANALYSE : {e} !!!")
        return pd.DataFrame()


# ----------------- FONCTION 2 : COMPTAGE ET VISUALISATION -----------------
def analyser_et_visualiser(df):
    """ Compte les protocoles (Pandas) et génère le graphique (Matplotlib) dans le dossier 'doc/'. """
    
    if df.empty:
        return
        
    # Comptage statistique des protocoles
    comptage = df['Protocole'].value_counts()
    
    print("\n--- Répartition des Protocoles Réels ---")
    print(comptage)
    
    # Création du diagramme en secteurs
    plt.figure(figsize=(8, 8))
    comptage.plot(kind='pie', autopct='%1.1f%%', startangle=90, cmap='viridis')
    plt.title(f'Distribution du Trafic Réseau ({df.shape[0]} paquets)')
    plt.ylabel('')
    
    # Sauvegarde de l'image dans le dossier doc/ (au même niveau que code/)
    plt.savefig('../doc/distribution_protocoles_reels.png') 
    print(f"\nGraphique sauvegardé dans : doc/distribution_protocoles_reels.png")
    

# ----------------- EXECUTION DU SCRIPT -----------------
if __name__ == "__main__":
    
    # Assure que le dossier de sortie 'doc/' existe
    if not os.path.exists('../doc'):
        os.makedirs('../doc')
        
    data_frame = analyser_trafic_reel()
    if not data_frame.empty:
        analyser_et_visualiser(data_frame)
    else:
        print("Analyse des données annulée.")