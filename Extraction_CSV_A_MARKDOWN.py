#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import filedialog, messagebox
import os
import csv
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter, defaultdict
import webbrowser

# ==========================================
# Configuration
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
plt.style.use('ggplot') # Style un peu plus joli que par defaut

# ==========================================
# Classe Principale d'Analyse
# ==========================================
class NetworkAnalyzer:
    def __init__(self):
        self.donnees = []
        self.stats = {}
        self.anomalies = []
        self.output_dir = BASE_DIR

    def charger_donnees(self, chemin_csv):
        """Charge les données CSV avec le module standard csv"""
        print(f"Chargement de {chemin_csv}...")
        self.donnees = []
        try:
            with open(chemin_csv, 'r', encoding='utf-8', errors='ignore') as f:
                # On détecte automatiquement si le séparateur est ; ou ,
                ligne1 = f.readline()
                separateur = ';' if ';' in ligne1 else ','
                f.seek(0) # Revenir au début
                
                lecteur = csv.reader(f, delimiter=separateur)
                next(lecteur, None) # Sauter l'en-tête
                
                for ligne in lecteur:
                    # On s'assure d'avoir assez de colonnes (min 11)
                    if len(ligne) >= 11:
                        # Nettoyage de la longueur
                        length_str = ligne[10].replace(':', '').replace(',', '').strip()
                        length = int(length_str) if length_str.isdigit() else 0
                        
                        # On structure la donnée proprement
                        paquet = {
                            'Timestamp': ligne[0],
                            'Heure': ligne[0].split(':')[0], # On garde juste l'heure HH
                            'Proto': ligne[1],
                            'SrcIP': ligne[2],
                            'DstPort': ligne[5],
                            'Flags': ligne[6],
                            'Length': length
                        }
                        self.donnees.append(paquet)
            
            print(f"Données chargées : {len(self.donnees)} paquets.")
            return True
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de lire le fichier :\n{e}")
            return False

    def executer_analyse(self):
        """Effectue les calculs statistiques"""
        if not self.donnees: return

        print("Exécution de l'analyse statistique...")
        
        # Initialisation des compteurs
        self.stats['total_paquets'] = len(self.donnees)
        self.stats['total_volume_ko'] = sum(p['Length'] for p in self.donnees) / 1024
        
        # Comptage IP Sources
        compteur_ip = Counter(p['SrcIP'] for p in self.donnees)
        self.stats['top_ips_src'] = compteur_ip.most_common(10) # Top 10 [(ip, count)]
        
        # Volume par IP
        vol_ip = defaultdict(int)
        for p in self.donnees:
            vol_ip[p['SrcIP']] += p['Length']
        # On trie pour avoir le top 10 volume
        self.stats['vol_par_ip'] = sorted(vol_ip.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Protocoles
        self.stats['protocoles'] = Counter(p['Proto'] for p in self.donnees)
        
        # Trafic par heure (trié par heure)
        self.stats['trafic_heure'] = sorted(Counter(p['Heure'] for p in self.donnees).items())
        
        # SYN par IP
        self.stats['syn_par_ip'] = Counter(p['SrcIP'] for p in self.donnees if 'S' in p['Flags'])
        
        # Ports uniques par IP
        ports_par_ip = defaultdict(set)
        for p in self.donnees:
            if p['DstPort'] != 'N/A':
                ports_par_ip[p['SrcIP']].add(p['DstPort'])
        self.stats['ports_uniques_par_ip'] = {k: len(v) for k, v in ports_par_ip.items()}

    def _get_periode_activite(self, ip):
        """Récupère la plage horaire d'activité pour une IP"""
        timestamps = [p['Timestamp'] for p in self.donnees if p['SrcIP'] == ip]
        if not timestamps: return "N/A"
        if len(timestamps) == 1: return timestamps[0]
        # On suppose que les timestamps sont triés ou on prend min/max si besoin
        # Ici on prend simplement premier et dernier vu l'ordre de lecture
        return f"{timestamps[0]} à {timestamps[-1]}"

    def detecter_anomalies(self):
        """Règles de détection"""
        print("Détection des anomalies...")
        self.anomalies = []
        seuils = {'syn': 100, 'ports': 50, 'volume_ratio': 0.40}

        # 1. SYN FLOOD
        for ip, count in self.stats['syn_par_ip'].items():
            if count > seuils['syn']:
                self.anomalies.append({
                    'ip': ip, 'type': 'SYN FLOOD', 'gravite': 'CRITIQUE',
                    'periode': self._get_periode_activite(ip),
                    'details': f"{count} paquets SYN (Seuil: {seuils['syn']}). Tentative de saturation."
                })

        # 2. PORT SCAN
        for ip, count in self.stats['ports_uniques_par_ip'].items():
            if count > seuils['ports']:
                 self.anomalies.append({
                    'ip': ip, 'type': 'SCAN DE PORTS', 'gravite': 'ÉLEVÉE',
                    'periode': self._get_periode_activite(ip),
                    'details': f"{count} ports visés. Reconnaissance réseau."
                })

        # 3. VOLUMETRIE
        for ip, count in self.stats['top_ips_src']:
            ratio = count / self.stats['total_paquets']
            if ratio > seuils['volume_ratio']:
                 self.anomalies.append({
                    'ip': ip, 'type': 'INONDATION VOLUMÉTRIQUE', 'gravite': 'MOYENNE',
                    'periode': self._get_periode_activite(ip),
                    'details': f"Représente {ratio:.1%} du trafic total. Suspect."
                })

    def generer_graphiques(self):
        print("Génération des images...")
        
        # --- Image 1 : Vue Globale ---
        fig1, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        fig1.suptitle('Vue Globale du Trafic', fontsize=16, fontweight='bold')
        
        # Graphique Heure
        heures = [x[0] for x in self.stats['trafic_heure']]
        counts = [x[1] for x in self.stats['trafic_heure']]
        ax1.plot(heures, counts, marker='o', color='#3498db', linewidth=2)
        ax1.fill_between(heures, counts, color='#3498db', alpha=0.3)
        ax1.set_title("Paquets par Heure")
        ax1.grid(True, linestyle='--')

        # Graphique Protocoles (Camembert)
        labels = list(self.stats['protocoles'].keys())
        sizes = list(self.stats['protocoles'].values())
        ax2.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        ax2.set_title("Répartition des Protocoles")
        
        plt.tight_layout()
        fig1.savefig(os.path.join(self.output_dir, '1_vue_globale.png'), dpi=100)
        plt.close(fig1)

        # --- Image 2 : Sources ---
        fig2, (ax3, ax4) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Top IP
        ips = [x[0] for x in self.stats['top_ips_src']]
        vals = [x[1] for x in self.stats['top_ips_src']]
        
        # Couleurs: Rouge si suspect, Bleu sinon
        suspects = [a['ip'] for a in self.anomalies]
        couleurs = ['red' if ip in suspects else 'steelblue' for ip in ips]
        
        ax3.barh(ips, vals, color=couleurs)
        ax3.set_title("Top 10 IP Sources (Rouge = Suspect)")
        ax3.set_xlabel("Nombre de paquets")
        ax3.invert_yaxis() # Pour avoir le 1er en haut

        # Top Volume
        ips_v = [x[0] for x in self.stats['vol_par_ip']]
        vals_v = [x[1]/1024 for x in self.stats['vol_par_ip']] # En Ko
        
        ax4.bar(ips_v, vals_v, color='seagreen')
        ax4.set_title("Top Volumes (Ko)")
        plt.setp(ax4.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        plt.tight_layout()
        fig2.savefig(os.path.join(self.output_dir, '2_analyse_sources.png'), dpi=100)
        plt.close(fig2)

    def generer_rapport_md(self):
        print("Rédaction du rapport...")
        timestamp_gen = datetime.now().strftime("%d/%m/%Y à %H:%M")
        
        # Début du Markdown
        md = f"""# Rapport d'Analyse de Trafic Réseau
**Généré le :** {timestamp_gen}
**Outil :** PyNetAnalyzer Standard SAE 1.05

---

## 1. Synthèse

* **Statut :** {"🔴 **CRITIQUE**" if self.anomalies else "🟢 **NORMAL**"}
* **Paquets analysés :** {self.stats['total_paquets']}
* **Volume total :** {self.stats['total_volume_ko']:.2f} Ko
* **Anomalies :** {len(self.anomalies)}

---

## 2. Analyse Visuelle

### Vue temporelle et Protocoles
![Vue Globale](1_vue_globale.png)

### Emetteurs et Suspects
![Sources](2_analyse_sources.png)

---

## 3. Détail des Anomalies
"""
        if not self.anomalies:
            md += "\n> ✅ *Aucune anomalie détectée.*\n"
        else:
            md += "| Gravité | Type | IP Source | Période | Détails |\n|---|---|---|---|---|\n"
            for ano in self.anomalies:
                icone = "🔴" if ano['gravite'] == 'CRITIQUE' else "🟠"
                md += f"| {icone} {ano['gravite']} | **{ano['type']}** | `{ano['ip']}` | {ano['periode']} | {ano['details']} |\n"

        md += """
### Recommandations :
* **SYN FLOOD :** Bloquer l'IP sur le pare-feu.
* **PORT SCAN :** Vérifier les services exposés.
"""

        md += """
---
## 4. Statistiques (Top 10 IP)
| Rang | IP | Paquets |
|---|---|---|
"""
        for i, (ip, count) in enumerate(self.stats['top_ips_src'], 1):
            md += f"| {i} | `{ip}` | {count} |\n"

        chemin_rapport = os.path.join(self.output_dir, 'Rapport_Analyse.md')
        with open(chemin_rapport, 'w', encoding='utf-8') as f:
            f.write(md)
        return chemin_rapport

    def generer_rapport_html(self):
        """Génère un rapport HTML complet et stylisé"""
        print("Génération du rapport HTML...")
        timestamp_gen = datetime.now().strftime("%d/%m/%Y à %H:%M")
        
        status_color = "#e74c3c" if self.anomalies else "#2ecc71"
        status_text = "CRITIQUE" if self.anomalies else "NORMAL"
        
        # CSS Moderne et "Premium"
        css = """
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
            
            :root {
                --primary: #2c3e50;
                --secondary: #3498db;
                --accent: #e74c3c;
                --bg-body: #f8f9fa;
                --bg-card: #ffffff;
                --text-main: #2c3e50;
                --text-muted: #95a5a6;
                --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            }
            
            body { 
                font-family: 'Inter', sans-serif; 
                background-color: var(--bg-body); 
                color: var(--text-main); 
                margin: 0; 
                padding: 0; 
                line-height: 1.6; 
            }
            
            .container { 
                max-width: 1200px; 
                margin: 40px auto; 
                padding: 0 20px; 
            }
            
            header { 
                background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
                color: white;
                padding: 40px; 
                border-radius: 16px; 
                box-shadow: var(--shadow); 
                text-align: center; 
                margin-bottom: 40px; 
                position: relative;
                overflow: hidden;
            }
            
            header h1 { margin: 0; font-size: 2.5rem; font-weight: 700; }
            .meta { opacity: 0.8; margin-top: 10px; font-weight: 300; }
            
            .dashboard-grid { 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); 
                gap: 24px; 
                margin-bottom: 40px; 
            }
            
            .card { 
                background: var(--bg-card); 
                padding: 24px; 
                border-radius: 12px; 
                box-shadow: var(--shadow); 
                text-align: center; 
                transition: transform 0.2s;
            }
            
            .card:hover { transform: translateY(-5px); }
            
            .card h3 { 
                margin: 0 0 15px 0; 
                font-size: 0.85rem; 
                text-transform: uppercase; 
                letter-spacing: 1px;
                color: var(--text-muted); 
            }
            
            .card .value { 
                font-size: 2.2rem; 
                font-weight: 700; 
                color: var(--primary); 
            }
            
            .card.status { border-top: 4px solid """ + status_color + """; }
            .card.status .value { color: """ + status_color + """; }
            
            .section-title { 
                font-size: 1.5rem;
                font-weight: 600;
                margin: 50px 0 25px 0; 
                color: var(--primary); 
                display: flex;
                align-items: center;
            }
            
            .section-title::before {
                content: '';
                display: inline-block;
                width: 6px;
                height: 24px;
                background: var(--secondary);
                margin-right: 12px;
                border-radius: 3px;
            }
            
            /* Anomalies */
            .anomalies-container { display: flex; flex-direction: column; gap: 16px; }
            .anomaly-item { 
                background: var(--bg-card); 
                padding: 20px; 
                border-left: 5px solid var(--accent); 
                border-radius: 8px; 
                box-shadow: var(--shadow); 
                display: flex;
                align-items: center;
                justify-content: space-between;
            }
            
            .anomaly-content { flex: 1; }
            .anomaly-type { font-weight: bold; color: var(--accent); display: block; margin-bottom: 4px;}
            .anomaly-ip { 
                font-family: 'Consolas', monospace; 
                background: #f1f2f6; 
                padding: 4px 8px; 
                border-radius: 4px; 
                font-size: 0.9em;
                margin-right: 10px;
            }
            .anomaly-badge {
                background: #ffe3e3;
                color: #c0392b;
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: 600;
                white-space: nowrap;
                margin-left: 15px;
            }
            
            /* Charts */
            .charts-grid { 
                display: grid; 
                grid-template-columns: 1fr; 
                gap: 30px; 
            }
            
            .chart-box { 
                background: var(--bg-card); 
                padding: 20px; 
                border-radius: 12px; 
                box-shadow: var(--shadow); 
                text-align: center; 
            }
            .chart-box img { max-width: 100%; height: auto; border-radius: 8px; }
            
            /* Table */
            table { 
                width: 100%; 
                border-collapse: separate; 
                border-spacing: 0;
                background: var(--bg-card); 
                border-radius: 12px; 
                overflow: hidden; 
                box-shadow: var(--shadow); 
            }
            
            th, td { padding: 16px 20px; text-align: left; }
            th { 
                background-color: #f1f2f6; 
                color: #576574; 
                font-weight: 600; 
                text-transform: uppercase;
                font-size: 0.8rem;
                letter-spacing: 0.5px;
            }
            td { border-bottom: 1px solid #f1f2f6; }
            tr:last-child td { border-bottom: none; }
            tr:hover { background-color: #fafafa; }
            
            .progress-bar-bg {
                background: #ecf0f1;
                width: 100px;
                height: 8px;
                border-radius: 4px;
                overflow: hidden;
                display: inline-block;
                margin-right: 10px;
                vertical-align: middle;
            }
            .progress-bar-fill {
                background: var(--secondary);
                height: 100%;
                border-radius: 4px;
            }
            
            .footer { text-align: center; margin-top: 60px; margin-bottom: 20px; color: var(--text-muted); font-size: 0.9em; }
        </style>
        """
        
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Analyse Réseau</title>
    {css}
</head>
<body>
    <div class="container">
        <header>
            <h1>Rapport d'Analyse de Trafic</h1>
            <div class="meta">Généré le {timestamp_gen} | PyNetAnalyzer Standard</div>
        </header>
        
        <div class="dashboard-grid">
            <div class="card status">
                <h3>Statut Global</h3>
                <div class="value">{status_text}</div>
            </div>
            <div class="card">
                <h3>Paquets Analysés</h3>
                <div class="value">{self.stats['total_paquets']:,}</div>
            </div>
            <div class="card">
                <h3>Volume Total</h3>
                <div class="value">{self.stats['total_volume_ko']:.2f} Ko</div>
            </div>
            <div class="card">
                <h3>Anomalies</h3>
                <div class="value">{len(self.anomalies)}</div>
            </div>
        </div>

        {self._html_anomalies()}
        
        <h2 class="section-title">Analyse Visuelle</h2>
        <div class="charts-grid">
            <div class="chart-box">
                <img src="1_vue_globale.png" alt="Graphique Vue Globale">
            </div>
            <div class="chart-box">
                <img src="2_analyse_sources.png" alt="Graphique Sources">
            </div>
        </div>
        
        <h2 class="section-title">Top 10 IP Sources</h2>
        <table>
            <thead>
                <tr>
                    <th width="10%">Rang</th>
                    <th width="30%">Adresse IP</th>
                    <th width="20%">Paquets</th>
                    <th width="40%">Activité Relative</th>
                </tr>
            </thead>
            <tbody>
                {self._html_table_ips()}
            </tbody>
        </table>
        
        <div class="footer">
            &copy; 2025 PyNetAnalyzer - SAE 1.05 | Généré automatiquement
        </div>
    </div>
</body>
</html>
"""
        chemin_html = os.path.join(self.output_dir, 'Rapport_Analyse.html')
        with open(chemin_html, 'w', encoding='utf-8') as f:
            f.write(html)
        return chemin_html

    def _html_anomalies(self):
        if not self.anomalies:
            return """
            <h2 class="section-title">État de Sécurité</h2>
            <div style="background: #e8f8f5; color: #0f5132; padding: 24px; border-radius: 12px; border: 1px solid #d1e7dd; display:flex; align-items:center; gap:15px;">
                <div style="font-size:2rem;">🛡️</div>
                <div>
                    <strong>Aucune anomalie détectée.</strong><br>
                    L'analyse sur la période donnée ne révèle pas de comportement suspect critique.
                </div>
            </div>
            """
        
        html = '<h2 class="section-title">Anomalies Détectées</h2><div class="anomalies-container">'
        for ano in self.anomalies:
            html += f"""
            <div class="anomaly-item">
                <div class="anomaly-content">
                    <span class="anomaly-type">{ano['type']}</span>
                    <div>
                        <span class="anomaly-ip">{ano['ip']}</span>
                        <span style="background:var(--bg-body); color:var(--text-muted); font-size:0.85em; padding:2px 8px; border-radius:4px; margin-right:10px; border:1px solid #e0e0e0;">
                            🕒 {ano['periode']}
                        </span>
                        <span>{ano['details']}</span>
                    </div>
                </div>
                <div class="anomaly-badge">{ano['gravite']}</div>
            </div>
            """
        html += '</div>'
        return html

    def _html_table_ips(self):
        rows = ""
        if self.stats['total_paquets'] == 0:
            return "<tr><td colspan='4'>Aucune donnée</td></tr>"
            
        total = self.stats['total_paquets']
        for i, (ip, count) in enumerate(self.stats['top_ips_src'], 1):
             pct = (count / total) * 100
             rows += f"""
             <tr>
                 <td><strong>{i}</strong></td>
                 <td><code>{ip}</code></td>
                 <td>{count}</td>
                 <td>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill" style="width:{pct}%"></div>
                    </div>
                    {pct:.1f}%
                 </td>
             </tr>
             """
        return rows

# ==========================================
# Interface Graphique
# ==========================================
def lancer():
    f = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
    if not f: return
    
    app = NetworkAnalyzer()
    lbl.config(text="Analyse en cours...", fg="blue")
    root.update()
    
    if app.charger_donnees(f):
        app.executer_analyse()
        app.detecter_anomalies()
        app.generer_graphiques()
        app.generer_rapport_md()
        chemin_html = app.generer_rapport_html()
        
        lbl.config(text="Terminé !", fg="green")
        
        # Ouverture automatique
        webbrowser.open('file://' + os.path.realpath(chemin_html))
        
        messagebox.showinfo("Succès", f"Rapport HTML généré et ouvert !\n\nFichiers sauvegardés dans :\n{BASE_DIR}")
        

    else:
        lbl.config(text="Erreur", fg="red")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("PyNetAnalyzer Standard")
    root.geometry("400x250")

    tk.Label(root, text="Analyseur Réseau (Version Standard)", font=("Arial", 14, "bold")).pack(pady=20)
    tk.Button(root, text="Charger CSV", command=lancer, bg="#3498db", fg="white", font=("Arial", 12), padx=20, pady=10).pack(pady=10)
    lbl = tk.Label(root, text="Prêt", fg="gray")
    lbl.pack(pady=10)

    root.mainloop()