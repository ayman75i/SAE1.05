import tkinter as tk
from tkinter import filedialog, messagebox
import re

def trouver_ip_et_port(texte):
    # Nettoyage et extraction de l'IP et du Port
    texte = texte.replace(':', '').replace('>', '').strip()
    position = texte.rfind('.')
    if position == -1: return texte, 'N/A'
    
    ip, port = texte[:position], texte[position + 1:]
    # Conversion des ports textuels
    ports_map = {'ssh': '22', 'http': '80', 'https': '443'}
    return ip, ports_map.get(port, port)

def chercher_valeur(mots, mot_a_chercher):
    try:
        idx = mots.index(mot_a_chercher)
        valeur = mots[idx + 1].replace(',', '')
        return valeur.split(':')[0] if (mot_a_chercher == 'seq' or mot_a_chercher == 'length') else valeur
    except (ValueError, IndexError):
        return 'N/A'

def analyser_ligne(ligne):
    if 'IP' not in ligne or ligne.strip().startswith('0x'): return None
    
    mots = ligne.split()
    if len(mots) < 5: return None

    # Extraction des flags via Regex (plus simple que find/index)
    flags_match = re.search(r'Flags \[(.*?)\]', ligne)
    flags = flags_match.group(1) if flags_match else 'N/A'

    # Destination : mot 4 si le mot 3 est '>', sinon mot 3
    idx_dest = 4 if mots[3] == '>' else 3
    ip_src, port_src = trouver_ip_et_port(mots[2])
    ip_dst, port_dst = trouver_ip_et_port(mots[idx_dest])

    return {
        'heure': mots[0], 'protocole': mots[1],
        'ip_src': ip_src, 'port_src': port_src,
        'ip_dst': ip_dst, 'port_dst': port_dst,
        'flags': flags, 'seq': chercher_valeur(mots, 'seq'),
        'ack': chercher_valeur(mots, 'ack'), 'win': chercher_valeur(mots, 'win'),
        'len': chercher_valeur(mots, 'length')
    }

def convertir(f_in, f_out):
    paquets = []
    with open(f_in, 'r', encoding='utf-8', errors='ignore') as f:
        for ligne in f:
            res = analyser_ligne(ligne)
            if res: paquets.append(res)

    if not paquets: return 0

    with open(f_out, 'w', encoding='utf-8') as f:
        f.write("Timestamp;Protocole;IP Source;Port Source;IP Destination;Port Destination;Flags;Seq;Ack;Window;Length\n")
        for p in paquets:
            f.write(f"{p['heure']};{p['protocole']};{p['ip_src']};{p['port_src']};{p['ip_dst']};{p['port_dst']};"
                    f"{p['flags']};{p['seq']};{p['ack']};{p['win']};{p['len']}\n")
    return len(paquets)

def bouton_choisir():
    f_in = filedialog.askopenfilename(filetypes=[("Texte", "*.txt"), ("Tous", "*.*")])
    if not f_in: return
    
    f_out = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
    if f_out:
        nb = convertir(f_in, f_out)
        if nb > 0:
            messagebox.showinfo("Succès", f"{nb} paquets extraits dans :\n{f_out}")
            label_info.config(text="✓ Terminé", fg="green")
        else:
            messagebox.showerror("Erreur", "Aucune donnée trouvée")

# --- Interface Graphique ---
app = tk.Tk()
app.title("SAE 1.05 - Convertisseur")
app.geometry("400x250")

tk.Label(app, text="TCPDUMP vers CSV", font=("Arial", 12, "bold")).pack(pady=20)
tk.Button(app, text="Sélectionner un fichier", command=bouton_choisir, bg="#3498db", fg="white", pady=5).pack()
label_info = tk.Label(app, text="En attente...", fg="gray")
label_info.pack(pady=20)
tk.Button(app, text="Quitter", command=app.destroy).pack()

app.mainloop()