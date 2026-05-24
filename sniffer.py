#!/usr/bin/env python3
import sys
import os
import threading
import time
from datetime import datetime
import customtkinter as ctk

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
except ImportError:
    print("[ERROR] Scapy n'est pas installé. Lancez : pip install scapy")
    sys.exit(1)

# Configuration de l'interface graphique (Thème sombre)
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class SnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CodeAlpha - Basic Network Sniffer (Dashboard)")
        self.geometry("1000x650")

        # Statistiques
        self.stats = {"TOTAL": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0}
        self.is_sniffing = False
        self.sniff_thread = None

        self.setup_ui()
        self.check_privileges()

    def check_privileges(self):
        """Vérification des droits Administrateur compatible Windows / Linux"""
        is_admin = False
        try:
            is_admin = os.getuid() == 0  # Linux
        except AttributeError:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows

        if not is_admin:
            self.log_box.insert("end",
                                "[⚠️ ATTENTION] Ce script doit être lancé en tant qu'ADMINISTRATEUR pour capturer les paquets.\n\n")

    def setup_ui(self):
        # --- HEADER ---
        self.header = ctk.CTkFrame(self, height=60, corner_radius=0, fg_color="#161b27")
        self.header.pack(fill="x", side="top")

        self.title_lbl = ctk.CTkLabel(self.header, text="🔍 CODEALPHA NETWORK SNIFFER",
                                      font=ctk.CTkFont(size=16, weight="bold"), text_color="#63b3ed")
        self.title_lbl.pack(side="left", padx=20, pady=15)

        self.status_badge = ctk.CTkLabel(self.header, text="● PAUSE", text_color="#a0aec0",
                                         font=ctk.CTkFont(weight="bold"))
        self.status_badge.pack(side="right", padx=20)

        # --- STATS CARDS ---
        self.stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.stats_frame.pack(fill="x", padx=20, pady=15)

        self.stat_widgets = {}
        colors = {"TOTAL": "#e2e8f0", "TCP": "#63b3ed", "UDP": "#f6ad55", "ICMP": "#fc8181", "ARP": "#b794f4"}

        for idx, (proto, color) in enumerate(colors.items()):
            card = ctk.CTkFrame(self.stats_frame, fg_color="#161b27", border_color="#2d3748", border_width=1, height=80)
            card.grid(row=0, column=idx, padx=5, sticky="ew")
            self.stats_frame.grid_columnconfigure(idx, weight=1)

            val_lbl = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=24, weight="bold"), text_color=color)
            val_lbl.pack(pady=(10, 0))

            lbl = ctk.CTkLabel(card, text=proto, font=ctk.CTkFont(size=11), text_color="#718096")
            lbl.pack(pady=(0, 10))

            self.stat_widgets[proto] = val_lbl

        # --- MAIN DISPLAY (PACKET LOG) ---
        self.main_frame = ctk.CTkFrame(self, fg_color="#161b27", border_color="#2d3748", border_width=1)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.log_box = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Courier New", size=12),
                                      text_color="#cbd5e0", fg_color="transparent")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)

        # --- CONTROLS FOOTER ---
        self.controls_frame = ctk.CTkFrame(self, height=60, fg_color="transparent")
        self.controls_frame.pack(fill="x", padx=20, pady=15, side="bottom")

        self.start_btn = ctk.CTkButton(self.controls_frame, text="Démarrer Capture", fg_color="#2b6cb0",
                                       hover_color="#2c5282", command=self.toggle_capture)
        self.start_btn.pack(side="left", padx=5)

        self.clear_btn = ctk.CTkButton(self.controls_frame, text="Vider", fg_color="#9b2c2c", hover_color="#742a2a",
                                       command=self.clear_logs)
        self.clear_btn.pack(side="left", padx=5)

    def toggle_capture(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.start_btn.configure(text="Pause", fg_color="#4a5568", hover_color="#2d3748")
            self.status_badge.configure(text="● LIVE", text_color="#68d391")

            # Lancer le sniffing dans un thread séparé pour éviter de figer l'IHM
            self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
            self.sniff_thread.start()
        else:
            self.is_sniffing = False
            self.start_btn.configure(text="Reprendre Capture", fg_color="#2b6cb0", hover_color="#2c5282")
            self.status_badge.configure(text="● PAUSE", text_color="#a0aec0")

    def start_sniffing(self):
        # La fonction stop_filter permet d'arrêter proprement Scapy quand on clique sur Pause
        sniff(prn=self.packet_callback, stop_filter=lambda p: not self.is_sniffing, store=False)

    def packet_callback(self, packet):
        self.stats["TOTAL"] += 1
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        proto_detected = "OTHER"
        msg = ""

        # Analyse ARP
        if packet.haslayer(ARP):
            self.stats["ARP"] += 1
            arp = packet[ARP]
            op = "REQ" if arp.op == 1 else "REP"
            msg = f"[{ts}] 📡 ARP {op:<4} | {arp.psrc} -> {arp.pdst}\n"

        # Analyse IP (TCP / UDP / ICMP)
        elif packet.haslayer(IP):
            ip = packet[IP]
            src, dst = ip.src, ip.dst

            if packet.haslayer(TCP):
                self.stats["TCP"] += 1
                tcp = packet[TCP]
                msg = f"[{ts}] 🔵 TCP      | {src}:{tcp.sport} -> {dst}:{tcp.dport} [{tcp.sprintf('%flags%')}]\n"
            elif packet.haslayer(UDP):
                self.stats["UDP"] += 1
                udp = packet[UDP]
                msg = f"[{ts}] 🟡 UDP      | {src}:{udp.sport} -> {dst}:{udp.dport}\n"
            elif packet.haslayer(ICMP):
                self.stats["ICMP"] += 1
                msg = f"[{ts}] 🔴 ICMP     | {src} -> {dst}\n"
            else:
                msg = f"[{ts}] ⚪ IP       | {src} -> {dst} (Proto: {ip.proto})\n"

        if msg:
            # Mettre à jour l'IHM de manière sécurisée depuis le thread
            self.log_box.insert("end", msg)
            self.log_box.see("end")
            self.update_counters()

    def update_counters(self):
        for proto, widget in self.stat_widgets.items():
            widget.configure(text=str(self.stats[proto]))

    def clear_logs(self):
        self.log_box.delete("1.0", "end")
        self.stats = {"TOTAL": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0}
        self.update_counters()


if __name__ == "__main__":
    app = SnifferApp()
    app.mainloop()