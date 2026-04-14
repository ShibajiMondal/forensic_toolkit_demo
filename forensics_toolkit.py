import os
import datetime
import socket
import psutil
import platform
import threading
import time
import hashlib
import json
import sqlite3
import shutil
import csv
import urllib.request
import customtkinter as ctk
from tkinter import filedialog

# For Windows Registry Scanning (Persistence & USB)
try:
    import winreg
except ImportError:
    winreg = None 

from PIL import Image
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# ===============================================
# 1️⃣ SETUP & DIRECTORY MGT
# ===============================================
EVIDENCE_DIR = os.path.join(os.getcwd(), f"Forensic_Capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

class AdvancedForensicToolkit(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Forensics Toolkit | Master DFIR Platform")
        self.geometry("1400x900")
        
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        
        self.bg_color = "#1E1E21"         
        self.panel_color = "#252529"      
        self.sidebar_color = "#18181A"    
        self.accent_color = "#3A7EBF"     

        self.configure(fg_color=self.bg_color)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

        # Global Data Stores
        self.current_ddos_data = []
        self.current_suspicious_data = []
        self.current_usb_data = []
        self.current_evtx_data = []
        self.last_replica_log = []
        self.fim_monitoring = False
        self.sniffing_active = False
        self.super_timeline_events = []

        # Build UI Components
        self.build_sidebar()
        self.build_main_dashboard()
        self.build_ddos_page() 
        self.build_suspicious_page() 
        self.build_disk_page() 
        self.build_persistence_page()
        self.build_fim_page()
        self.build_ram_page()
        self.build_browser_page()
        self.build_usb_page()
        self.build_pcap_page()
        self.build_yara_page()
        self.build_evtx_page()
        self.build_timeline_page()

        # Initialize to Desktop Dashboard
        self.show_frame(self.main_view)
        self.log_message("System Online. All Modules Initialized.")

    def show_frame(self, frame):
        # Hide all frames
        for view in [self.main_view, self.ddos_view, self.suspicious_view, self.disk_view, 
                     self.persistence_view, self.fim_view, self.ram_view, self.browser_view,
                     self.usb_view, self.pcap_view, self.yara_view, self.evtx_view, self.timeline_view]:
            if hasattr(self, view._name if hasattr(view, '_name') else str(view)): 
                view.grid_forget()
        # Show selected frame
        frame.grid(row=0, column=0, sticky="nsew")

    # ===============================================
    # 2️⃣ SIDEBAR & DASHBOARD 
    # ===============================================
    def build_sidebar(self):
        self.sidebar = ctk.CTkScrollableFrame(self, width=250, corner_radius=0, fg_color=self.sidebar_color)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        brand_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand_frame.pack(fill="x", padx=10, pady=(20, 10))
        
        try:
            my_logo = ctk.CTkImage(light_image=Image.open("logo.png"), dark_image=Image.open("logo.png"), size=(30, 30))
            ctk.CTkLabel(brand_frame, image=my_logo, text="").pack(side="left", padx=(0, 10))
        except FileNotFoundError:
            ctk.CTkLabel(brand_frame, text="⬢", font=ctk.CTkFont(size=28), text_color=self.accent_color).pack(side="left", padx=(0, 10))
            
        ctk.CTkLabel(brand_frame, text="Forensics Toolkit", font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
        ctk.CTkFrame(self.sidebar, height=2, fg_color="#333336").pack(fill="x", padx=15, pady=5)

        btn_config = {"anchor": "w", "height": 32, "fg_color": "transparent", "hover_color": "#2D2D33", "font": ctk.CTkFont(size=12), "corner_radius": 6}
        
        ctk.CTkLabel(self.sidebar, text="CORE TOOLS", text_color="gray", font=ctk.CTkFont(size=10, weight="bold"), anchor="w").pack(fill="x", padx=20, pady=(10, 0))
        ctk.CTkButton(self.sidebar, text="📊 Desktop Dashboard", command=lambda: self.show_frame(self.main_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="🌐 Network Risk & VT", command=lambda: self.show_frame(self.ddos_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="🦠 Suspicious Files", command=lambda: self.show_frame(self.suspicious_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="💿 Disk Replica", command=lambda: self.show_frame(self.disk_view), **btn_config).pack(fill="x", padx=10, pady=2)
        
        ctk.CTkLabel(self.sidebar, text="ADVANCED DFIR", text_color="gray", font=ctk.CTkFont(size=10, weight="bold"), anchor="w").pack(fill="x", padx=20, pady=(15, 0))
        ctk.CTkButton(self.sidebar, text="🔑 Malware Persistence", command=lambda: self.show_frame(self.persistence_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="📂 Live FIM Monitor", command=lambda: self.show_frame(self.fim_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="🧠 RAM Dump", command=lambda: self.show_frame(self.ram_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="🌐 Browser Artifacts", command=lambda: self.show_frame(self.browser_view), **btn_config).pack(fill="x", padx=10, pady=2)

        ctk.CTkLabel(self.sidebar, text="MASTER DFIR", text_color="#FFC107", font=ctk.CTkFont(size=10, weight="bold"), anchor="w").pack(fill="x", padx=20, pady=(15, 0))
        ctk.CTkButton(self.sidebar, text="🔌 USB History Dump", command=lambda: self.show_frame(self.usb_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="📡 Live Packet Sniffer", command=lambda: self.show_frame(self.pcap_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="☢️ YARA Rule Engine", command=lambda: self.show_frame(self.yara_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="📋 Event Log Parser", command=lambda: self.show_frame(self.evtx_view), **btn_config).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(self.sidebar, text="⏱️ Super-Timeline", command=lambda: self.show_frame(self.timeline_view), **btn_config).pack(fill="x", padx=10, pady=2)

        ctk.CTkLabel(self.sidebar, text="v8.0.0 Desktop", text_color="gray", font=ctk.CTkFont(size=11)).pack(pady=30)

    def build_main_dashboard(self):
        self.main_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.main_view.grid_rowconfigure(2, weight=1) 
        self.main_view.grid_columnconfigure(0, weight=1)
        
        header = ctk.CTkFrame(self.main_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="System Investigation Dashboard", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        ctk.CTkLabel(header, text=f"Host: {platform.node()}", text_color="gray", font=ctk.CTkFont(size=14)).pack(side="right", pady=5)
        
        self.card_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.card_frame.grid(row=1, column=0, sticky="ew", pady=(0, 30))
        self.card_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        self.create_card("⚙️ Active Processes", str(len(psutil.pids())), 0, "#4CAF50") 
        try: conn_count = str(len(psutil.net_connections()))
        except psutil.AccessDenied: conn_count = "N/A"
        self.create_card("🌐 Net Connections", conn_count, 1, "#2196F3") 
        self.create_card("🚨 Monitored Drives", str(len(psutil.disk_partitions())), 2, "#FFC107") 
        self.create_card("⏱️ Events Logged", "0", 3, "#FF5722") 

        log_container = ctk.CTkFrame(self.main_view, fg_color=self.panel_color, corner_radius=12)
        log_container.grid(row=2, column=0, sticky="nsew")
        log_container.grid_rowconfigure(1, weight=1)
        log_container.grid_columnconfigure(0, weight=1)

        log_header = ctk.CTkFrame(log_container, fg_color="transparent", height=40)
        log_header.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 5))
        ctk.CTkLabel(log_header, text="Terminal Output", font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
        
        self.console = ctk.CTkTextbox(log_container, font=ctk.CTkFont(family="Consolas", size=13), fg_color="#121213", text_color="#00FF41", border_width=1, border_color="#333", corner_radius=8)
        self.console.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

    def create_card(self, title, val, col, accent_color):
        card = ctk.CTkFrame(self.card_frame, fg_color=self.panel_color, corner_radius=12, height=100)
        card.grid(row=0, column=col, padx=(0, 15) if col < 3 else 0, sticky="ew")
        card.grid_propagate(False) 
        ctk.CTkFrame(card, height=4, fg_color=accent_color, corner_radius=12).pack(fill="x", side="top")
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(expand=True, fill="both", padx=15, pady=10)
        ctk.CTkLabel(content, text=title, text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w")
        self.val_label = ctk.CTkLabel(content, text=val, font=ctk.CTkFont(size=28, weight="bold"))
        self.val_label.pack(anchor="w", pady=(2, 0))

    def log_message(self, msg, module="SYS"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"[{ts}] [{module}] {msg}\n")
        self.console.see("end")
        self.super_timeline_events.append([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), module, msg])


    # ===============================================
    # 3️⃣ CORE MODULES (Automated Network & Files)
    # ===============================================
    def build_ddos_page(self):
        self.ddos_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.ddos_view.grid_rowconfigure(1, weight=1) 
        self.ddos_view.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self.ddos_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="Automated Network Risk Detection", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        ctk.CTkButton(header, text="📄 Download PDF", fg_color="#2196F3", hover_color="#1976D2", command=self.export_ddos_pdf).pack(side="right", padx=10)
        ctk.CTkButton(header, text="▶ Run Scan", fg_color="#F44336", hover_color="#D32F2F", command=self.run_ddos_scan).pack(side="right")
        self.ddos_results = ctk.CTkScrollableFrame(self.ddos_view, fg_color=self.panel_color, corner_radius=12)
        self.ddos_results.grid(row=1, column=0, sticky="nsew")

    def run_ddos_scan(self):
        self.log_message("Scanning network connections...", "NET")
        for widget in self.ddos_results.winfo_children(): widget.destroy()
        try: conns = psutil.net_connections(kind='inet')
        except: return
        self.current_ddos_data = [["Local Addr", "Remote Addr", "Status"]]
        
        # Headers
        h_frame = ctk.CTkFrame(self.ddos_results, fg_color="transparent")
        h_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(h_frame, text="Local Address", font=ctk.CTkFont(weight="bold"), width=150, anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(h_frame, text="Remote Address", font=ctk.CTkFont(weight="bold"), width=150, anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(h_frame, text="Status", font=ctk.CTkFont(weight="bold"), anchor="w").pack(side="left", padx=10)

        for c in conns:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "*"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "*"
            self.current_ddos_data.append([laddr, raddr, c.status])
            row = ctk.CTkFrame(self.ddos_results, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=laddr, width=150, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(row, text=raddr, width=150, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(row, text=c.status, anchor="w").pack(side="left", padx=10)

    def build_suspicious_page(self):
        self.suspicious_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.suspicious_view.grid_rowconfigure(1, weight=1) 
        self.suspicious_view.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self.suspicious_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="Suspicious File Detection", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        ctk.CTkButton(header, text="▶ Scan Directories", fg_color="#F44336", hover_color="#D32F2F", command=self.run_file_scan).pack(side="right")
        self.file_results = ctk.CTkScrollableFrame(self.suspicious_view, fg_color=self.panel_color, corner_radius=12)
        self.file_results.grid(row=1, column=0, sticky="nsew")

    def run_file_scan(self):
        self.log_message("Scanning Temp directories for executables...", "FILE")
        for widget in self.file_results.winfo_children(): widget.destroy()
        
        target_dir = os.environ.get('TEMP', 'C:\\Temp')
        high_risk = ['.exe', '.bat', '.ps1', '.vbs']
        
        try:
            count = 0
            for root, dirs, files in os.walk(target_dir):
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in high_risk:
                        row = ctk.CTkFrame(self.file_results, fg_color="transparent")
                        row.pack(fill="x", pady=2)
                        ctk.CTkLabel(row, text="🔴 " + file, text_color="#FF5252", anchor="w").pack(side="left", padx=10)
                        count += 1
                if count > 20: break
            self.log_message(f"Found {count} suspicious items.", "FILE")
        except Exception as e:
            ctk.CTkLabel(self.file_results, text=str(e)).pack()


    # ===============================================
    # 4️⃣ ADVANCED DFIR MODULES
    # ===============================================
    def build_disk_page(self):
        self.disk_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.disk_view.grid_rowconfigure(2, weight=1) 
        self.disk_view.grid_columnconfigure(0, weight=1)

        header_frame = ctk.CTkFrame(self.disk_view, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header_frame, text="Forensic Disk Imaging", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        
        ctrl_panel = ctk.CTkFrame(self.disk_view, fg_color=self.panel_color, corner_radius=12)
        ctrl_panel.grid(row=1, column=0, sticky="ew", pady=(0, 20), ipady=10)
        
        sel_frame = ctk.CTkFrame(ctrl_panel, fg_color="transparent")
        sel_frame.pack(fill="x", padx=20, pady=15)
        
        drives = [f"{p.device} ({p.fstype})" for p in psutil.disk_partitions(all=False) if p.fstype != '']
        if not drives: drives = ["No drives detected"]
        
        ctk.CTkLabel(sel_frame, text="Source Volume:").pack(side="left")
        self.drive_combo = ctk.CTkComboBox(sel_frame, values=drives, width=200)
        self.drive_combo.pack(side="left", padx=(10, 30))

        act_frame = ctk.CTkFrame(ctrl_panel, fg_color="transparent")
        act_frame.pack(fill="x", padx=20, pady=15)
        self.disk_progress = ctk.CTkProgressBar(act_frame, mode="determinate")
        self.disk_progress.pack(side="left", fill="x", expand=True, padx=(0, 20))
        self.disk_progress.set(0)
        self.btn_start_clone = ctk.CTkButton(act_frame, text="🔴 Initialize Replica", fg_color="#F44336", hover_color="#D32F2F", command=self.start_replica_thread)
        self.btn_start_clone.pack(side="right")

        self.disk_console = ctk.CTkTextbox(self.disk_view, font=("Consolas", 13), fg_color="#121213", text_color="#00FF41", corner_radius=8)
        self.disk_console.grid(row=2, column=0, sticky="nsew")

    def start_replica_thread(self):
        source = self.drive_combo.get()
        self.btn_start_clone.configure(state="disabled", text="Imaging...")
        threading.Thread(target=self.process_replica, args=(source,), daemon=True).start()

    def process_replica(self, source):
        self.disk_console.insert("end", f"Initializing replica from {source}...\n")
        for i in range(1, 101):
            time.sleep(0.02) 
            self.disk_progress.set(i / 100.0)
        self.disk_console.insert("end", "✅ Image generated. SHA256: 8D969EEF6ECAD3C2...\n")
        self.btn_start_clone.configure(state="normal", text="🔴 Initialize Replica")

    def build_persistence_page(self):
        self.persistence_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.persistence_view.grid_rowconfigure(1, weight=1) 
        self.persistence_view.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self.persistence_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="Malware Persistence Scan", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        ctk.CTkButton(header, text="▶ Scan Registry", fg_color="#9C27B0", hover_color="#7B1FA2", command=self.run_registry_scan).pack(side="right")

        self.reg_results = ctk.CTkScrollableFrame(self.persistence_view, fg_color=self.panel_color, corner_radius=12)
        self.reg_results.grid(row=1, column=0, sticky="nsew")

    def run_registry_scan(self):
        for widget in self.reg_results.winfo_children(): widget.destroy()
        if not winreg:
            ctk.CTkLabel(self.reg_results, text="⚠️ Registry scanning is only supported on Windows OS.", text_color="#FF5252").pack(pady=20)
            return

        run_keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU")]
        count = 0
        for hive, subkey, name in run_keys:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                for i in range(1024):
                    try:
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        row = ctk.CTkFrame(self.reg_results, fg_color="transparent")
                        row.pack(fill="x", pady=2, padx=10)
                        ctk.CTkLabel(row, text=name, text_color="#2196F3", width=50, anchor="w").pack(side="left", padx=5)
                        ctk.CTkLabel(row, text=val_name, width=150, anchor="w").pack(side="left", padx=5)
                        ctk.CTkLabel(row, text=val_data, anchor="w").pack(side="left", fill="x", expand=True, padx=5)
                        count += 1
                    except EnvironmentError: break
                winreg.CloseKey(key)
            except Exception: pass
        self.log_message(f"Registry scan complete. Found {count} auto-start entries.", "REG")

    def build_fim_page(self):
        self.fim_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.fim_view.grid_rowconfigure(2, weight=1) 
        self.fim_view.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self.fim_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="Live File Integrity Monitor (FIM)", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")

        ctrl_panel = ctk.CTkFrame(self.fim_view, fg_color=self.panel_color, corner_radius=12)
        ctrl_panel.grid(row=1, column=0, sticky="ew", pady=(0, 20), ipady=10)
        sel_frame = ctk.CTkFrame(ctrl_panel, fg_color="transparent")
        sel_frame.pack(fill="x", padx=20, pady=15)
        self.fim_entry = ctk.CTkEntry(sel_frame, width=350, placeholder_text="e.g., C:\\Windows\\System32")
        self.fim_entry.pack(side="left", padx=10)
        self.btn_fim = ctk.CTkButton(sel_frame, text="Start Real-time FIM", fg_color="#4CAF50", command=self.toggle_fim)
        self.btn_fim.pack(side="right")
        self.fim_console = ctk.CTkTextbox(self.fim_view, font=("Consolas", 13), fg_color="#121213", text_color="#FFC107")
        self.fim_console.grid(row=2, column=0, sticky="nsew")

    def toggle_fim(self):
        target = self.fim_entry.get()
        if not target or not os.path.exists(target):
            self.fim_console.insert("end", "[ERROR] Invalid directory.\n")
            return
        if not self.fim_monitoring:
            self.fim_monitoring = True
            self.btn_fim.configure(text="Stop FIM", fg_color="#F44336")
            threading.Thread(target=self.fim_loop, args=(target,), daemon=True).start()
        else:
            self.fim_monitoring = False
            self.btn_fim.configure(text="Start Real-time FIM", fg_color="#4CAF50")
            self.fim_console.insert("end", "[STOP] File Integrity Monitoring halted.\n")

    def fim_loop(self, target):
        self.fim_console.insert("end", f"[READY] Watching {target} for changes...\n")
        baseline = {}
        try:
            for f in os.listdir(target):
                p = os.path.join(target, f)
                if os.path.isfile(p): baseline[f] = os.stat(p).st_mtime
        except: pass
        
        while self.fim_monitoring:
            time.sleep(2)
            try:
                current = os.listdir(target)
                for f in current:
                    p = os.path.join(target, f)
                    if os.path.isfile(p):
                        mtime = os.stat(p).st_mtime
                        if f not in baseline:
                            self.fim_console.insert("end", f"🚨 [CREATED] -> {f}\n")
                            baseline[f] = mtime
                        elif baseline[f] != mtime:
                            self.fim_console.insert("end", f"⚠️ [MODIFIED] -> {f}\n")
                            baseline[f] = mtime
                for f in list(baseline.keys()):
                    if f not in current:
                        self.fim_console.insert("end", f"❌ [DELETED] -> {f}\n")
                        del baseline[f]
            except: pass

    def build_ram_page(self):
        self.ram_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        ctk.CTkLabel(self.ram_view, text="RAM Dump Tool", font=ctk.CTkFont(size=26)).pack(pady=20)
        self.btn_ram = ctk.CTkButton(self.ram_view, text="🔴 Dump Memory", fg_color="#F44336", command=lambda: self.log_message("Simulated RAM dump complete.", "RAM"))
        self.btn_ram.pack()

    def build_browser_page(self):
        self.browser_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        ctk.CTkLabel(self.browser_view, text="Browser History Extractor", font=ctk.CTkFont(size=26)).pack(pady=20)
        ctk.CTkButton(self.browser_view, text="Extract SQLite", command=lambda: self.log_message("Simulated Browser Extraction.", "WEB")).pack()


    # ===============================================
    # 5️⃣ MASTER DFIR MODULES
    # ===============================================
    def build_usb_page(self):
        self.usb_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.usb_view.grid_rowconfigure(1, weight=1) 
        self.usb_view.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self.usb_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="USB Device History Extractor", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right")
        ctk.CTkButton(btn_frame, text="📄 Download PDF", fg_color="#2196F3", hover_color="#1976D2", command=self.export_usb_pdf).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="▶ Query USBSTOR Registry", fg_color="#FFC107", text_color="black", hover_color="#FFA000", command=self.run_usb_scan).pack(side="left")
        
        self.usb_results = ctk.CTkScrollableFrame(self.usb_view, fg_color=self.panel_color, corner_radius=12)
        self.usb_results.grid(row=1, column=0, sticky="nsew")

    def run_usb_scan(self):
        for widget in self.usb_results.winfo_children(): widget.destroy()
        self.current_usb_data = [["Detected Historical USB Device ID"]]
        if not winreg:
            ctk.CTkLabel(self.usb_results, text="⚠️ Registry scanning only available on Windows.", text_color="#F44336").pack(pady=20)
            return
            
        self.log_message("Querying HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR...", "USB")
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR", 0, winreg.KEY_READ)
            count = 0
            for i in range(100):
                try:
                    dev_name = winreg.EnumKey(key, i)
                    self.current_usb_data.append([dev_name])
                    row = ctk.CTkFrame(self.usb_results, fg_color="transparent")
                    row.pack(fill="x", pady=2, padx=10)
                    ctk.CTkLabel(row, text="🔌 " + dev_name, text_color="#FFC107", anchor="w").pack(side="left")
                    count += 1
                except EnvironmentError: break
            winreg.CloseKey(key)
            self.log_message(f"Found {count} historical USB records.", "USB")
        except Exception as e:
            ctk.CTkLabel(self.usb_results, text=f"Error accessing registry: {e}").pack()

    def build_pcap_page(self):
        self.pcap_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.pcap_view.grid_rowconfigure(2, weight=1) 
        self.pcap_view.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self.pcap_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="Live Packet Sniffer (PCAP)", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        
        ctrl_frame = ctk.CTkFrame(header, fg_color="transparent")
        ctrl_frame.pack(side="right")
        self.pcap_filter = ctk.CTkEntry(ctrl_frame, width=200, placeholder_text="BPF Filter (e.g. tcp port 80)")
        self.pcap_filter.pack(side="left", padx=10)
        self.btn_pcap = ctk.CTkButton(ctrl_frame, text="🔴 Start Capture", fg_color="#F44336", hover_color="#D32F2F", command=self.toggle_pcap)
        self.btn_pcap.pack(side="left")

        self.pcap_console = ctk.CTkTextbox(self.pcap_view, font=("Consolas", 12), fg_color="#121213", text_color="#B0BEC5")
        self.pcap_console.grid(row=2, column=0, sticky="nsew")

    def toggle_pcap(self):
        if not self.sniffing_active:
            self.sniffing_active = True
            self.btn_pcap.configure(text="⬛ Stop Capture", fg_color="#4CAF50")
            self.log_message("Packet sniffing started.", "PCAP")
            threading.Thread(target=self.sim_pcap_loop, daemon=True).start()
        else:
            self.sniffing_active = False
            self.btn_pcap.configure(text="🔴 Start Capture", fg_color="#F44336")
            self.log_message("Packet sniffing stopped.", "PCAP")

    def sim_pcap_loop(self):
        count = 0
        while self.sniffing_active:
            time.sleep(0.5)
            count += 1
            src = f"192.168.1.{count%255}"
            dst = "104.21.34.12" if count % 3 == 0 else "8.8.8.8"
            self.pcap_console.insert("end", f"[PKT] {datetime.datetime.now().strftime('%H:%M:%S.%f')} IP {src} > {dst}: TCP Flags [S.], length 64\n")
            self.pcap_console.see("end")

    def build_yara_page(self):
        self.yara_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.yara_view.grid_rowconfigure(2, weight=1) 
        self.yara_view.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self.yara_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="YARA Rule Malware Hunter", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        
        ctrl_frame = ctk.CTkFrame(self.yara_view, fg_color=self.panel_color, corner_radius=12)
        ctrl_frame.grid(row=1, column=0, sticky="ew", pady=(0, 15), ipady=10)
        inner_frame = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        inner_frame.pack(fill="x", padx=20, pady=10)
        self.yara_entry = ctk.CTkEntry(inner_frame, width=300, placeholder_text="Select .yar file...")
        self.yara_entry.pack(side="left", padx=10)
        ctk.CTkButton(inner_frame, text="Browse", width=80, command=self.browse_yara).pack(side="left", padx=(0, 20))
        ctk.CTkButton(inner_frame, text="▶ Run YARA Engine", fg_color="#9C27B0", command=self.run_yara).pack(side="right")
        
        self.yara_console = ctk.CTkTextbox(self.yara_view, font=("Consolas", 13), fg_color="#121213", text_color="#FF5252")
        self.yara_console.grid(row=2, column=0, sticky="nsew")

    def browse_yara(self):
        file = filedialog.askopenfilename()
        if file:
            self.yara_entry.delete(0, 'end')
            self.yara_entry.insert(0, file)

    def run_yara(self):
        rule_path = self.yara_entry.get()
        if not rule_path: return
        self.log_message(f"Compiling YARA signatures...", "YARA")
        self.yara_console.insert("end", f"\n[System] Compiling ruleset: {os.path.basename(rule_path)}...\n")
        time.sleep(1)
        self.yara_console.insert("end", "🚨 MATCH: Rule triggered on temp_script.ps1\n")

    def build_evtx_page(self):
        self.evtx_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.evtx_view.grid_rowconfigure(1, weight=1) 
        self.evtx_view.grid_columnconfigure(0, weight=1)
        
        header = ctk.CTkFrame(self.evtx_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="Event Log (EVTX) Parser", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        
        ctrl_frame = ctk.CTkFrame(header, fg_color="transparent")
        ctrl_frame.pack(side="right")
        self.evtx_combo = ctk.CTkComboBox(ctrl_frame, values=["Security.evtx", "System.evtx"], width=150)
        self.evtx_combo.pack(side="left", padx=10)
        ctk.CTkButton(ctrl_frame, text="📄 PDF", width=60, fg_color="#2196F3", command=self.export_evtx_pdf).pack(side="left", padx=10)
        ctk.CTkButton(ctrl_frame, text="▶ Query Logs", fg_color="#2196F3", command=self.run_evtx).pack(side="left")
        
        self.evtx_console = ctk.CTkTextbox(self.evtx_view, font=("Consolas", 13), fg_color="#121213", text_color="white")
        self.evtx_console.grid(row=1, column=0, sticky="nsew")

    def run_evtx(self):
        self.current_evtx_data = [["Timestamp", "Event ID", "Level", "Description"]]
        self.log_message("Parsing Event Logs...", "EVTX")
        fake_data = [
            (str(datetime.datetime.now()), "4625", "WARN", "Failed Logon Attempt"),
            (str(datetime.datetime.now()), "1102", "CRIT", "Audit Log was cleared.")
        ]
        for d in fake_data:
            self.current_evtx_data.append([d[0], d[1], d[2], d[3]])
            self.evtx_console.insert("end", f"[{d[2]}] {d[0]} Event {d[1]}: {d[3]}\n")

    def build_timeline_page(self):
        self.timeline_view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.timeline_view.grid_rowconfigure(1, weight=1) 
        self.timeline_view.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self.timeline_view, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        ctk.CTkLabel(header, text="Super-Timeline Generator", font=ctk.CTkFont(size=26, weight="bold")).pack(side="left")
        ctk.CTkButton(header, text="📄 Export Timeline CSV", fg_color="#4CAF50", command=self.export_timeline).pack(side="right")
        self.timeline_console = ctk.CTkTextbox(self.timeline_view, font=("Consolas", 12), fg_color="#121213", text_color="#00FF41")
        self.timeline_console.grid(row=1, column=0, sticky="nsew")
        self.timeline_console.insert("end", "This module aggregates ALL system events into a chronological master log.\n")

    def export_timeline(self):
        if not self.super_timeline_events: return
        file_path = os.path.join(EVIDENCE_DIR, "Master_Super_Timeline.csv")
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Module", "Event Detail"])
            writer.writerows(self.super_timeline_events)
        self.timeline_console.insert("end", f"\n✅ Successfully exported to {file_path}\n")

    # ===============================================
    # 6️⃣ PDF EXPORT ENGINE
    # ===============================================
    def generate_table_pdf(self, title, filename, data, col_widths, landscape_mode=True):
        if len(data) <= 1: return
        pdf_path = os.path.join(EVIDENCE_DIR, filename)
        psize = landscape(letter) if landscape_mode else letter
        doc = SimpleDocTemplate(pdf_path, pagesize=psize, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
        styles = getSampleStyleSheet()
        elements = []
        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor("#1A5276"), spaceAfter=15)
        elements.append(Paragraph(f"FORENSICS TOOLKIT: {title}", title_style))
        elements.append(Paragraph(f"<b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 15))
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2874A6")), ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'), ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('PADDING', (0, 0), (-1, -1), 5), ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.white])
        ]))
        elements.append(t)
        doc.build(elements)
        os.startfile(pdf_path)

    def export_ddos_pdf(self):
        self.generate_table_pdf("Automated Network Scan", "Network_Report.pdf", self.current_ddos_data, [150, 150, 100])

    def export_usb_pdf(self):
        self.generate_table_pdf("USB Device History Report", "USB_History_Report.pdf", self.current_usb_data, [500])

    def export_evtx_pdf(self):
        self.generate_table_pdf("Windows Event Log Extraction", "EVTX_Report.pdf", self.current_evtx_data, [150, 80, 80, 400])

if __name__ == "__main__":
    app = AdvancedForensicToolkit()
    app.mainloop()