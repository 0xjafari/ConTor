#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ConTor - Connect Tor + DNS Scanner + Local DNS Proxy
Version: 5.3 (Ultra UI) - Fixed Top Bar, All Features Complete
"""

import os
import sys
import json
import time
import random
import struct
import socket
import ssl
import threading
import subprocess
import ipaddress
import platform
import csv
import webbrowser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import *
from tkinter import ttk, messagebox, scrolledtext, filedialog

try:
    from stem import Signal
    from stem.control import Controller
except ImportError:
    print("Please install stem: pip install stem")
    sys.exit(1)

# ========== ToolTip Class ==========
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind('<Enter>', self.show_tip)
        widget.bind('<Leave>', self.hide_tip)

    def show_tip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tip_window = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = Label(tw, text=self.text, justify=LEFT,
                      background="#ffffe0", relief=SOLID, borderwidth=1,
                      font=("Segoe UI", 8, "normal"))
        label.pack()

    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

# ========== Ultra UI Helpers ==========
class UltraUI:
    def __init__(self, root):
        self.root = root

    def neon_button(self, parent, text, command, color="#00f5c4"):
        btn = Label(
            parent,
            text=text,
            bg="#0b1220",
            fg=color,
            font=("Segoe UI", 10, "bold"),
            padx=16,
            pady=8,
            cursor="hand2"
        )
        def on_enter(e):
            btn.config(bg=color, fg="#000")
        def on_leave(e):
            btn.config(bg="#0b1220", fg=color)
        def on_click(e):
            btn.config(bg="#22c55e")
            self.root.after(120, lambda: btn.config(bg=color, fg="#000"))
            command()
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        btn.bind("<Button-1>", on_click)
        return btn

    def glass_card(self, parent):
        frame = Frame(parent, bg="#0b1220")
        frame.config(highlightbackground="#1f2937", highlightthickness=1)
        return frame

    def neon_entry(self, parent, textvar):
        e = Entry(
            parent,
            textvariable=textvar,
            bg="#020617",
            fg="#00f5c4",
            insertbackground="#00f5c4",
            relief="flat",
            font=("JetBrains Mono", 10)
        )
        def on_focus(e): e.config(highlightthickness=1, highlightbackground="#00f5c4")
        def on_blur(e): e.config(highlightthickness=0)
        e.bind("<FocusIn>", on_focus)
        e.bind("<FocusOut>", on_blur)
        return e

def apply_glow(widget, color="#00f5c4"):
    def glow_on(e): widget.config(highlightthickness=2, highlightbackground=color)
    def glow_off(e): widget.config(highlightthickness=0)
    widget.bind("<Enter>", glow_on)
    widget.bind("<Leave>", glow_off)

# ========== Configuration ==========
DEFAULT_CONFIG = {
    "tor": {
        "tor_path": "./vendor/tor-bundle/tor/tor.exe" if platform.system() == "Windows" else "./vendor/tor-bundle/tor/tor",
        "torrc_path": "torrc",
        "control_port": 9051,
        "control_password": "",
        "auth_method": "none",
        "bridges": []
    },
    "dns_scanner": {
        "max_workers": 80,
        "timeout": 0.8,
        "use_tcp": False,
        "check_fake": True,
        "check_doh_dot": True,
        "rate_limit_ms": 0
    },
    "dns_proxy": {
        "listen_port": 5353,
        "fallback_dns": ["8.8.8.8", "1.1.1.1"],
        "cache_size": 100
    },
    "appearance": {
        "theme": "dark",
        "font_family": "Consolas",
        "font_size": 9
    },
    "loop_identity": {
        "iterations": 10,
        "interval_sec": 5
    }
}

CONFIG_FILE = "tor_dns_config.json"

# ========== Helper Functions ==========
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                saved = json.load(f)
                for k, v in DEFAULT_CONFIG.items():
                    if k not in saved: saved[k] = v
                    else:
                        for sk, sv in v.items():
                            if sk not in saved[k]: saved[k][sk] = sv
                return saved
        except: pass
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=4)

def build_dns_query(domain, txid):
    header = struct.pack('>HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    question = b''
    for part in domain.split('.'):
        question += bytes([len(part)]) + part.encode()
    question += b'\x00' + struct.pack('>HH', 1, 1)
    return header + question

def parse_dns_response(resp, txid):
    try:
        if len(resp) < 12: return False, False
        if struct.unpack('>H', resp[:2])[0] != txid: return False, False
        flags = struct.unpack('>H', resp[2:4])[0]
        ancount = struct.unpack('>H', resp[6:8])[0]
        is_noerror = (flags & 0x0F) == 0
        has_answer = ancount > 0
        return is_noerror, has_answer
    except: return False, False

def get_tor_exit_ip(socks_host='127.0.0.1', socks_port=9050, timeout=10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((socks_host, socks_port))
        s.send(b'\x05\x01\x00')
        response = s.recv(2)
        if response[0] != 0x05 or response[1] != 0x00:
            s.close()
            return "SOCKS5 auth error"
        host = b'api.ipify.org'
        port = 80
        s.send(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + struct.pack('>H', port))
        response = s.recv(10)
        if len(response) < 10 or response[1] != 0x00:
            s.close()
            return "SOCKS5 connection failed"
        s.send(b'GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n')
        data = b''
        while True:
            chunk = s.recv(1024)
            if not chunk: break
            data += chunk
        s.close()
        lines = data.decode('utf-8', errors='ignore').split('\r\n')
        for line in lines:
            if line and not line.startswith('HTTP') and not line.startswith('Date') and not line.startswith('Content'):
                return line.strip()
        return "IP not found"
    except Exception as e:
        return f"Error: {e}"

# ========== DNS Proxy Server ==========
class DNSProxy:
    def __init__(self, upstream_servers, listen_port=5353, cache_size=100):
        self.upstream_servers = upstream_servers
        self.listen_port = listen_port
        self.cache = {}
        self.cache_size = cache_size
        self.running = False
        self.sock = None

    def start(self):
        if self.running: return False
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(('127.0.0.1', self.listen_port))
        except Exception:
            self.running = False
            return False
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def stop(self):
        self.running = False
        if self.sock: self.sock.close()

    def _run(self):
        self.sock.settimeout(0.5)
        while self.running:
            try:
                data, addr = self.sock.recvfrom(512)
                threading.Thread(target=self._handle, args=(data, addr), daemon=True).start()
            except socket.timeout: continue
            except: break

    def _handle(self, data, client_addr):
        qname = self._extract_qname(data)
        if qname and qname in self.cache:
            if self.cache[qname][0] > time.time():
                self.sock.sendto(self.cache[qname][1], client_addr)
                return
            else: del self.cache[qname]

        for upstream in self.upstream_servers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.sendto(data, (upstream, 53))
                resp, _ = s.recvfrom(512)
                s.close()
                if qname:
                    self.cache[qname] = (time.time() + 60, resp)
                    if len(self.cache) > self.cache_size:
                        oldest = min(self.cache.items(), key=lambda x: x[1][0])[0]
                        del self.cache[oldest]
                self.sock.sendto(resp, client_addr)
                return
            except: continue
        self.sock.sendto(data[:2] + b'\x81\x83' + data[4:], client_addr)

    def _extract_qname(self, data):
        try:
            idx, labels = 12, []
            while True:
                length = data[idx]
                if length == 0: break
                idx += 1
                labels.append(data[idx:idx+length].decode('ascii', errors='ignore'))
                idx += length
            return '.'.join(labels)
        except: return None

# ========== Main Application (Ultra UI with Top Bar) ==========
class ConTorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ConTor - Connect Tor & DNS Tool v5.3")
        self.root.geometry("950x900")
        self.root.minsize(850, 800)
        self.root.attributes("-alpha", 0.0)

        self.config = load_config()
        self.tor_process = None
        self.dns_proxy = None
        self.scanning = False
        self.scan_stop_event = threading.Event()
        self.scan_results = []
        self.last_bw_read = 0
        self.last_bw_written = 0
        self.loop_running = False
        self.gradient_offset = 0
        self.zoom = 0.95

        self.ui = UltraUI(root)
        self.canvas_bg = Canvas(self.root, highlightthickness=0)
        self.canvas_bg.place(relwidth=1, relheight=1)

        self._setup_styles()
        self._create_menu()
        self._create_top_bar()          # <--- نوار بالایی ثابت
        self._create_notebook()

        self._log("ConTor v5.3 Ultra UI initialized.", "#00f5c4")
        self._load_config_to_ui()
        self._ensure_torrc()
        self._start_bw_monitor()
        self._apply_appearance()
        self._add_right_click_menu_to_entries()

        self.animate_background()
        self.ultra_start()

    # ---------- Animations ----------
    def animate_background(self):
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        self.canvas_bg.delete("all")
        for i in range(0, w, 10):
            color = "#0f172a" if (i + self.gradient_offset) % 200 < 100 else "#020617"
            self.canvas_bg.create_line(i, 0, i, h, fill=color)
        self.gradient_offset += 2
        self.root.after(50, self.animate_background)

    def ultra_start(self):
        self.animate_ultra()

    def animate_ultra(self):
        alpha = self.root.attributes("-alpha")
        if alpha < 1:
            alpha += 0.04
            self.zoom += 0.01
            self.root.attributes("-alpha", alpha)
            new_w = int(950 * self.zoom)
            new_h = int(900 * self.zoom)
            self.root.geometry(f"{new_w}x{new_h}")
            self.root.after(16, self.animate_ultra)

    # ---------- Top Bar (Always Visible) ----------
    def _create_top_bar(self):
        top_frame = Frame(self.root, bg="#0b1220", height=36)
        top_frame.pack(side=TOP, fill=X, padx=5, pady=(5,0))

        self.tor_status_indicator = Label(top_frame, text="⚫ Tor: Stopped",
                                          bg="#0b1220", fg="#94a3b8", font=("Segoe UI", 9, "bold"))
        self.tor_status_indicator.pack(side=LEFT, padx=10)

        self.dl_label = Label(top_frame, text="↓ 0 KB/s", bg="#0b1220", fg="#22c55e", font=("JetBrains Mono", 9, "bold"))
        self.dl_label.pack(side=LEFT, padx=15)

        self.ul_label = Label(top_frame, text="↑ 0 KB/s", bg="#0b1220", fg="#f59e0b", font=("JetBrains Mono", 9, "bold"))
        self.ul_label.pack(side=LEFT, padx=5)

        spacer = Label(top_frame, text="", bg="#0b1220")
        spacer.pack(side=LEFT, expand=True, fill=X)

        self.clock_label = Label(top_frame, text="", bg="#0b1220", fg="#cbd5e1", font=("Segoe UI", 8))
        self.clock_label.pack(side=RIGHT, padx=10)
        self._update_clock()

    def _update_clock(self):
        current_time = datetime.now().strftime("%H:%M:%S")
        self.clock_label.config(text=current_time)
        self.root.after(1000, self._update_clock)

    def _update_bandwidth_display(self, down_kb, up_kb):
        self.dl_label.config(text=f"↓ {down_kb:.1f} KB/s")
        self.ul_label.config(text=f"↑ {up_kb:.1f} KB/s")

    # ---------- UI Setup ----------
    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.bg_color = "#0b1220"
        self.fg_color = "#00f5c4"
        self.root.configure(bg=self.bg_color)
        self.style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        self.style.configure('TNotebook.Tab', background='#1e293b', foreground='#00f5c4', padding=[12,6])
        self.style.map('TNotebook.Tab', background=[('selected', '#0f172a')])
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground='#cbd5e1')
        self.style.configure('Treeview', background='#020617', foreground='#00f5c4', fieldbackground='#020617', rowheight=25)
        self.style.configure('Treeview.Heading', background='#1e293b', foreground='#00f5c4', font=('Segoe UI',9,'bold'))
        self.style.map('Treeview', background=[('selected', '#007acc')])

    def _apply_appearance(self):
        font_family = self.config["appearance"]["font_family"]
        font_size = self.config["appearance"]["font_size"]
        self.log_text.config(font=("JetBrains Mono", font_size))
        self.root.option_add('*Font', (font_family, font_size))

    def _create_menu(self):
        menubar = Menu(self.root, bg="#0b1220", fg="#00f5c4", activebackground="#1e293b", activeforeground="#00f5c4")
        file_menu = Menu(menubar, tearoff=0, bg="#0b1220", fg="#00f5c4")
        file_menu.add_command(label="Save Config", command=self.save_config_ui)
        file_menu.add_command(label="Load Config", command=self.load_config_ui)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = Menu(menubar, tearoff=0, bg="#0b1220", fg="#00f5c4")
        tools_menu.add_command(label="Clear Log", command=self._clear_log)
        tools_menu.add_command(label="Export Log", command=self.export_log)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = Menu(menubar, tearoff=0, bg="#0b1220", fg="#00f5c4")
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    def _clear_log(self):
        self.log_text.config(state=NORMAL)
        self.log_text.delete(1.0, END)
        self.log_text.config(state=DISABLED)

    def _create_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=15, pady=15)

        self.tor_tab = Frame(self.notebook, bg="#0b1220")
        self.notebook.add(self.tor_tab, text="🔐 Tor Control")
        self.dns_tab = Frame(self.notebook, bg="#0b1220")
        self.notebook.add(self.dns_tab, text="🌐 DNS Scanner")
        self.proxy_tab = Frame(self.notebook, bg="#0b1220")
        self.notebook.add(self.proxy_tab, text="🚀 DNS Proxy")
        self.settings_tab = Frame(self.notebook, bg="#0b1220")
        self.notebook.add(self.settings_tab, text="⚙️ Settings")

        self.tor_card = self.ui.glass_card(self.tor_tab)
        self.tor_card.pack(fill='both', expand=True, padx=10, pady=10)
        self.dns_card = self.ui.glass_card(self.dns_tab)
        self.dns_card.pack(fill='both', expand=True, padx=10, pady=10)
        self.proxy_card = self.ui.glass_card(self.proxy_tab)
        self.proxy_card.pack(fill='both', expand=True, padx=10, pady=10)
        self.settings_card = self.ui.glass_card(self.settings_tab)
        self.settings_card.pack(fill='both', expand=True, padx=10, pady=10)

        self._build_tor_tab()
        self._build_dns_tab()
        self._build_proxy_tab()
        self._build_settings_tab()

        log_frame = LabelFrame(self.root, text="📜 Log Output", bg="#0b1220", fg="#00f5c4", font=("Segoe UI",10,"bold"))
        log_frame.pack(fill='both', expand=True, padx=15, pady=(0,15))
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=WORD, bg="#020617", fg="#00f5c4",
                                                   insertbackground="#00f5c4", font=("JetBrains Mono",10),
                                                   height=10, state=DISABLED, relief="flat", bd=0)
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)

    # ---------- Tor Tab ----------
    def _build_tor_tab(self):
        f = self.tor_card
        row = 0
        Label(f, text="Tor Executable:", bg="#0b1220", fg="#cbd5e1").grid(row=row, column=0, sticky='e', padx=5, pady=5)
        self.tor_path_var = StringVar()
        self.ui.neon_entry(f, self.tor_path_var).grid(row=row, column=1, sticky='w', padx=5, ipadx=200)
        self.ui.neon_button(f, "Browse", self.browse_tor, "#3b82f6").grid(row=row, column=2, padx=5)
        self.ui.neon_button(f, "Download", lambda: webbrowser.open("https://www.torproject.org/download/tor/"), "#f59e0b").grid(row=row, column=3, padx=5)
        row += 1

        Label(f, text="Torrc Path:", bg="#0b1220", fg="#cbd5e1").grid(row=row, column=0, sticky='e', padx=5, pady=5)
        self.torrc_var = StringVar()
        self.ui.neon_entry(f, self.torrc_var).grid(row=row, column=1, sticky='w', padx=5, ipadx=200)
        row += 1

        Label(f, text="Control Port:", bg="#0b1220", fg="#cbd5e1").grid(row=row, column=0, sticky='e', padx=5, pady=5)
        self.ctrl_port_var = IntVar()
        ctrl_entry = self.ui.neon_entry(f, self.ctrl_port_var)
        ctrl_entry.grid(row=row, column=1, sticky='w', padx=5)
        ToolTip(ctrl_entry, "Internal control port (9051). For browsing use SOCKS5 on port 9050.")
        row += 1

        info_label = Label(f, text="ℹ️ Control Port (9051) is for internal use only.\n   For browser/proxy, use SOCKS5 on 127.0.0.1:9050",
                           bg="#0b1220", fg="#94a3b8", font=("Segoe UI",8,"italic"), justify=LEFT)
        info_label.grid(row=row, column=0, columnspan=4, sticky='w', padx=20, pady=(0,5))
        row += 1

        Label(f, text="Auth Method:", bg="#0b1220", fg="#cbd5e1").grid(row=row, column=0, sticky='e', padx=5, pady=5)
        self.auth_method_var = StringVar()
        ttk.Combobox(f, textvariable=self.auth_method_var, values=["none","password","cookie"], state="readonly", width=15).grid(row=row, column=1, sticky='w', padx=5)
        row += 1

        Label(f, text="Password:", bg="#0b1220", fg="#cbd5e1").grid(row=row, column=0, sticky='e', padx=5, pady=5)
        self.ctrl_pass_var = StringVar()
        pass_entry = self.ui.neon_entry(f, self.ctrl_pass_var)
        pass_entry.config(show="*")
        pass_entry.grid(row=row, column=1, sticky='w', padx=5, ipadx=150)
        row += 1

        loop_frame = LabelFrame(f, text="🔄 Automatic Identity Change Loop", bg="#0b1220", fg="#00f5c4", font=("Segoe UI",9,"bold"))
        loop_frame.grid(row=row, column=0, columnspan=4, sticky='ew', padx=5, pady=5)
        row += 1
        Label(loop_frame, text="Iterations:", bg="#0b1220", fg="#cbd5e1").grid(row=0, column=0, padx=5, pady=5)
        self.loop_iter_var = IntVar(value=self.config["loop_identity"]["iterations"])
        Entry(loop_frame, textvariable=self.loop_iter_var, width=8, bg="#020617", fg="#00f5c4", insertbackground="#00f5c4").grid(row=0, column=1, padx=5)
        Label(loop_frame, text="Interval (sec):", bg="#0b1220", fg="#cbd5e1").grid(row=0, column=2, padx=5)
        self.loop_interval_var = IntVar(value=self.config["loop_identity"]["interval_sec"])
        Entry(loop_frame, textvariable=self.loop_interval_var, width=8, bg="#020617", fg="#00f5c4", insertbackground="#00f5c4").grid(row=0, column=3, padx=5)
        self.ui.neon_button(loop_frame, "▶ Start Loop", self.start_identity_loop, "#e67e22").grid(row=0, column=4, padx=5)
        self.ui.neon_button(loop_frame, "⏹ Stop Loop", self.stop_identity_loop, "#e74c3c").grid(row=0, column=5, padx=5)

        Label(f, text="Bridges (Obfs4):", bg="#0b1220", fg="#cbd5e1").grid(row=row, column=0, sticky='ne', padx=5, pady=5)
        self.bridges_text = Text(f, height=4, width=60, bg="#020617", fg="#00f5c4", insertbackground="#00f5c4", font=("JetBrains Mono",9))
        self.bridges_text.grid(row=row, column=1, columnspan=3, sticky='w', padx=5, pady=5)
        row += 1

        btn_frame = Frame(f, bg="#0b1220")
        btn_frame.grid(row=row, column=0, columnspan=4, pady=10)
        btns = [
            ("▶ Start", self.start_tor, "#22c55e"),
            ("⏹ Stop", self.stop_tor, "#ef4444"),
            ("🔄 New Identity", self.new_identity, "#3b82f6"),
            ("📡 Show Circuit", self.show_circuit, "#8b5cf6"),
            ("📡 Show Exit IP", self.show_tor_ip, "#f59e0b"),
            ("ℹ️ How to Connect", self.show_connection_help, "#06b6d4"),
            ("🐞 Debug SOCKS", self.debug_socks, "#ec4899")
        ]
        for text, cmd, color in btns:
            btn = self.ui.neon_button(btn_frame, text, cmd, color)
            btn.pack(side='left', padx=6)
            apply_glow(btn, color)

        row += 1
        self.tor_status_label = Label(f, text="Status: Not Running", bg="#0b1220", fg="#ef4444", font=("Segoe UI",10,"bold"))
        self.tor_status_label.grid(row=row, column=0, columnspan=4, pady=10)

    # ---------- DNS Tab ----------
    def _build_dns_tab(self):
        f = self.dns_card
        Label(f, text="Target CIDR:", bg="#0b1220", fg="#cbd5e1").grid(row=0, column=0, sticky='e', padx=5, pady=5)
        self.cidr_var = StringVar(value="8.8.8.0/24")
        self.ui.neon_entry(f, self.cidr_var).grid(row=0, column=1, sticky='w', padx=5, ipadx=200)

        Label(f, text="Workers:", bg="#0b1220", fg="#cbd5e1").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        self.workers_var = IntVar()
        Spinbox(f, from_=10, to=300, textvariable=self.workers_var, width=8, bg="#020617", fg="#00f5c4", relief="flat").grid(row=1, column=1, sticky='w', padx=5)

        Label(f, text="Timeout (s):", bg="#0b1220", fg="#cbd5e1").grid(row=2, column=0, sticky='e', padx=5, pady=5)
        self.timeout_var = DoubleVar()
        self.ui.neon_entry(f, self.timeout_var).grid(row=2, column=1, sticky='w', padx=5)

        self.use_tcp_var = BooleanVar()
        Checkbutton(f, text="Use TCP (slower but reliable)", variable=self.use_tcp_var, bg="#0b1220", fg="#cbd5e1", selectcolor="#0b1220").grid(row=3, column=1, sticky='w', padx=5)
        self.check_fake_var = BooleanVar()
        Checkbutton(f, text="Detect Fake DNS (Hijacking)", variable=self.check_fake_var, bg="#0b1220", fg="#cbd5e1", selectcolor="#0b1220").grid(row=4, column=1, sticky='w', padx=5)
        self.check_doh_var = BooleanVar()
        Checkbutton(f, text="Scan DoH (443) & DoT (853)", variable=self.check_doh_var, bg="#0b1220", fg="#cbd5e1", selectcolor="#0b1220").grid(row=5, column=1, sticky='w', padx=5)

        btn_frame = Frame(f, bg="#0b1220")
        btn_frame.grid(row=6, column=0, columnspan=2, pady=10)
        self.ui.neon_button(btn_frame, "⚡ Start Scan", self.start_dns_scan, "#8b5cf6").pack(side='left', padx=5)
        self.ui.neon_button(btn_frame, "⏹ Stop Scan", self.stop_dns_scan, "#ef4444").pack(side='left', padx=5)

        self.scan_progress = ttk.Progressbar(f, mode='determinate', maximum=100)
        self.scan_progress.grid(row=7, column=0, columnspan=2, sticky='ew', padx=10, pady=5)
        self.scan_status_label = Label(f, text="Ready", bg="#0b1220", fg="#00f5c4")
        self.scan_status_label.grid(row=8, column=0, columnspan=2)

        cols = ("ip","latency","status","type")
        self.dns_tree = ttk.Treeview(f, columns=cols, show="headings", height=10)
        self.dns_tree.heading("ip", text="IP Address")
        self.dns_tree.heading("latency", text="Latency (ms)")
        self.dns_tree.heading("status", text="Status")
        self.dns_tree.heading("type", text="Type")
        self.dns_tree.column("ip", width=120)
        self.dns_tree.column("latency", width=80)
        self.dns_tree.column("status", width=100)
        self.dns_tree.column("type", width=80)
        self.dns_tree.grid(row=9, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)
        scroll = Scrollbar(f, orient=VERTICAL, command=self.dns_tree.yview)
        scroll.grid(row=9, column=2, sticky='ns')
        self.dns_tree.config(yscrollcommand=scroll.set)
        f.grid_rowconfigure(9, weight=1)
        f.grid_columnconfigure(1, weight=1)

        self.context_menu = Menu(self.dns_tree, tearoff=0, bg="#0b1220", fg="#00f5c4")
        self.context_menu.add_command(label="Copy IP", command=self.copy_selected)
        self.context_menu.add_command(label="Add to Proxy Upstreams", command=self.use_selected_as_proxy)
        self.context_menu.add_command(label="Set as Main Upstream (replace)", command=self.set_as_main_upstream)
        self.dns_tree.bind("<Button-3>", self._show_context_menu)

        exp_frame = Frame(f, bg="#0b1220")
        exp_frame.grid(row=10, column=0, columnspan=3, pady=5)
        for text, cmd, color in [("📋 Copy IP", self.copy_selected, "#3b82f6"),
                                  ("⚡ Use as Proxy", self.use_selected_as_proxy, "#e67e22"),
                                  ("💾 JSON", lambda: self.export_results('json'), "#06b6d4"),
                                  ("💾 CSV", lambda: self.export_results('csv'), "#22c55e"),
                                  ("💾 dnsmasq", lambda: self.export_results('dnsmasq'), "#f59e0b")]:
            self.ui.neon_button(exp_frame, text, cmd, color).pack(side='left', padx=5)

    # ---------- Proxy Tab ----------
    def _build_proxy_tab(self):
        f = self.proxy_card
        Label(f, text="Listen Port:", bg="#0b1220", fg="#cbd5e1").grid(row=0, column=0, sticky='e', padx=5, pady=5)
        self.proxy_port_var = IntVar()
        self.ui.neon_entry(f, self.proxy_port_var).grid(row=0, column=1, sticky='w', padx=5)

        Label(f, text="Upstream DNS:", bg="#0b1220", fg="#cbd5e1").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        self.upstream_var = StringVar()
        self.ui.neon_entry(f, self.upstream_var).grid(row=1, column=1, sticky='w', padx=5, ipadx=300)

        btn_frame = Frame(f, bg="#0b1220")
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        self.ui.neon_button(btn_frame, "🚀 Start Proxy", self.start_dns_proxy, "#22c55e").pack(side='left', padx=5)
        self.ui.neon_button(btn_frame, "⏹ Stop Proxy", self.stop_dns_proxy, "#ef4444").pack(side='left', padx=5)

        self.proxy_status_label = Label(f, text="Proxy: Stopped", bg="#0b1220", fg="#ef4444")
        self.proxy_status_label.grid(row=3, column=0, columnspan=2, pady=5)

        info = """How to use:
1. Start DNS Proxy (listens on 127.0.0.1:port)
2. Change your system DNS to 127.0.0.1
3. All queries will be forwarded to your custom upstreams."""
        Label(f, text=info, justify=LEFT, bg="#0b1220", fg="#94a3b8", font=("Segoe UI",9)).grid(row=4, column=0, columnspan=2, sticky='w', padx=10, pady=10)
        self.ui.neon_button(f, "🔧 Set as System DNS (Admin)", self.set_system_dns, "#f59e0b").grid(row=5, column=0, columnspan=2, pady=10)

    # ---------- Settings Tab ----------
    def _build_settings_tab(self):
        f = self.settings_card
        Label(f, text="Theme:", bg="#0b1220", fg="#cbd5e1").grid(row=0, column=0, sticky='e', padx=5, pady=5)
        self.theme_var = StringVar()
        ttk.Combobox(f, textvariable=self.theme_var, values=["dark","light"], state="readonly").grid(row=0, column=1, sticky='w')

        Label(f, text="Font Family:", bg="#0b1220", fg="#cbd5e1").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        self.font_family_var = StringVar()
        self.ui.neon_entry(f, self.font_family_var).grid(row=1, column=1, sticky='w', padx=5)

        Label(f, text="Font Size:", bg="#0b1220", fg="#cbd5e1").grid(row=2, column=0, sticky='e', padx=5, pady=5)
        self.font_size_var = IntVar()
        Spinbox(f, from_=8, to=20, textvariable=self.font_size_var, width=5, bg="#020617", fg="#00f5c4", relief="flat").grid(row=2, column=1, sticky='w', padx=5)

        self.ui.neon_button(f, "Apply & Save Settings", self.apply_and_save_settings, "#3b82f6").grid(row=3, column=0, columnspan=2, pady=20)
        self.ui.neon_button(f, "Reset to Defaults", self.reset_settings, "#ef4444").grid(row=4, column=0, columnspan=2, pady=5)

    # ---------- Right-click menu for all Entry/Text ----------
    def _apply_menu_to_children(self, widget, create_menu):
        if isinstance(widget, Entry) or isinstance(widget, Text):
            create_menu(widget, isinstance(widget, Text))
        else:
            for child in widget.winfo_children():
                self._apply_menu_to_children(child, create_menu)

    def _add_right_click_menu_to_entries(self):
        def create_menu(widget, is_text=False):
            menu = Menu(widget, tearoff=0, bg="#0b1220", fg="#00f5c4")
            menu.add_command(label="Copy", command=lambda: widget.event_generate('<<Copy>>'))
            menu.add_command(label="Cut", command=lambda: widget.event_generate('<<Cut>>'))
            menu.add_command(label="Paste", command=lambda: widget.event_generate('<<Paste>>'))
            if is_text:
                menu.add_separator()
                menu.add_command(label="Select All", command=lambda: widget.event_generate('<<SelectAll>>'))
            def show_menu(event):
                menu.post(event.x_root, event.y_root)
            widget.bind("<Button-3>", show_menu)

        self._apply_menu_to_children(self.root, create_menu)

    # ---------- Logging ----------
    def _log(self, msg, color="#00f5c4"):
        def _insert():
            self.log_text.config(state=NORMAL)
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_text.insert(END, f"[{timestamp}] {msg}\n", color)
            self.log_text.tag_config(color, foreground=color)
            self.log_text.see(END)
            self.log_text.config(state=DISABLED)
        if threading.current_thread() is threading.main_thread():
            _insert()
        else:
            self.root.after(0, _insert)

    def export_log(self):
        fname = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")])
        if fname:
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, END))
            self._log(f"Log exported to {fname}")

    # ---------- Tor Control ----------
    def browse_tor(self):
        fname = filedialog.askopenfilename(title="Select Tor executable")
        if fname: self.tor_path_var.set(fname)

    def _ensure_torrc(self):
        path = self.torrc_var.get()
        if not os.path.exists(path):
            self._log(f"Creating default torrc at {path}", "#f39c12")
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"ControlPort {self.ctrl_port_var.get()}\n")
                f.write("CookieAuthentication 1\n")
                f.write("DataDirectory ./tor_data\n")
                bridges = self.bridges_text.get("1.0", END).strip()
                if bridges:
                    f.write("UseBridges 1\n")
                    if "obfs4" in bridges.lower():
                        f.write("ClientTransportPlugin obfs4 exec ./vendor/obfs4proxy\n")
                    for b in bridges.split('\n'):
                        if b.strip(): f.write(f"Bridge {b.strip()}\n")

    def _get_controller(self):
        try:
            ctrl = Controller.from_port(port=self.ctrl_port_var.get())
            method = self.auth_method_var.get()
            if method == "password": ctrl.authenticate(password=self.ctrl_pass_var.get())
            else: ctrl.authenticate()
            return ctrl
        except Exception as e:
            self._log(f"Controller connection failed: {e}", "#ff6b6b")
            return None

    def start_tor(self):
        if self.tor_process and self.tor_process.poll() is None:
            self._log("Tor already running", "#f39c12")
            return
        self._ensure_torrc()
        tor_path = self.tor_path_var.get()
        if not os.path.exists(tor_path):
            self._log(f"Tor not found: {tor_path}", "#ff6b6b")
            return
        try:
            self.tor_process = subprocess.Popen(
                [tor_path, "-f", self.torrc_var.get()],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            )
            def reader(stream, is_err):
                for line in iter(stream.readline, ''):
                    if line:
                        self._log(line.strip(), "#ff6b6b" if is_err else "#00ff88")
            threading.Thread(target=reader, args=(self.tor_process.stdout, False), daemon=True).start()
            threading.Thread(target=reader, args=(self.tor_process.stderr, True), daemon=True).start()
            self.tor_status_label.config(text="Status: Running", fg="#22c55e")
            self.root.after(0, lambda: self.tor_status_indicator.config(text="🟢 Tor: Connected", fg="#22c55e"))
            self._log("Tor started successfully", "#00ff88")
            self._log("✅ Tor SOCKS proxy is ready at 127.0.0.1:9050. Use this in your browser or other apps.", "#00d2ff")
        except Exception as e:
            self._log(f"Failed to start Tor: {e}", "#ff6b6b")

    def stop_tor(self):
        if self.tor_process:
            self.tor_process.terminate()
            self.tor_process = None
            self.tor_status_label.config(text="Status: Stopped", fg="#ef4444")
            self.root.after(0, lambda: self.tor_status_indicator.config(text="⚫ Tor: Stopped", fg="#94a3b8"))
            self._log("Tor stopped")
        else:
            ctrl = self._get_controller()
            if ctrl:
                ctrl.signal(Signal.HALT)
                ctrl.close()
                self._log("Tor halted via control port")

    def new_identity(self, use_existing_controller=None):
        if use_existing_controller:
            ctrl = use_existing_controller
        else:
            ctrl = self._get_controller()
            if not ctrl: return False
        try:
            ctrl.signal(Signal.NEWNYM)
            self._log("New identity requested", "#3b82f6")
            return True
        except Exception as e:
            self._log(f"Failed to signal NEWNYM: {e}", "#ff6b6b")
            return False
        finally:
            if not use_existing_controller and ctrl: ctrl.close()

    def start_identity_loop(self):
        if self.loop_running:
            self._log("Loop already running", "#f39c12")
            return
        iterations = self.loop_iter_var.get()
        interval = self.loop_interval_var.get()
        if iterations <= 0 or interval <= 0:
            self._log("Invalid iterations or interval", "#ff6b6b")
            return
        persistent_ctrl = self._get_controller()
        if not persistent_ctrl:
            self._log("Cannot start loop: unable to connect to control port", "#ff6b6b")
            return
        self.loop_running = True
        self._log(f"Starting identity loop: {iterations} times, {interval}s interval", "#e67e22")
        def loop_worker():
            for i in range(iterations):
                if not self.loop_running: break
                self._log(f"Loop iteration {i+1}/{iterations}", "#3b82f6")
                if not self.new_identity(use_existing_controller=persistent_ctrl):
                    self._log("Identity change failed, stopping loop", "#ff6b6b")
                    break
                if i < iterations-1 and self.loop_running:
                    for _ in range(int(interval*2)):
                        if not self.loop_running: break
                        time.sleep(0.5)
            persistent_ctrl.close()
            self.loop_running = False
            self._log("Identity loop finished", "#00d2ff")
        threading.Thread(target=loop_worker, daemon=True).start()

    def stop_identity_loop(self):
        if self.loop_running:
            self.loop_running = False
            self._log("Loop stopped by user", "#ef4444")
        else: self._log("No loop running", "#f39c12")

    def show_circuit(self):
        ctrl = self._get_controller()
        if not ctrl: return
        try:
            circuits = ctrl.get_circuits()
            if not circuits: self._log("No active circuits", "#f39c12"); return
            est = [c for c in circuits if c.purpose=="CIRCUIT_PURPOSE_C_GENERAL" and c.path]
            if not est: self._log("No established circuits", "#f39c12"); return
            latest = max(est, key=lambda c: c.created)
            path_str = " -> ".join([f"{node[0]} ({node[1]})" for node in latest.path])
            self._log(f"Circuit: {path_str}", "#8b5cf6")
        except Exception as e: self._log(f"Circuit error: {e}", "#ff6b6b")
        finally: ctrl.close()

    def show_tor_ip(self):
        self._log("Fetching exit IP via Tor SOCKS5...", "#f59e0b")
        def fetch():
            ip = get_tor_exit_ip('127.0.0.1', 9050, timeout=15)
            self._log(f"Current Exit IP: {ip}", "#8b5cf6")
        threading.Thread(target=fetch, daemon=True).start()

    def debug_socks(self):
        self._log("🐞 Fetching SOCKS listener info...", "#ec4899")
        ctrl = self._get_controller()
        if not ctrl: return
        try:
            socks_info = ctrl.get_info("net/listeners/socks")
            if socks_info: self._log(f"✅ SOCKS Listener: {socks_info}", "#22c55e")
            else: self._log("⚠️ No SOCKS listener found. Is Tor running with SocksPort configured?", "#f59e0b")
        except Exception as e: self._log(f"Failed to get SOCKS info: {e}", "#ff6b6b")
        finally: ctrl.close()

    def show_connection_help(self):
        msg = """How to use Tor with ConTor:

1. Start Tor using the 'Start' button.
2. Wait until you see "Tor started successfully" in the log.
3. In your browser (Firefox, Chrome) or any app that supports proxies:
   - Proxy type: SOCKS5
   - Host: 127.0.0.1
   - Port: 9050
4. You can also use the DNS Proxy (port 5353) for custom DNS resolution.
5. To change your Tor identity, click 'New Identity' or use the loop.

Note: Control Port (9051) is only for internal communication of this tool.
Do not use it in your browser."""
        messagebox.showinfo("How to Connect to Tor", msg)

    def _start_bw_monitor(self):
        def monitor():
            if self.tor_process and self.tor_process.poll() is None:
                ctrl = self._get_controller()
                if ctrl:
                    try:
                        r = int(ctrl.get_info("traffic/read"))
                        w = int(ctrl.get_info("traffic/written"))
                        dr = (r - self.last_bw_read) / 1024 / 2
                        dw = (w - self.last_bw_written) / 1024 / 2
                        self.last_bw_read = r
                        self.last_bw_written = w
                        self.root.after(0, lambda: self._update_bandwidth_display(dr, dw))
                    except: pass
                    finally: ctrl.close()
                else:
                    self.root.after(0, lambda: self.tor_status_indicator.config(text="⚫ Tor: Disconnected", fg="#94a3b8"))
            else:
                self.root.after(0, lambda: self.tor_status_indicator.config(text="⚫ Tor: Disconnected", fg="#94a3b8"))
            self.root.after(2000, monitor)
        monitor()

    # ---------- DNS Scanner ----------
    def start_dns_scan(self):
        if self.scanning: self._log("Scan already in progress", "#f39c12"); return
        cidr = self.cidr_var.get().strip()
        try: network = ipaddress.ip_network(cidr, strict=False)
        except: self._log("Invalid CIDR", "#ff6b6b"); return
        total = sum(1 for _ in network.hosts())
        if total > 10000:
            if not messagebox.askyesno("Warning", f"Scanning {total} IPs may take a long time. Continue?"): return
        self.scanning = True
        self.scan_stop_event.clear()
        self.scan_results = []
        for item in self.dns_tree.get_children(): self.dns_tree.delete(item)
        self.scan_progress['maximum'] = total
        self.scan_progress['value'] = 0
        self.scan_status_label.config(text=f"Scanning 0 / {total}...")
        def scan_worker():
            workers = self.workers_var.get()
            timeout = self.timeout_var.get()
            use_tcp = self.use_tcp_var.get()
            check_fake = self.check_fake_var.get()
            check_doh = self.check_doh_var.get()
            fake_domain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=12)) + ".nonexistent"
            processed = 0
            lock = threading.Lock()
            def check_ip(ip_str):
                if self.scan_stop_event.is_set(): return []
                nonlocal processed
                ip = str(ip_str)
                results = []
                if use_tcp: rtt, valid = self._probe_tcp(ip,53,timeout)
                else: rtt, valid = self._probe_udp(ip,53,timeout)
                if valid:
                    is_fake = False
                    if check_fake:
                        if use_tcp: _, fake_valid = self._probe_tcp(ip,53,timeout,domain=fake_domain)
                        else: _, fake_valid = self._probe_udp(ip,53,timeout,domain=fake_domain)
                        is_fake = fake_valid
                    status = "Fake/Hijacked" if is_fake else "Clean"
                    proto = "TCP 53" if use_tcp else "UDP 53"
                    results.append((ip, rtt, status, proto))
                if check_doh and not self.scan_stop_event.is_set():
                    rtt_dot, valid_dot = self._probe_dot(ip,853,timeout)
                    if valid_dot: results.append((ip, rtt_dot, "Clean", "DoT 853"))
                    rtt_doh, valid_doh = self._probe_doh(ip,443,timeout)
                    if valid_doh: results.append((ip, rtt_doh, "Clean", "DoH 443"))
                with lock:
                    processed += 1
                    if processed % 10 == 0 or len(results)>0:
                        self.root.after(0, self._update_scan_progress, processed, total)
                return results
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {ex.submit(check_ip, ip): ip for ip in network.hosts()}
                for fut in as_completed(futures):
                    if self.scan_stop_event.is_set(): ex.shutdown(wait=False); break
                    for res in fut.result():
                        if self.scan_stop_event.is_set(): break
                        self.scan_results.append(res)
                        self.root.after(0, self._insert_tree_row, res)
            self.scanning = False
            self.scan_stop_event.clear()
            self.root.after(0, self._scan_finished, len(self.scan_results))
        threading.Thread(target=scan_worker, daemon=True).start()

    def _probe_udp(self, ip, port, timeout, domain="example.com"):
        if self.scan_stop_event.is_set(): return 9999, False
        txid = random.randint(0,65535)
        packet = build_dns_query(domain, txid)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        start = time.time()
        try:
            s.sendto(packet, (ip, port))
            resp,_ = s.recvfrom(512)
            rtt = (time.time()-start)*1000
            noerr, hasans = parse_dns_response(resp, txid)
            return rtt, (noerr and hasans)
        except: return 9999, False
        finally: s.close()

    def _probe_tcp(self, ip, port, timeout, domain="example.com"):
        if self.scan_stop_event.is_set(): return 9999, False
        txid = random.randint(0,65535)
        packet = build_dns_query(domain, txid)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        try:
            s.connect((ip, port))
            s.send(struct.pack('>H', len(packet)) + packet)
            resp_len = struct.unpack('>H', s.recv(2))[0]
            resp = s.recv(resp_len)
            rtt = (time.time()-start)*1000
            noerr, hasans = parse_dns_response(resp, txid)
            return rtt, (noerr and hasans)
        except: return 9999, False
        finally: s.close()

    def _probe_dot(self, ip, port, timeout):
        if self.scan_stop_event.is_set(): return 9999, False
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s, server_hostname=ip)
            ss.connect((ip, port))
            rtt = (time.time()-start)*1000
            ss.close()
            return rtt, True
        except: return 9999, False

    def _probe_doh(self, ip, port, timeout):
        if self.scan_stop_event.is_set(): return 9999, False
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s, server_hostname=ip)
            ss.connect((ip, port))
            rtt = (time.time()-start)*1000
            ss.close()
            return rtt, True
        except: return 9999, False

    def _update_scan_progress(self, current, total):
        self.scan_progress['value'] = current
        self.scan_status_label.config(text=f"Scanning {current} / {total}...")

    def _insert_tree_row(self, res):
        ip, rtt, status, typ = res
        self.dns_tree.insert("", "end", values=(ip, f"{rtt:.1f}", status, typ))

    def _scan_finished(self, count):
        self.scanning = False
        self.scan_progress['value'] = 0
        self.scan_status_label.config(text=f"Done! Found {count} open ports/servers.")
        self._log(f"Scan finished. {count} results found.", "#00d2ff")

    def stop_dns_scan(self):
        if self.scanning: self.scan_stop_event.set(); self._log("Stop requested...", "#f39c12")
        else: self._log("No scan in progress", "#f39c12")

    def copy_selected(self):
        sel = self.dns_tree.selection()
        if sel:
            ip = self.dns_tree.item(sel[0])['values'][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self._log(f"Copied {ip}")

    def use_selected_as_proxy(self):
        sel = self.dns_tree.selection()
        if sel:
            ip = self.dns_tree.item(sel[0])['values'][0]
            current = self.upstream_var.get()
            if current: self.upstream_var.set(f"{current},{ip}")
            else: self.upstream_var.set(ip)
            self.notebook.select(2)
            self._log(f"Added {ip} to upstream DNS list")

    def set_as_main_upstream(self):
        sel = self.dns_tree.selection()
        if sel:
            ip = self.dns_tree.item(sel[0])['values'][0]
            self.upstream_var.set(ip)
            self.notebook.select(2)
            self._log(f"Upstream replaced with {ip}", "#00ff88")

    def _show_context_menu(self, event):
        item = self.dns_tree.identify_row(event.y)
        if item:
            self.dns_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def export_results(self, fmt):
        if not self.scan_results: self._log("No results to export", "#f39c12"); return
        fname = filedialog.asksaveasfilename(defaultextension=f".{fmt}", filetypes=[(fmt.upper(), f"*.{fmt}")])
        if not fname: return
        try:
            if fmt == 'json':
                data = [{"ip":r[0], "latency_ms":round(r[1],1), "status":r[2], "type":r[3]} for r in self.scan_results]
                with open(fname,'w') as f: json.dump(data, f, indent=4)
            elif fmt == 'csv':
                with open(fname,'w',newline='') as f:
                    w = csv.writer(f)
                    w.writerow(["IP","Latency(ms)","Status","Type"])
                    w.writerows(self.scan_results)
            elif fmt == 'dnsmasq':
                with open(fname,'w') as f:
                    f.write("# ConTor DNS servers\n")
                    for r in self.scan_results:
                        if "UDP 53" in r[3] and r[2]=="Clean":
                            f.write(f"server={r[0]}\n")
            self._log(f"Exported to {fname}", "#00ff88")
        except Exception as e: self._log(f"Export failed: {e}", "#ff6b6b")

    # ---------- DNS Proxy ----------
    def start_dns_proxy(self):
        if self.dns_proxy and self.dns_proxy.running: return
        port = self.proxy_port_var.get()
        upstreams = [x.strip() for x in self.upstream_var.get().split(',') if x.strip()]
        if not upstreams: self._log("No upstreams provided", "#ff6b6b"); return
        self.dns_proxy = DNSProxy(upstreams, listen_port=port)
        if self.dns_proxy.start():
            self.proxy_status_label.config(text=f"Proxy: Running on 127.0.0.1:{port}", fg="#22c55e")
            self._log(f"DNS Proxy started on port {port}")
        else: self._log("Failed to start proxy (Port in use?)", "#ff6b6b")

    def stop_dns_proxy(self):
        if self.dns_proxy:
            self.dns_proxy.stop()
            self.dns_proxy = None
            self.proxy_status_label.config(text="Proxy: Stopped", fg="#ef4444")
            self._log("DNS Proxy stopped")

    def set_system_dns(self):
        upstreams = [x.strip() for x in self.upstream_var.get().split(',') if x.strip()]
        if not upstreams: self._log("No DNS server to set", "#ff6b6b"); return
        dns_ip = upstreams[0]
        if platform.system() == "Windows":
            try:
                import ctypes
                if ctypes.windll.shell32.ShellExecuteW(None, "runas", "netsh", f"interface ip set dns name=\"Wi-Fi\" static {dns_ip}", None, 1) > 32:
                    self._log(f"System DNS set to {dns_ip} (requires admin confirmation)", "#f59e0b")
                else: self._log("Failed to set DNS, admin rights required", "#ff6b6b")
            except: self._log("Failed to set system DNS on Windows", "#ff6b6b")
        elif platform.system() == "Linux":
            self._log(f"Run manually with sudo: resolvectl dns eth0 {dns_ip}", "#f59e0b")
        else: self._log("Automatic DNS setting not supported on this OS", "#ff6b6b")

    # ---------- Settings & Config ----------
    def save_config_ui(self):
        self.config["tor"]["tor_path"] = self.tor_path_var.get()
        self.config["tor"]["torrc_path"] = self.torrc_var.get()
        self.config["tor"]["control_port"] = self.ctrl_port_var.get()
        self.config["tor"]["auth_method"] = self.auth_method_var.get()
        self.config["tor"]["control_password"] = self.ctrl_pass_var.get()
        self.config["tor"]["bridges"] = [b.strip() for b in self.bridges_text.get("1.0", END).split('\n') if b.strip()]
        self.config["dns_scanner"]["max_workers"] = self.workers_var.get()
        self.config["dns_scanner"]["timeout"] = self.timeout_var.get()
        self.config["dns_scanner"]["use_tcp"] = self.use_tcp_var.get()
        self.config["dns_scanner"]["check_fake"] = self.check_fake_var.get()
        self.config["dns_scanner"]["check_doh_dot"] = self.check_doh_var.get()
        self.config["dns_proxy"]["listen_port"] = self.proxy_port_var.get()
        self.config["dns_proxy"]["fallback_dns"] = [x.strip() for x in self.upstream_var.get().split(',') if x.strip()]
        self.config["appearance"]["theme"] = self.theme_var.get()
        self.config["appearance"]["font_family"] = self.font_family_var.get()
        self.config["appearance"]["font_size"] = self.font_size_var.get()
        self.config["loop_identity"]["iterations"] = self.loop_iter_var.get()
        self.config["loop_identity"]["interval_sec"] = self.loop_interval_var.get()
        save_config(self.config)
        self._log("Config saved")

    def load_config_ui(self):
        fname = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if fname:
            try:
                with open(fname,'r') as f: self.config = json.load(f)
                self._load_config_to_ui()
                self._apply_appearance()
                self._log("Configuration loaded")
            except Exception as e: self._log(f"Failed to load config: {e}", "#ff6b6b")

    def _load_config_to_ui(self):
        self.tor_path_var.set(self.config["tor"]["tor_path"])
        self.torrc_var.set(self.config["tor"]["torrc_path"])
        self.ctrl_port_var.set(self.config["tor"]["control_port"])
        self.auth_method_var.set(self.config["tor"]["auth_method"])
        self.ctrl_pass_var.set(self.config["tor"]["control_password"])
        self.bridges_text.delete("1.0", END)
        self.bridges_text.insert("1.0", "\n".join(self.config["tor"].get("bridges",[])))
        self.workers_var.set(self.config["dns_scanner"]["max_workers"])
        self.timeout_var.set(self.config["dns_scanner"]["timeout"])
        self.use_tcp_var.set(self.config["dns_scanner"].get("use_tcp",False))
        self.check_fake_var.set(self.config["dns_scanner"].get("check_fake",True))
        self.check_doh_var.set(self.config["dns_scanner"].get("check_doh_dot",True))
        self.proxy_port_var.set(self.config["dns_proxy"]["listen_port"])
        self.upstream_var.set(",".join(self.config["dns_proxy"]["fallback_dns"]))
        self.theme_var.set(self.config["appearance"].get("theme","dark"))
        self.font_family_var.set(self.config["appearance"].get("font_family","Consolas"))
        self.font_size_var.set(self.config["appearance"].get("font_size",9))
        self.loop_iter_var.set(self.config["loop_identity"].get("iterations",10))
        self.loop_interval_var.set(self.config["loop_identity"].get("interval_sec",5))

    def apply_and_save_settings(self):
        self.config["appearance"]["theme"] = self.theme_var.get()
        self.config["appearance"]["font_family"] = self.font_family_var.get()
        self.config["appearance"]["font_size"] = self.font_size_var.get()
        self._apply_appearance()
        save_config(self.config)
        self._log("Settings applied and saved")

    def reset_settings(self):
        self.config = DEFAULT_CONFIG.copy()
        self._load_config_to_ui()
        self._apply_appearance()
        save_config(self.config)
        self._log("Settings reset to defaults")

    def show_about(self):
        about_text = """ConTor v5.2 - Connect Tor & DNS Tool

Full Feature List:

🔹 Tor Control:
- Start/Stop Tor with custom executable and torrc
- Authentication: none, password, cookie
- One-click New Identity
- Automated identity loop (configurable iterations & interval)
- Show current circuit (entry/middle/exit nodes)
- Show Tor exit IP via SOCKS5 (no extra libs)
- Bridges support (Obfs4) - automatic obfs4proxy line only when needed
- Real-time bandwidth monitor
- Auto-generate torrc if missing
- Debug SOCKS listener info

🔹 DNS Scanner:
- Scan IP ranges in CIDR format (e.g., 8.8.8.0/24)
- Adjustable workers (threads) and timeout
- UDP/TCP selection
- Fake DNS detection (via random non-existent domain)
- DoH (port 443) and DoT (port 853) scanning
- RTT (Round Trip Time) measurement in ms
- Progress bar and live status
- Stop scan at any time
- Export results: JSON, CSV, dnsmasq format
- Right-click menu: Copy IP, Add to Upstreams, Set as Main Upstream

🔹 DNS Proxy:
- Start a local DNS proxy on 127.0.0.1:port (default 5353)
- Forward queries to custom upstream servers (use scanned DNS)
- Response caching
- One-click set as system DNS (Windows admin required)
- Instructions inside the tab

🔹 Settings:
- Theme: dark / light
- Font family and size (applied globally)
- Save/Load full configuration to JSON file
- Reset to defaults

🔹 General:
- Right-click context menu (Copy/Cut/Paste/Select All) on all Entry and Text fields
- Colored log with timestamps
- Log export to text file
- Download Tor button (opens official website)
- Cross-platform (Windows, Linux, macOS)
- "How to Connect" button with SOCKS5 proxy instructions

Libraries used: Python 3, Tkinter, stem, socket, ssl, threading, concurrent.futures, ipaddress, csv, json.

For help, click 'How to Connect' in the Tor Control tab."""
        about_win = Toplevel(self.root)
        about_win.title("About ConTor")
        about_win.geometry("600x500")
        about_win.minsize(500,400)
        text_area = scrolledtext.ScrolledText(about_win, wrap=WORD, font=("JetBrains Mono",10), bg="#020617", fg="#00f5c4")
        text_area.pack(fill=BOTH, expand=True)
        text_area.insert(INSERT, about_text)
        text_area.config(state=DISABLED)
        Button(about_win, text="Close", command=about_win.destroy, bg="#0b1220", fg="#00f5c4", relief="flat").pack(pady=10)

    def on_close(self):
        self.save_config_ui()
        self.stop_dns_proxy()
        if self.tor_process: self.stop_tor()
        self.root.destroy()

# ========== Main ==========
def main():
    root = Tk()
    if platform.system() == "Windows":
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except: pass
    app = ConTorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

if __name__ == "__main__":
    main()