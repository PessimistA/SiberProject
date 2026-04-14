import customtkinter as ctk
from datetime import datetime
 
class MonitorUI(ctk.CTk):
    def __init__(self, on_load_history=None, on_load_dates=None, on_load_ips=None, on_load_stats=None):
        super().__init__()
        self.title("PLEASE HACK ME — Threat Monitor & Session History")
        self.geometry("1350x820")
        ctk.set_appearance_mode("dark")
 
        self.on_load_history = on_load_history
        self.on_load_dates = on_load_dates
        self.on_load_ips = on_load_ips
        self.on_load_stats = on_load_stats
 
        self.session_widgets = {}
 
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.top_frame = ctk.CTkFrame(self, height=50, fg_color="#111111", corner_radius=0)
        self.top_frame.grid(row=0, column=0, columnspan=2, sticky="new")
 
        self.lbl_status = ctk.CTkLabel(
            self.top_frame,
            text=" PLEASE HACK ME | Analysis Engine Online",
            font=("Consolas", 14, "bold"),
            text_color="#00FF00"
        )
        self.lbl_status.pack(side="left", padx=20, pady=12)
 
        self.lbl_time = ctk.CTkLabel(
            self.top_frame,
            text="",
            font=("Consolas", 13),
            text_color="#888888"
        )
        self.lbl_time.pack(side="right", padx=20)
        self._update_clock()
 
        self.sidebar = ctk.CTkScrollableFrame(
            self, width=310, corner_radius=0,
            label_text="  Active Threat Actors",
            label_font=("Arial", 13, "bold")
        )
        self.sidebar.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=8)

        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=1, column=1, sticky="nsew", padx=(4, 8), pady=8)
 
        self.tab_live = self.tabview.add(" Live Traffic")
        self.tab_history = self.tabview.add(" Session History")
        self.tab_stats = self.tabview.add(" Statistics")
 
        self._setup_live_tab()
        self._setup_history_tab()
        self._setup_stats_tab()
 
    def _update_clock(self):
        self.lbl_time.configure(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._update_clock)
 
    def _setup_live_tab(self):
        self.tab_live.grid_rowconfigure(0, weight=1)
        self.tab_live.grid_columnconfigure(0, weight=1)
 
        self.chat_frame = ctk.CTkScrollableFrame(
            self.tab_live,
            label_text=" Network Traffic & Threat Stream",
            label_font=("Arial", 12, "bold")
        )
        self.chat_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
 
    # HISTORY TAB
    def _setup_history_tab(self):
        # Filter bar
        filter_frame = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        filter_frame.pack(fill="x", padx=10, pady=(10, 5))
 
        ctk.CTkLabel(filter_frame, text="Date:", font=("Arial", 12)).pack(side="left", padx=(0, 4))
        self.date_menu = ctk.CTkOptionMenu(filter_frame, values=["Loading..."], width=140, command=self._on_date_changed)
        self.date_menu.pack(side="left", padx=4)
 
        ctk.CTkLabel(filter_frame, text="IP:", font=("Arial", 12)).pack(side="left", padx=(10, 4))
        self.ip_menu = ctk.CTkOptionMenu(filter_frame, values=["All"], width=160, command=self._on_ip_changed)
        self.ip_menu.pack(side="left", padx=4)
 
        self.btn_load = ctk.CTkButton(
            filter_frame, text="Load Session Logs", width=150,
            fg_color="#005500", hover_color="#007700",
            command=self._do_load_history
        )
        self.btn_load.pack(side="left", padx=10)
 
        self.lbl_result_count = ctk.CTkLabel(filter_frame, text="", font=("Arial", 11), text_color="#888888")
        self.lbl_result_count.pack(side="left", padx=10)
 
        self.history_box = ctk.CTkScrollableFrame(
            self.tab_history,
            label_text="Session Entries",
            label_font=("Arial", 12, "bold")
        )
        self.history_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
 
    def _on_date_changed(self, value):
        if self.on_load_ips:
            ips = self.on_load_ips(value)
            self.ip_menu.configure(values=["All"] + ips)
            self.ip_menu.set("All")
 
    def _on_ip_changed(self, value):
        pass
 
    def _do_load_history(self):
        date = self.date_menu.get()
        ip = self.ip_menu.get()
        if date == "Loading..." or date == "No logs found":
            return
        if ip == "All":
            ip = None
        if self.on_load_history:
            self.btn_load.configure(state="disabled", text="Loading...")
            self.on_load_history(date, ip)
 
    def populate_history(self, entries):
        for widget in self.history_box.winfo_children():
            widget.destroy()
 
        self.lbl_result_count.configure(text=f"{len(entries)} entries found")
        self.btn_load.configure(state="normal", text="Load Session Logs")
 
        if not entries:
            ctk.CTkLabel(
                self.history_box,
                text="No log entries found for selected filter.",
                text_color="#888888", font=("Arial", 12)
            ).pack(pady=20)
            return
 
        for entry in entries:
            role = entry.get("role", "system")
            cmd = entry.get("command", "")
            resp = entry.get("response", "")
            ts = entry.get("timestamp", "")
            ip = entry.get("ip", "")
            port = entry.get("port", "")
 
            if cmd == "SESSION_START":
                card = ctk.CTkFrame(self.history_box, fg_color="#1a2a1a", border_width=1, border_color="#00aa00", corner_radius=6)
                card.pack(fill="x", pady=3, padx=5)
                ctk.CTkLabel(
                    card,
                    text=f"  {ts}  —  NEW SESSION  —  {ip}  →  Port {port}",
                    font=("Consolas", 11, "bold"), text_color="#00ff88"
                ).pack(anchor="w", padx=10, pady=5)
                continue
 
            if role == "attacker":
                bg, border, icon, tc = "#2a1a1a", "#ff4444", "⌨", "#ffaaaa"
            elif role == "ai":
                bg, border, icon, tc = "#1a1a2a", "#0088ff", "🤖", "#88bbff"
            elif role == "system":
                bg, border, icon, tc = "#1a1a1a", "#555555", "⚙", "#888888"
            else:
                bg, border, icon, tc = "#1a1a1a", "#333333", "•", "#777777"
 
            card = ctk.CTkFrame(self.history_box, fg_color=bg, border_width=1, border_color=border, corner_radius=5)
            card.pack(fill="x", pady=2, padx=5)
 
            header = f"{icon}  [{ts}]  {ip}  Port {port}"
            ctk.CTkLabel(card, text=header, font=("Consolas", 10, "bold"), text_color=border).pack(anchor="w", padx=8, pady=(4, 0))
 
            if cmd and cmd != "SESSION_START":
                ctk.CTkLabel(card, text=f"CMD: {cmd}", font=("Consolas", 11), text_color=tc).pack(anchor="w", padx=12, pady=(2, 0))
            if resp:
                ctk.CTkLabel(card, text=f"OUT: {resp[:120]}{'...' if len(resp) > 120 else ''}", font=("Consolas", 10), text_color="#666666").pack(anchor="w", padx=12, pady=(0, 4))
 
    def populate_dates(self, dates):
        if not dates:
            self.date_menu.configure(values=["No logs found"])
            self.date_menu.set("No logs found")
        else:
            self.date_menu.configure(values=dates)
            self.date_menu.set(dates[0])
            self._on_date_changed(dates[0])
 
    # STATS TAB
    def _setup_stats_tab(self):
        btn_frame = ctk.CTkFrame(self.tab_stats, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=10)
 
        ctk.CTkButton(
            btn_frame, text="Refresh Statistics", width=160,
            fg_color="#004488", hover_color="#0066aa",
            command=self._do_refresh_stats
        ).pack(side="left", padx=5)
 
        self.stats_frame = ctk.CTkScrollableFrame(self.tab_stats)
        self.stats_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
 
    def _do_refresh_stats(self):
        if self.on_load_stats:
            self.on_load_stats()
 
    def populate_stats(self, stats, attacker_db):
        for widget in self.stats_frame.winfo_children():
            widget.destroy()

        header = ctk.CTkFrame(self.stats_frame, fg_color="#1a1a2a", border_width=1, border_color="#0055aa", corner_radius=8)
        header.pack(fill="x", padx=5, pady=8)
        ctk.CTkLabel(header, text="Global Session Statistics", font=("Arial", 15, "bold"), text_color="#4488ff").pack(anchor="w", padx=15, pady=(10, 5))
 
        global_items = [
            ("Total Commands Executed", str(stats.get("total_commands", 0))),
            ("Unique Attacker IPs", str(len(stats.get("unique_ips", [])))),
            ("File Read Attempts", str(stats.get("file_reads", 0))),
            ("Download Attempts", str(stats.get("download_attempts", 0))),
            ("Risky Commands", str(stats.get("risky_commands", 0))),
        ]
        for label, value in global_items:
            row = ctk.CTkFrame(header, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=2)
            ctk.CTkLabel(row, text=label, font=("Consolas", 12), text_color="#aaaaaa", width=280, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=("Consolas", 13, "bold"), text_color="#00ff88").pack(side="left")
 
        cmds = stats.get("commands_by_type", {})
        if cmds:
            cmd_frame = ctk.CTkFrame(self.stats_frame, fg_color="#1a1a1a", border_width=1, border_color="#333333", corner_radius=8)
            cmd_frame.pack(fill="x", padx=5, pady=5)
            ctk.CTkLabel(cmd_frame, text="  Top Commands Used", font=("Arial", 13, "bold"), text_color="#ffaa00").pack(anchor="w", padx=15, pady=(10, 5))
            sorted_cmds = sorted(cmds.items(), key=lambda x: x[1], reverse=True)[:10]
            for cmd_name, count in sorted_cmds:
                row = ctk.CTkFrame(cmd_frame, fg_color="transparent")
                row.pack(fill="x", padx=20, pady=1)
                bar_len = int((count / max(cmds.values())) * 200)
                ctk.CTkLabel(row, text=f"{cmd_name:<20}", font=("Consolas", 12), text_color="#cccccc", width=160, anchor="w").pack(side="left")
                ctk.CTkProgressBar(row, width=bar_len or 10, height=12, progress_color="#ff6600").pack(side="left", padx=5)
                ctk.CTkLabel(row, text=str(count), font=("Consolas", 12), text_color="#ff8844").pack(side="left", padx=5)

        if attacker_db:
            atk_frame = ctk.CTkFrame(self.stats_frame, fg_color="#1a1a1a", border_width=1, border_color="#333333", corner_radius=8)
            atk_frame.pack(fill="x", padx=5, pady=5)
            ctk.CTkLabel(atk_frame, text="  Known Attacker Profiles", font=("Arial", 13, "bold"), text_color="#ff4444").pack(anchor="w", padx=15, pady=(10, 5))
            for ip, data in list(attacker_db.items())[:20]:
                row = ctk.CTkFrame(atk_frame, fg_color="#111111", corner_radius=5)
                row.pack(fill="x", padx=15, pady=3)
                ctk.CTkLabel(row, text=f" {ip}", font=("Consolas", 12, "bold"), text_color="#ffffff", width=160, anchor="w").pack(side="left", padx=10)
                ctk.CTkLabel(row, text=f"First seen: {data.get('first_seen', 'N/A')}", font=("Consolas", 11), text_color="#888888", width=200, anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=f"{data.get('total_connections', 0)} connections", font=("Consolas", 12, "bold"), text_color="#ffaa00").pack(side="left", padx=10)
 
    def add_active_session(self, attacker_ip, target, risk):
        if attacker_ip in self.session_widgets:
            return
 
        frame = ctk.CTkFrame(self.sidebar, fg_color="#1e1e1e", border_width=1, border_color="#444444", corner_radius=6)
        frame.pack(fill="x", pady=4, padx=5)
 
        ctk.CTkLabel(frame, text=f"  {attacker_ip}", font=("Consolas", 13, "bold"), text_color="#ffffff").pack(anchor="w", padx=10, pady=(6, 0))
        ctk.CTkLabel(frame, text=f"Target: {target}", font=("Arial", 11), text_color="#aaaaaa").pack(anchor="w", padx=10)
 
        lbl_profile = ctk.CTkLabel(frame, text="⏳  Profiling...", font=("Arial", 11, "italic"), text_color="gray")
        lbl_profile.pack(anchor="w", padx=10, pady=(4, 0))
 
        progress = ctk.CTkProgressBar(frame, width=270, height=8, progress_color="#444444")
        progress.set(0.05)
        progress.pack(padx=10, pady=8)
 
        self.session_widgets[attacker_ip] = {"frame": frame, "profile": lbl_profile, "progress": progress}
 
    def update_attacker_profile(self, ip, profile, risk_score):
        if ip not in self.session_widgets:
            return
        w = self.session_widgets[ip]
        pl = profile.lower()
        if "apt" in pl or "advanced" in pl:
            icon, color = "☠️", "#ff0000"
        elif "professional" in pl:
            icon, color = "🥷", "#ff4400"
        elif "explorer" in pl or "hacker" in pl:
            icon, color = "🔍", "#ffaa00"
        elif "kiddie" in pl:
            icon, color = "👶", "#ffdd00"
        else:
            icon, color = "🤖", "#00ccff"
 
        w["profile"].configure(text=f"{icon}  {profile}", font=("Arial", 12, "bold"), text_color=color)
        score = max(0, min(100, risk_score)) / 100.0
        w["progress"].set(score)
        w["progress"].configure(progress_color=color)
        w["frame"].configure(border_color="#ff0000" if risk_score > 70 else color, border_width=2 if risk_score > 70 else 1)

    def add_interaction_card(self, sender, text, role):
        timestamp = datetime.now().strftime("%H:%M:%S")
 
        if role == "attacker":
            border, header, tc = "#ff4444", f"[{timestamp}]  😈  ATTACKER  ({sender})", "#ffaaaa"
        elif role == "ai":
            border, header, tc = "#00ccff", f"[{timestamp}]  🤖  AI HONEYPOT  ({sender})", "#88ddff"
        elif sender == "RULE ENGINE":
            border, header, tc = "#ff8800", f"[{timestamp}]  🚨  RULE ENGINE ", "#ffcc88"
        elif role == "web":
            border, header, tc = "#cc00ff", f"[{timestamp}]  🌐  WEB INTELLIGENCE", "#ee88ff"
        else:
            border, header, tc = "#444444", f"[{timestamp}]  ⚙️  SYSTEM", "#aaaaaa"
 
        card = ctk.CTkFrame(
            self.chat_frame,
            border_width=2, border_color=border,
            corner_radius=5, fg_color="#0d0d0d"
        )
        card.pack(fill="x", pady=4, padx=5)
 
        ctk.CTkLabel(card, text=header, font=("Consolas", 11, "bold"), text_color=border).pack(anchor="w", padx=10, pady=(5, 2))
 
        lines = text.count("\n") + 1
        h = max(30, min(200, lines * 18))
        box = ctk.CTkTextbox(card, height=h, font=("Consolas", 11), fg_color="transparent", text_color=tc, wrap="word")
        box.pack(fill="x", padx=10, pady=(0, 5))
        box.insert("0.0", text)
        box.configure(state="disabled")
 
        self.after(80, lambda: self.chat_frame._parent_canvas.yview_moveto(1.0))