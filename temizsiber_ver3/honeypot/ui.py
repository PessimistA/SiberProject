import customtkinter as ctk
from tkinter import filedialog 

class HoneypotUI(ctk.CTk):
    def __init__(self, start_callback, stop_callback, port_info_callback, analyze_url_callback):
        super().__init__()
        self.title("PLEASE HACK ME - Honeypot Control Center")
        self.geometry("950x700")
        ctk.set_appearance_mode("dark")

        self.start_callback = start_callback
        self.stop_callback = stop_callback
        self.port_info_callback = port_info_callback
        self.analyze_url_callback = analyze_url_callback 
        
        self.port_items = {} 
        self.is_split_mode = False

        self.header = ctk.CTkLabel(self, text="PLEASE HACK ME  Central Management", font=("Consolas", 22, "bold"), text_color="#00FF00")
        self.header.pack(pady=15)

        self.api_url = ctk.CTkEntry(self)
        self.api_url.insert(0, "http://ai_koprusu:5000") 
        self.sys_prompt = "You are an Ubuntu 22.04 LTS bash terminal. Produce short and concise fake Linux outputs."

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.tab_network = self.tabview.add("Network Defense (Ports)")
        self.tab_web = self.tabview.add("Web Defense (URL/File)") 

        self.setup_network_tab()
        self.setup_web_defense_tab()

    def setup_network_tab(self):
        self.top_controls = ctk.CTkFrame(self.tab_network, fg_color="transparent")
        self.top_controls.pack(fill="x", padx=10, pady=5)
        
        self.btn_toggle_mode = ctk.CTkButton(self.top_controls, text="Load Standard Ports", command=self.load_default_ports, width=150)
        self.btn_toggle_mode.pack(side="left", padx=5)

        self.action_buttons_frame = ctk.CTkFrame(self.top_controls, fg_color="transparent")
        self.action_buttons_frame.pack(side="right", padx=5)

        self.btn_start = ctk.CTkButton(self.action_buttons_frame, text="Listen on Selected Ports", fg_color="#005500", hover_color="#007700", command=self.start_callback, font=("Arial", 14, "bold"))
        self.btn_start.pack(side="left", padx=5)

        self.btn_stop = ctk.CTkButton(self.action_buttons_frame, text="Stop Scanning", fg_color="#880000", hover_color="#aa0000", command=self.stop_callback, font=("Arial", 14, "bold"), state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        self.main_container = ctk.CTkFrame(self.tab_network, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)

        self.list_panel = ctk.CTkFrame(self.main_container)
        self.list_panel.pack(side="top", fill="y", expand=True, pady=10) 

        self.add_frame = ctk.CTkFrame(self.list_panel, fg_color="transparent")
        self.add_frame.pack(fill="x", padx=10, pady=10)
        self.port_entry = ctk.CTkEntry(self.add_frame, placeholder_text="e.g. 3306", width=100)
        self.port_entry.pack(side="left", padx=5)
        ctk.CTkButton(self.add_frame, text="Add Port", width=80, command=self.add_custom_port).pack(side="left", padx=5)

        self.scroll_frame = ctk.CTkScrollableFrame(self.list_panel, width=300, height=400)
        self.scroll_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.detail_panel = ctk.CTkFrame(self.main_container)
        
        self.lbl_detail_title = ctk.CTkLabel(self.detail_panel, text="Port Details", font=("Arial", 18, "bold"))
        self.lbl_detail_title.pack(pady=10)
        
        self.lbl_detail_status = ctk.CTkLabel(self.detail_panel, text="Status: Unknown", font=("Consolas", 14), text_color="gray")
        self.lbl_detail_status.pack(pady=5)
        
        ctk.CTkLabel(self.detail_panel, text="AI Threat & Function Analysis:", font=("Arial", 14, "bold")).pack(anchor="w", padx=20, pady=(20,5))
        self.ai_info_box = ctk.CTkTextbox(self.detail_panel, font=("Consolas", 13), wrap="word")
        self.ai_info_box.pack(fill="both", expand=True, padx=20, pady=10)

        self.load_default_ports()

    def setup_web_defense_tab(self):
        ctk.CTkLabel(self.tab_web, text="Web Analysis ", font=("Arial", 16, "bold"), text_color="#00aaff").pack(pady=(15, 0))
        ctk.CTkLabel(self.tab_web, text="Note: For security reasons, direct internet access is disabled. HTML scenarios are tested via AI.", font=("Arial", 11), text_color="gray").pack(pady=5)
        
        input_frame = ctk.CTkFrame(self.tab_web, fg_color="transparent")
        input_frame.pack(pady=10)

        self.url_entry = ctk.CTkEntry(input_frame, width=300, placeholder_text="Enter Local URL or Select File...")
        self.url_entry.pack(side="left", padx=5)

        self.btn_browse = ctk.CTkButton(input_frame, text="Browse File", width=100, fg_color="#333333", hover_color="#555555", command=self._browse_file)
        self.btn_browse.pack(side="left", padx=5)
        
        self.btn_analyze_url = ctk.CTkButton(input_frame, text="Analyze Source", fg_color="#aa0000", hover_color="#cc0000", command=self._on_analyze_url)
        self.btn_analyze_url.pack(side="left", padx=5)

        split_frame = ctk.CTkFrame(self.tab_web, fg_color="transparent")
        split_frame.pack(fill="both", expand=True, padx=10, pady=5)

        left_box = ctk.CTkFrame(split_frame)
        left_box.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(left_box, text="Simulated HTML Source Code", font=("Arial", 12, "bold")).pack(pady=5)
        self.html_box = ctk.CTkTextbox(left_box, font=("Consolas", 11), text_color="#aaaaaa", wrap="none")
        self.html_box.pack(fill="both", expand=True, padx=10, pady=10)

        right_box = ctk.CTkFrame(split_frame)
        right_box.pack(side="right", fill="both", expand=True, padx=5)
        ctk.CTkLabel(right_box, text="AI Threat Intelligence Report", font=("Arial", 12, "bold"), text_color="#00FF00").pack(pady=5)
        self.ai_report_box = ctk.CTkTextbox(right_box, font=("Consolas", 13), wrap="word")
        self.ai_report_box.pack(fill="both", expand=True, padx=10, pady=10)


    def _browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Source Code File",
            filetypes=[("HTML/JS/PHP Files", "*.html *.htm *.js *.jsx *.php"), ("All Files", "*.*")]
        )
        if file_path:
            self.url_entry.delete(0, 'end')
            self.url_entry.insert(0, file_path)

    def _on_analyze_url(self):
        target = self.url_entry.get().strip()
        if target:
            self.btn_analyze_url.configure(state="disabled", text="Analyzing...")
            self.html_box.delete("0.0", "end")
            self.ai_report_box.delete("0.0", "end")
            self.ai_report_box.insert("end", "LM Studio is analyzing...\nPlease wait.")
            self.analyze_url_callback(target)

    def update_web_defense_ui(self, html_code, ai_report):
        self.html_box.insert("end", html_code)
        self.ai_report_box.delete("0.0", "end")
        self.ai_report_box.insert("end", ai_report)
        self.btn_analyze_url.configure(state="normal", text="Analyze Source")

    def load_default_ports(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
        self.port_items.clear()
        for p in [21, 22, 80, 445, 3389]:
            self.add_port_row(p)

    def add_custom_port(self):
        port_txt = self.port_entry.get().strip()
        if port_txt.isdigit():
            port_num = int(port_txt)
            if port_num not in self.port_items:
                self.add_port_row(port_num)
        self.port_entry.delete(0, 'end')

    def add_port_row(self, port):
        row = ctk.CTkFrame(self.scroll_frame, fg_color="#333333", corner_radius=5)
        row.pack(fill="x", pady=2)
        
        chk_var = ctk.BooleanVar(value=True) 
        chk = ctk.CTkCheckBox(row, text="", variable=chk_var, width=20)
        chk.pack(side="left", padx=10, pady=5)
        
        lbl = ctk.CTkLabel(row, text=f"Port {port}", font=("Consolas", 14, "bold"), width=80, anchor="w")
        lbl.pack(side="left", padx=5)
        
        btn_info = ctk.CTkButton(row, text="Detail >", width=60, fg_color="#555555", hover_color="#777777",
                                 command=lambda p=port: self.show_port_details(p))
        btn_info.pack(side="right", padx=10)

        self.port_items[port] = {"var": chk_var, "label": lbl, "status": "Pending", "row_frame": row}

    def show_port_details(self, port):
        if not self.is_split_mode:
            self.list_panel.pack_forget() 
            self.list_panel.pack(side="left", fill="y", padx=(0, 10)) 
            self.detail_panel.pack(side="right", fill="both", expand=True) 
            self.is_split_mode = True

        self.lbl_detail_title.configure(text=f"Port {port} Inspection")
        status = self.port_items[port]["status"]
        self.lbl_detail_status.configure(text=f"Network Status: Listening (0.0.0.0:{port})" if status == "Active" else f"Network Status: {status}")
        
        self.ai_info_box.configure(state="normal")
        self.ai_info_box.delete("0.0", "end")
        self.ai_info_box.insert("end", "Awaiting AI Analysis...\n")
        self.ai_info_box.configure(state="disabled")

        self.port_info_callback(port)

    def update_port_status(self, port, status, color):
        if port in self.port_items:
            self.port_items[port]["status"] = status
            self.port_items[port]["label"].configure(text_color=color)
            if status == "Breach":
                self.port_items[port]["row_frame"].configure(fg_color="#aa0000")

    def show_ai_port_info(self, info_text):
        self.ai_info_box.configure(state="normal")
        self.ai_info_box.delete("0.0", "end")
        self.ai_info_box.insert("end", info_text)
        self.ai_info_box.configure(state="disabled")

    def get_selected_ports(self):
        selected = []
        for port, data in self.port_items.items():
            if data["var"].get():
                selected.append(port)
        return selected

    def get_config(self):
        return {
            "api_url": self.api_url.get().strip(),
            "sys_prompt": self.sys_prompt,
            "ports": self.get_selected_ports()
        }