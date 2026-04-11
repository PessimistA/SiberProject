import customtkinter as ctk

class AttackerUI(ctk.CTk):
    def __init__(self, connect_callback, disconnect_callback, send_command_callback):
        super().__init__()
        self.title("ShadowGuard - APT Infiltration Terminal")
        self.geometry("900x600")
        ctk.set_appearance_mode("dark")
        
        # Communication bridges originating from main.py
        self.connect_callback = connect_callback
        self.disconnect_callback = disconnect_callback
        self.send_command_callback = send_command_callback
        
        # --- TOP BAR (Target Definition) ---
        self.top_frame = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=0)
        self.top_frame.pack(fill="x", side="top")
        
        self.ip_entry = ctk.CTkEntry(self.top_frame, width=150, font=("Consolas", 12))
        self.ip_entry.insert(0, "shadow_honeypot")
        self.ip_entry.pack(side="left", padx=10, pady=10)
        
        self.port_entry = ctk.CTkEntry(self.top_frame, width=80, font=("Consolas", 12))
        self.port_entry.insert(0, "22")
        self.port_entry.pack(side="left", padx=10, pady=10)
        
        self.btn_connect = ctk.CTkButton(self.top_frame, text="Initiate Breach", fg_color="#660000", hover_color="#880000", font=("Consolas", 13, "bold"), command=self._on_connect_click)
        self.btn_connect.pack(side="left", padx=10)
        
        self.btn_disconnect = ctk.CTkButton(self.top_frame, text="Disconnect", state="disabled", fg_color="#333333", command=self._on_disconnect_click)
        self.btn_disconnect.pack(side="left", padx=10)
        
        # --- MAIN TERMINAL SCREEN (The core of the illusion) ---
        self.terminal = ctk.CTkTextbox(self, fg_color="#050505", text_color="#00FF00", font=("Consolas", 16, "bold"), wrap="word")
        self.terminal.pack(fill="both", expand=True, padx=5, pady=5)
        
        # --- TERMINAL MANIPULATIONS (Security Shield) ---
        self.terminal.bind("<Return>", self._on_enter)
        self.terminal.bind("<BackSpace>", self._on_backspace)
        self.terminal.bind("<Key>", self._on_key)
        self.terminal.bind("<Button-1>", self._on_click) 
        
        # "Boundary Line" that the user cannot delete
        self.input_start_index = "1.0"
        self.is_connected = False
        
        self.print_to_screen("ShadowGuard APT Infiltration Terminal v2.0\nUse the top panel to connect to a target...\n\n")

    def print_to_screen(self, text):
        """Prints incoming text (from outside or the server) to the screen and locks the boundary."""
        self.terminal.configure(state="normal")
        self.terminal.insert("end", text)
        self.terminal.see("end")
        
        # New boundary: immediately following the last character
        self.input_start_index = self.terminal.index("end-1c")

    def toggle_buttons(self, connected):
        """Toggles buttons based on the connection status."""
        self.is_connected = connected
        if connected:
            self.btn_connect.configure(state="disabled")
            self.btn_disconnect.configure(state="normal")
        else:
            self.btn_connect.configure(state="normal")
            self.btn_disconnect.configure(state="disabled")
            self.input_start_index = self.terminal.index("end-1c")

    # --- BUTTON TRIGGERS ---
    def _on_connect_click(self):
        ip = self.ip_entry.get().strip()
        port = int(self.port_entry.get().strip())
        self.connect_callback(ip, port)

    def _on_disconnect_click(self):
        self.disconnect_callback()

    # --- KEYBOARD ILLUSION AND CONTROLS ---
    def _on_enter(self, event):
        if not self.is_connected: return "break"
        
        # Retrieve user input starting from the boundary line
        cmd = self.terminal.get(self.input_start_index, "end-1c")
        
        # FIX: Manually insert a newline into the UI BEFORE sending the command.
        # This forces server responses (like "Password:") to appear cleanly on the next line.
        self.terminal.insert("end", "\n")
        self.terminal.see("end")
        
        # Update the boundary index so the user cannot backspace the newline we just added
        self.input_start_index = self.terminal.index("end-1c")
        
        # Route the command to the core via main.py
        self.send_command_callback(cmd)
        
        # Prevent Tkinter from proceeding to the next line natively (we just handled it)
        return "break"

    def _on_backspace(self, event):
        # Refuse to delete if the cursor is at the boundary line when backspace is pressed.
        if self.terminal.compare("insert", "<=", self.input_start_index):
            return "break"
            
    def _on_key(self, event):
        # Prevent moving past the boundary line using arrow keys.
        if event.keysym not in ["Return", "BackSpace"]:
            if self.terminal.compare("insert", "<", self.input_start_index):
                self.terminal.mark_set("insert", "end")
                
    def _on_click(self, event):
        # Prevent clicking into previous lines and modifying them with the mouse.
        self.terminal.after(10, lambda: self.terminal.mark_set("insert", "end"))