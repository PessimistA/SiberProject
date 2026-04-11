from ui import AttackerUI
from core import AttackerCore

class AttackerController:
    def __init__(self):
        # Core'u başlat ve geri dönüş fonksiyonlarını tanımla
        self.core = AttackerCore(
            on_receive_callback=self.handle_server_response,
            on_disconnect_callback=self.handle_server_disconnect
        )
        
        # UI'ı başlat ve buton/enter fonksiyonlarını tanımla
        self.ui = AttackerUI(
            connect_callback=self.handle_connect,
            disconnect_callback=self.handle_disconnect,
            send_command_callback=self.handle_send_command
        )

    # --- UI'DAN CORE'A GİDEN EMİRLER ---
    def handle_connect(self, ip, port):
        self.ui.print_to_screen(f"[*] {ip}:{port} hedefine baglaniliyor...\n")
        
        success, message = self.core.connect(ip, port)
        
        if success:
            self.ui.toggle_buttons(connected=True)
        else:
            self.ui.print_to_screen(f"[-] Baglanti Hatasi: {message}\n")

    def handle_disconnect(self):
        self.core.disconnect()

    def handle_send_command(self, cmd):
        self.core.send_command(cmd)

    # --- CORE'DAN UI'A GELEN VERİLER ---
    def handle_server_response(self, text):
        # Sunucudan veri geldiğinde Tkinter arayüzüne GÜVENLİ bir şekilde (.after ile) yaz
        self.ui.after(0, lambda: self.ui.print_to_screen(text))

    def handle_server_disconnect(self):
        # Sunucu bağlantıyı kestiğinde (veya biz kestiğimizde) UI'ı güncelle
        def update_ui():
            self.ui.print_to_screen("\n[*] Baglanti kesildi.\n")
            self.ui.toggle_buttons(connected=False)
            
        self.ui.after(0, update_ui)

    def run(self):
        self.ui.mainloop()

if __name__ == "__main__":
    app = AttackerController()
    app.run()