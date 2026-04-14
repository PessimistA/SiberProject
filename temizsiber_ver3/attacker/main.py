from ui import AttackerUI
from core import AttackerCore

class AttackerController:
    def __init__(self):
        self.core = AttackerCore(
            on_receive_callback=self.handle_server_response,
            on_disconnect_callback=self.handle_server_disconnect
        )
        
        self.ui = AttackerUI(
            connect_callback=self.handle_connect,
            disconnect_callback=self.handle_disconnect,
            send_command_callback=self.handle_send_command
        )
    # Connect to target using an IP adress and a port
    def handle_connect(self, ip, port):
        self.ui.print_to_screen(f"[*] {ip}:{port} getting connect...\n")
        
        success, message = self.core.connect(ip, port)
        
        if success:
            self.ui.toggle_buttons(connected=True)
        else:
            self.ui.print_to_screen(f"[-] Connection error: {message}\n")
    #tell the core logic stop current connection
    def handle_disconnect(self):
        self.core.disconnect()
    #take the command from ui and send it to the core
    def handle_send_command(self, cmd):
        self.core.send_command(cmd)
    #after recieve the text showsn on the UI screen
    def handle_server_response(self, text):
        self.ui.after(0, lambda: self.ui.print_to_screen(text))
    # Reset the UI buttons and show a message when connection is lost
    def handle_server_disconnect(self):
        def update_ui():
            self.ui.print_to_screen("\n[*] Connection error.\n")
            self.ui.toggle_buttons(connected=False)
            
        self.ui.after(0, update_ui)
    
    def run(self):
        self.ui.mainloop()

if __name__ == "__main__":
    app = AttackerController()
    app.run()