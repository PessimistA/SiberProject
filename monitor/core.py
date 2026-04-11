import socket
import json
import threading
import time
import os
import glob
from datetime import datetime

class MonitorCore:
    def __init__(self, on_new_log, on_new_session, on_profile_update=None, on_history_loaded=None):
        # UI updates rely on these callbacks.
        self.on_new_log = on_new_log
        self.on_new_session = on_new_session
        self.on_profile_update = on_profile_update
        self.on_history_loaded = on_history_loaded
        
        self.is_running = False

        # Active session state tracker
        self.sessions = {}
        
        # Paths for persistent storage mapped via Docker volumes
        self.log_dir = "./data/session_logs"
        self.attacker_db_path = "./data/attacker_profiles/attacker_history.json"

    # Persistent Log Management

    def load_historical_logs(self, filter_ip=None, filter_date=None):
        """
        Parses the JSONL logs from disk.
        Can filter by a specific IP or a specific YYYY-MM-DD date.
        """
        if not os.path.exists(self.log_dir):
            return []

        results = []
        pattern = os.path.join(self.log_dir, "*.jsonl")
        files = sorted(glob.glob(pattern))

        for filepath in files:
            filename = os.path.basename(filepath)
            
            # Expected format: YYYY-MM-DD_192_168_1_5_port22.jsonl
            parts = filename.replace(".jsonl", "").split("_")
            file_date = parts[0] if parts else ""
            
            # Reconstruct the IP address replacing underscores with dots
            file_ip_raw = "_".join(parts[1:-1]) if len(parts) > 2 else ""
            file_ip = file_ip_raw.replace("_", ".")

            # Skip files that don't match our filters
            if filter_date and file_date != filter_date:
                continue
            if filter_ip and file_ip != filter_ip:
                continue

            # Read the file line by line since it's JSONL
            try:
                with open(filepath, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            results.append(entry)
                        except json.JSONDecodeError:
                            # Skip corrupted lines
                            pass
            except Exception:
                pass

        return results

    def get_available_dates(self):
        """Extracts unique dates from the filenames for the UI dropdown."""
        if not os.path.exists(self.log_dir):
            return []
            
        files = glob.glob(os.path.join(self.log_dir, "*.jsonl"))
        dates = set()
        
        for f in files:
            name = os.path.basename(f)
            parts = name.split("_")
            if parts:
                dates.add(parts[0])
                
        # Return newest first
        return sorted(list(dates), reverse=True)

    def get_available_ips(self, date=None):
        """Extracts unique IPs from the filenames, optionally filtering by date."""
        if not os.path.exists(self.log_dir):
            return []
            
        pattern = os.path.join(self.log_dir, f"{date}_*.jsonl" if date else "*.jsonl")
        files = glob.glob(pattern)
        ips = set()
        
        for f in files:
            name = os.path.basename(f).replace(".jsonl", "")
            parts = name.split("_")
            if len(parts) >= 3:
                ip_raw = "_".join(parts[1:-1])
                ips.add(ip_raw.replace("_", "."))
                
        return sorted(list(ips))

    def get_attacker_summary(self):
        """Reads the global attacker JSON database."""
        if not os.path.exists(self.attacker_db_path):
            return {}
            
        try:
            with open(self.attacker_db_path, "r") as f:
                return json.load(f)
        except:
            return {}

    def get_session_stats(self, ip=None):
        """Compiles aggregated statistics for the dashboard."""
        logs = self.load_historical_logs(filter_ip=ip)
        
        stats = {
            "total_commands": 0,
            "unique_ips": set(),
            "commands_by_type": {},
            "risky_commands": 0,
            "file_reads": 0,
            "download_attempts": 0,
            "login_attempts": 0,
        }
        
        # High-risk keywords to flag
        risky = ["wget", "curl", "chmod", "rm", "python", "bash", "sh", "./", "cat /etc/shadow", "id_rsa"]
        
        for entry in logs:
            cmd = entry.get("command", "")
            role = entry.get("role", "")
            eip = entry.get("ip", "")

            # Only count actual commands sent by the attacker
            if role == "attacker" and cmd not in ["SESSION_START"]:
                stats["total_commands"] += 1
                stats["unique_ips"].add(eip)
                
                # Get the base command (e.g., 'ls' from 'ls -la')
                base = cmd.split()[0] if cmd else "unknown"
                stats["commands_by_type"][base] = stats["commands_by_type"].get(base, 0) + 1
                
                if any(r in cmd for r in risky):
                    stats["risky_commands"] += 1
                if cmd.startswith("cat "):
                    stats["file_reads"] += 1
                if base in ["wget", "curl"]:
                    stats["download_attempts"] += 1
                if "login" in cmd.lower():
                    stats["login_attempts"] += 1

        # Convert the set to a list before returning
        stats["unique_ips"] = list(stats["unique_ips"])
        return stats

    # Behavioral Profiling Logic

    def _analyze_behavior(self, ip, cmd):
        """Assigns a risk score and profile based on the commands executed."""
        if ip not in self.sessions:
            self.sessions[ip] = {
                "commands": [],
                "risk_score": 0,
                "profile": "Unknown",
                "start_time": time.time()
            }

        session = self.sessions[ip]
        session["commands"].append(cmd)

        # Commands that indicate serious intent
        critical_cmds = ["wget", "curl", "chmod +x", "rm -rf", "id_rsa", "shadow",
                         "python3 -c", "bash -i", "nc ", "ncat", "socat", "/dev/tcp",
                         ".ssh", "authorized_keys", "crontab", "sudoers"]
                         
        # General recon commands
        recon_cmds = ["ls", "whoami", "pwd", "id", "uname", "netstat", "ps",
                      "cat /etc", "env", "history", "find /", "hostname"]

        # Calculate risk
        for c in critical_cmds:
            if c in cmd:
                session["risk_score"] += 25
                break

        for c in recon_cmds:
            if cmd.startswith(c) or c in cmd:
                session["risk_score"] += 5
                break

        cmd_count = len(session["commands"])
        score = session["risk_score"]

        # Assign profile tiers based on the score
        if score >= 75:
            session["profile"] = "APT / Advanced Threat"
        elif score >= 50:
            session["profile"] = "Professional Attacker"
        elif score >= 25:
            session["profile"] = "Explorer / Hacker"
        elif cmd_count >= 5:
            session["profile"] = "Script Kiddie"
        else:
            session["profile"] = "Bot / Scanner"

        # Push the update to the UI
        if self.on_profile_update:
            self.on_profile_update(ip, session["profile"], min(session["risk_score"], 100))

    # UDP Listener for Live Traffic

    def start_listening(self, host="0.0.0.0", port=5000):
        """Starts the background thread to catch incoming UDP logs from the honeypot."""
        self.is_running = True
        threading.Thread(target=self._udp_server, args=(host, port), daemon=True).start()

    def _udp_server(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))

        while self.is_running:
            try:
                # Max payload size
                data, addr = sock.recvfrom(65535)
                log_data = json.loads(data.decode('utf-8'))

                attacker_ip = log_data.get("attacker_ip") or log_data.get("sender", "unknown")

                # If the log is an attacker command, run it through the behavioral engine
                if log_data.get("role") == "attacker":
                    self._analyze_behavior(attacker_ip, log_data.get("text", ""))

                # Route the log data to the appropriate UI callback
                if log_data.get("type") == "session":
                    self.on_new_session(
                        log_data["attacker_ip"],
                        log_data.get("target", ""),
                        log_data.get("risk", "")
                    )
                else:
                    current_risk = self.sessions.get(attacker_ip, {}).get("risk_score", 0)
                    text = log_data.get("text", "")
                    
                    # Prepend the risk score to the log text if it's an attacker
                    enhanced = (
                        f"[Risk: {current_risk}] {text}"
                        if log_data.get("role") == "attacker" and current_risk > 0
                        else text
                    )
                    
                    self.on_new_log(
                        log_data.get("sender", "unknown"),
                        enhanced,
                        log_data.get("role", "system")
                    )

            except Exception as e:
                # Catch-all to keep the UDP server alive if parsing fails
                pass