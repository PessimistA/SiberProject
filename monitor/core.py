import socket
import json
import threading
import time
import os
import glob
from datetime import datetime
 
 
class MonitorCore:
    def __init__(self, on_new_log, on_new_session, on_profile_update=None, on_history_loaded=None):
        self.on_new_log = on_new_log
        self.on_new_session = on_new_session
        self.on_profile_update = on_profile_update
        self.on_history_loaded = on_history_loaded
        self.is_running = False
 
        self.sessions = {}

        self.log_dir = "./data/session_logs"
        self.attacker_db_path = "./data/attacker_profiles/attacker_history.json"

    # PERSISTENT LOG READING
 
    def load_historical_logs(self, filter_ip=None, filter_date=None):
        """
        Reads all persisted .jsonl session log files.
        Returns a list of log entries, optionally filtered by IP or date.
        """
        if not os.path.exists(self.log_dir):
            return []
 
        results = []
        pattern = os.path.join(self.log_dir, "*.jsonl")
        files = sorted(glob.glob(pattern))
 
        for filepath in files:
            filename = os.path.basename(filepath)
            # Filename format: YYYY-MM-DD_IP_portXXXX.jsonl
            parts = filename.replace(".jsonl", "").split("_")
            file_date = parts[0] if parts else ""
            file_ip_raw = "_".join(parts[1:-1]) if len(parts) > 2 else ""
            file_ip = file_ip_raw.replace("_", ".")
 
            if filter_date and file_date != filter_date:
                continue
            if filter_ip and file_ip != filter_ip:
                continue
 
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
                            pass
            except Exception:
                pass
 
        return results
 
    def get_available_dates(self):
        """Returns sorted list of dates that have log files."""
        if not os.path.exists(self.log_dir):
            return []
        files = glob.glob(os.path.join(self.log_dir, "*.jsonl"))
        dates = set()
        for f in files:
            name = os.path.basename(f)
            parts = name.split("_")
            if parts:
                dates.add(parts[0])
        return sorted(list(dates), reverse=True)
 
    def get_available_ips(self, date=None):
        """Returns list of attacker IPs that have log files (optionally filtered by date)."""
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
        """Returns summary data from attacker_history.json."""
        if not os.path.exists(self.attacker_db_path):
            return {}
        try:
            with open(self.attacker_db_path, "r") as f:
                return json.load(f)
        except:
            return {}
 
    def get_session_stats(self, ip=None):
        """Returns session statistics from log files."""
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
        risky = ["wget", "curl", "chmod", "rm", "python", "bash", "sh", "./", "cat /etc/shadow", "id_rsa"]
        for entry in logs:
            cmd = entry.get("command", "")
            role = entry.get("role", "")
            eip = entry.get("ip", "")
 
            if role == "attacker" and cmd not in ["SESSION_START"]:
                stats["total_commands"] += 1
                stats["unique_ips"].add(eip)
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
 
        stats["unique_ips"] = list(stats["unique_ips"])
        return stats

    # BEHAVIOR ANALYSIS ENGINE
 
    def _analyze_behavior(self, ip, cmd):
        if ip not in self.sessions:
            self.sessions[ip] = {
                "commands": [],
                "risk_score": 0,
                "profile": "Unknown",
                "start_time": time.time()
            }
 
        session = self.sessions[ip]
        session["commands"].append(cmd)
 
        critical_cmds = ["wget", "curl", "chmod +x", "rm -rf", "id_rsa", "shadow",
                         "python3 -c", "bash -i", "nc ", "ncat", "socat", "/dev/tcp",
                         ".ssh", "authorized_keys", "crontab", "sudoers"]
        recon_cmds = ["ls", "whoami", "pwd", "id", "uname", "netstat", "ps",
                      "cat /etc", "env", "history", "find /", "hostname"]
 
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
 
        # Profile detection logic
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
 
        if self.on_profile_update:
            self.on_profile_update(ip, session["profile"], min(session["risk_score"], 100))

    # UDP LISTENER
 
    def start_listening(self, host="0.0.0.0", port=5000):
        self.is_running = True
        threading.Thread(target=self._udp_server, args=(host, port), daemon=True).start()
 
    def _udp_server(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
 
        while self.is_running:
            try:
                data, addr = sock.recvfrom(65535)
                log_data = json.loads(data.decode('utf-8'))
 
                attacker_ip = log_data.get("attacker_ip") or log_data.get("sender", "unknown")
 
                if log_data.get("role") == "attacker":
                    self._analyze_behavior(attacker_ip, log_data.get("text", ""))
 
                if log_data.get("type") == "session":
                    self.on_new_session(
                        log_data["attacker_ip"],
                        log_data.get("target", ""),
                        log_data.get("risk", "")
                    )
                else:
                    current_risk = self.sessions.get(attacker_ip, {}).get("risk_score", 0)
                    text = log_data.get("text", "")
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
                pass