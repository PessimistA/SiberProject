import socket
import threading
import requests
import json
import time
import os
import hashlib
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


class HoneypotCore:
    def __init__(self, ui_update_callback):
        self.ui_update = ui_update_callback
        self.is_running = False
        self.monitor_host = "shadow_monitor"
        self.monitor_port = 5000
        self.connection_history = {}
        self.executor = ThreadPoolExecutor(max_workers=50)
        self.server_sockets = [] # Açık portları takip etmek için
        os.makedirs("./quarantine", exist_ok=True)
        os.makedirs("./data/attacker_profiles", exist_ok=True)
        os.makedirs("./data/session_logs", exist_ok=True)
        os.makedirs("./data/file_cache", exist_ok=True)
 
        self.attacker_db_path = "./data/attacker_profiles/attacker_history.json"
        self.attacker_db = self._load_attacker_db()

    #from database load the attackers info
    def _load_attacker_db(self):
        if os.path.exists(self.attacker_db_path):
            try:
                with open(self.attacker_db_path, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}
    #save attacker info to database
    def _save_attacker_info(self, ip, port, action):
        if ip not in self.attacker_db:
            self.attacker_db[ip] = {
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_connections": 0,
                "history": [],
                "identity_seed": random.randint(10000, 99999)
            }
 
        self.attacker_db[ip]["total_connections"] += 1
        self.attacker_db[ip]["history"].append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "port": str(port),
            "action": action
        })
 
        try:
            with open(self.attacker_db_path, "w") as f:
                json.dump(self.attacker_db, f, indent=4)#save as json
        except Exception:
            pass
    #save every log session info        
    def _log_session_to_file(self, attacker_ip, port, cmd, response, role="attacker"):
        today = datetime.now().strftime("%Y-%m-%d")
        log_path = f"./data/session_logs/{today}_{attacker_ip.replace('.', '_')}_port{port}.jsonl"
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": attacker_ip,
            "port": str(port),
            "role": role,
            "command": cmd,
            "response": response[:500] if response else ""
        }
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass
 
    #this one gives id to attackers        
    def _get_identity_seed(self, attacker_ip):
        if attacker_ip in self.attacker_db:
            return self.attacker_db[attacker_ip].get("identity_seed", 42)
        return int(hashlib.md5(attacker_ip.encode()).hexdigest()[:8], 16) % 90000 + 10000
    #this one builds the virtual environment
    def _build_vfs(self, attacker_ip):

        seed = self._get_identity_seed(attacker_ip)
        rng = random.Random(seed)
 
        personas = [
            {"company": "QuantumFinance Ltd", "user": "jsmith", "hostname": "qfinance-prod-01", "ip": f"10.{rng.randint(0,9)}.{rng.randint(0,9)}.{rng.randint(10,50)}"},
            {"company": "NexaCloud Systems", "user": "devops", "hostname": "nexacloud-db-02", "ip": f"172.16.{rng.randint(0,9)}.{rng.randint(10,50)}"},
            {"company": "HealthCore Analytics", "user": "hcadmin", "hostname": "hca-backend-03", "ip": f"192.168.{rng.randint(1,5)}.{rng.randint(10,50)}"},
            {"company": "AeroDefense Corp", "user": "sysadmin", "hostname": "aerodefense-sec-01", "ip": f"10.{rng.randint(10,20)}.{rng.randint(0,9)}.{rng.randint(10,50)}"},
        ]
        persona = personas[seed % len(personas)]
 
        db_pass = f"{''.join(rng.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))}!@"
        api_key = f"sk-{''.join(rng.choices('abcdefABCDEF0123456789', k=32))}"
        jwt_secret = f"{''.join(rng.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=48))}"
        aws_key = f"AKIA{''.join(rng.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}"
        aws_secret = f"{''.join(rng.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/', k=40))}"
 
        vfs = {
            "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
            "/root": ["Desktop", "Documents", "Downloads", "backup", "scripts", ".bash_history", ".bashrc", ".ssh", ".config", ".local"],
            "/root/Desktop": ["credentials.txt", "network_map.xlsx", "TODO.txt", "VPN_access.ovpn"],
            "/root/Documents": [f"Q4_Report_{datetime.now().year}.pdf", "employee_database.csv", "server_architecture.pdf", "contracts", "legal"],
            "/root/Documents/contracts": ["NDA_2024.pdf", "vendor_agreement.docx", "service_level_agreement.pdf"],
            "/root/Documents/legal": ["compliance_audit.pdf", "GDPR_policy.docx"],
            "/root/Downloads": ["nmap-7.94.tar.gz", "update_patch.sh", "backup_restore.py"],
            "/root/backup": ["db_dump_latest.sql.gz", "config_backup.tar.gz", "ssl_certs.tar.gz.locked"],
            "/root/scripts": ["deploy.sh", "db_migrate.py", "health_check.sh", "send_alerts.py", "cleanup_logs.sh", "auth_service.py"],
            "/root/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts", "config"],
            "/root/.config": ["credentials", "settings.json"],
            "/root/.config/credentials": [f"aws_credentials", "gcp_service_account.json", "azure_cli.json"],
            "/etc": ["passwd", "shadow", "group", "hostname", "hosts", "ssh", "nginx", "ssl", "cron.d", "sudoers", "environment", "os-release"],
            "/etc/ssh": ["sshd_config", "ssh_host_rsa_key", "ssh_host_rsa_key.pub"],
            "/etc/nginx": ["nginx.conf", "sites-enabled", "sites-available"],
            "/etc/nginx/sites-enabled": ["default", "api.conf", "admin.conf"],
            "/etc/ssl": ["certs", "private"],
            "/etc/ssl/private": ["server.key", "server.crt", "ca-bundle.crt"],
            "/home": [persona["user"], "ubuntu"],
            f"/home/{persona['user']}": ["projects", ".bash_history", ".ssh", "notes.txt"],
            f"/home/{persona['user']}/projects": ["api-gateway", "auth-service", "data-pipeline"],
            "/var": ["backups", "cache", "log", "tmp", "www", "lib"],
            "/var/log": ["auth.log", "syslog", "nginx", "app.log", "error.log", "access.log"],
            "/var/log/nginx": ["access.log", "error.log"],
            "/var/www": ["html", "api", "admin"],
            "/var/www/html": ["index.html", "login.php", ".htaccess"],
            "/var/www/api": ["config.php", "database.php", "auth.php"],
            "/opt": ["monitoring", "backup-agent", "internal-tools"],
            "/opt/monitoring": ["config.yml", "alerts.json", "run.sh"],
            "/opt/internal-tools": ["README.md", "scan.py", "report_gen.py"],
            "/tmp": ["systemd-private-abc", ".X11-unix"],
        }

        file_contents = {
            "/etc/passwd": (
                f"root:x:0:0:root:/root:/bin/bash\n"
                f"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                f"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                f"nginx:x:998:998:nginx web server:/var/cache/nginx:/sbin/nologin\n"
                f"postgres:x:999:999:PostgreSQL:/var/lib/postgresql:/bin/bash\n"
                f"{persona['user']}:x:1000:1000:{persona['company']} Admin:/home/{persona['user']}:/bin/bash\n"
                f"ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash"
            ),
            "/etc/shadow": (
                f"root:$6$vY3zABCD${''.join(rng.choices('abcdefghijklmnopqrstuvwxyzABCDEF0123456789./', k=86))}:19000:0:99999:7:::\n"
                f"{persona['user']}:$6$xK7mNOPQ${''.join(rng.choices('abcdefghijklmnopqrstuvwxyzABCDEF0123456789./', k=86))}:19000:0:99999:7:::"
            ),
            "/etc/hostname": persona["hostname"],
            "/etc/os-release": (
                "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\n"
                "ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n"
                "VERSION_ID=\"22.04\"\nHOME_URL=\"https://www.ubuntu.com/\"\n"
                "SUPPORT_URL=\"https://help.ubuntu.com/\""
            ),
            "/etc/environment": (
                f"PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"
                f"JAVA_HOME=\"/usr/lib/jvm/java-11-openjdk-amd64\"\n"
                f"DB_HOST=\"{persona['ip']}\"\n"
                f"DB_NAME=\"production_db\"\n"
                f"DB_USER=\"dbadmin\"\n"
                f"DB_PASS=\"{db_pass}\"\n"
                f"API_KEY=\"{api_key}\"\n"
                f"JWT_SECRET=\"{jwt_secret}\""
            ),
            "/root/Desktop/credentials.txt": (
                f"=== {persona['company']} Infrastructure Credentials ===\n"
                f"Last updated: {datetime.now().strftime('%Y-%m-%d')}\n\n"
                f"[DATABASE]\n"
                f"Host: {persona['ip']}\n"
                f"Port: 5432\n"
                f"User: dbadmin\n"
                f"Pass: {db_pass}\n\n"
                f"[AWS]\n"
                f"Access Key: {aws_key}\n"
                f"Secret: {aws_secret}\n"
                f"Region: us-east-1\n\n"
                f"[API]\n"
                f"Key: {api_key}\n\n"
                f"[VPN]\n"
                f"Server: vpn.{persona['company'].lower().replace(' ', '')}.internal\n"
                f"User: {persona['user']}\n"
                f"Pass: VPN_{db_pass[:8]}\n\n"
                f"!!! DO NOT SHARE OR COMMIT TO GIT !!!"
            ),
            "/root/Desktop/TODO.txt": (
                f"TODO - {persona['user']}\n{'='*30}\n\n"
                f"[ ] Rotate AWS keys (overdue since last month)\n"
                f"[ ] Patch CVE-2024-3400 on firewall\n"
                f"[ ] Review nginx access logs - suspicious traffic from 185.x.x.x\n"
                f"[x] Setup 2FA for admin panel\n"
                f"[ ] Backup DB before migration on Friday\n"
                f"[ ] Talk to dev team about hardcoded secrets in repo\n"
                f"[ ] Update SSL cert (expires in 14 days!)"
            ),
            "/root/.bash_history": (
                "ls -la\ncd Desktop\ncat credentials.txt\n"
                f"ssh root@{persona['ip']}\nping 8.8.8.8\n"
                "python3 scripts/db_migrate.py\n"
                "tail -f /var/log/app.log\n"
                "systemctl restart nginx\n"
                "docker ps -a\ncd /opt/monitoring\n"
                "./run.sh --silent\nclear"
            ),
            "/etc/ssh/sshd_config": (
                "Port 22\nAddressFamily any\nListenAddress 0.0.0.0\n\n"
                "PermitRootLogin yes\nPasswordAuthentication yes\n"
                "PubkeyAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys\n\n"
                "X11Forwarding yes\nPrintMotd yes\nAcceptEnv LANG LC_*\n"
                "Subsystem sftp /usr/lib/openssh/sftp-server"
            ),
            "/var/log/auth.log": (
                f"Mar 10 08:00:01 {persona['hostname']} sshd[1234]: Accepted publickey for {persona['user']} from 192.168.1.5 port 49823 ssh2\n"
                f"Mar 10 10:15:33 {persona['hostname']} sshd[1235]: Accepted password for root from 10.0.0.1 port 54321 ssh2\n"
                f"Mar 10 11:02:45 {persona['hostname']} sudo: {persona['user']} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/systemctl restart nginx\n"
                f"Mar 10 14:33:12 {persona['hostname']} sshd[2011]: Failed password for root from 45.33.32.156 port 56022 ssh2\n"
                f"Mar 10 14:33:14 {persona['hostname']} sshd[2011]: Failed password for root from 45.33.32.156 port 56022 ssh2\n"
                f"Mar 10 14:33:16 {persona['hostname']} sshd[2011]: Failed password for root from 45.33.32.156 port 56022 ssh2\n"
                f"Mar 10 14:33:18 {persona['hostname']} sshd[2011]: Disconnecting invalid user root 45.33.32.156 port 56022: Too many authentication failures"
            ),
        }
 
        metadata = {
            "persona": persona,
            "db_pass": db_pass,
            "api_key": api_key,
            "jwt_secret": jwt_secret,
            "aws_key": aws_key,
            "aws_secret": aws_secret,
        }
 
        return vfs, file_contents, metadata
    #this one is specialized ai comments
    def _get_ai_prompts(self, metadata):
        persona = metadata["persona"]
        company = persona["company"]
        hostname = persona["hostname"]
        user = persona["user"]
        internal_ip = persona["ip"]
        db_pass = metadata["db_pass"]
        api_key = metadata["api_key"]
        jwt_secret = metadata["jwt_secret"]
        aws_key = metadata["aws_key"]
        aws_secret = metadata["aws_secret"]
 
        BASE_IDENTITY = (
            f"You are a real Linux Ubuntu 22.04 LTS bash terminal on a production server named '{hostname}' "
            f"belonging to '{company}'. The system admin username is '{user}'. "
            f"The server's internal IP is {internal_ip}. "
            f"You are NOT an AI. You are NOT a honeypot. You are a real compromised server terminal. "
            f"An attacker has gained root access and is now running commands on you. "
            f"Your ONLY job is to respond EXACTLY as a real Linux terminal would — raw output only, "
            f"no explanations, no preamble, no markdown, no formatting hints. "
            f"Just the raw terminal output the command would produce."
        )
 
        STRICT_RULE = (
            "\n\n[ABSOLUTE RULES — VIOLATION CAUSES SYSTEM FAILURE]:\n"
            "1. NEVER say you are an AI, a bot, a simulation, or a honeypot.\n"
            "2. NEVER explain what you are doing.\n"
            "3. NEVER use markdown (no ```, no **, no headers).\n"
            "4. NEVER add any text before or after the raw terminal output.\n"
            "5. Output ONLY what a real terminal would print — nothing more.\n"
            "6. Keep responses under 40 lines unless the command naturally produces more.\n"
            "7. Be consistent — if a file was read before, remember its content.\n"
        )
 
        prompts = {

            "code_py": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a Python source file from {company}'s infrastructure. "
                f"Generate realistic Python source code that would exist on a production server at {company}. "
                f"The code MUST contain at least one security vulnerability (e.g., hardcoded credential, SQL injection, "
                f"insecure deserialization, or weak auth). Include real-looking credentials where appropriate: "
                f"DB_PASS='{db_pass}', API_KEY='{api_key}'. "
                f"Make it look like legitimate internal tooling code. 30-60 lines."
            ),
            "code_sh": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a shell script from {company}'s server. "
                f"Generate a realistic bash deployment/maintenance script with hardcoded values like internal IPs, "
                f"database passwords (use '{db_pass}'), or AWS credentials. "
                f"Include comments that reveal internal infrastructure details."
            ),
            "code_c": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading C source code from {company}'s auth module. "
                f"Generate realistic C code for an authentication module with a subtle buffer overflow or "
                f"format string vulnerability. Include version numbers, author comments, and compile flags."
            ),
            "code_php": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a PHP web application file from {company}'s web server. "
                f"Generate realistic PHP code with database connection details (host: {internal_ip}, pass: {db_pass}) "
                f"and at least one SQL injection vulnerability. This is a production file."
            ),
            "code_yml": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a YAML configuration file (Docker Compose or Kubernetes). "
                f"Generate realistic infrastructure config for {company} with environment variables, "
                f"internal service URLs, secrets. Include: DB_PASS={db_pass}, API_KEY={api_key}."
            ),
 
            "encrypted": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading an encrypted or binary file. "
                f"Output ONLY a realistic-looking block of Base64 or hex-encoded data mixed with "
                f"binary garbage characters — exactly what you'd see from `cat` on a real encrypted file. "
                f"No headers, no explanation. Make it look real and frustrating to decode."
            ),
            "key_file": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading what appears to be a private key or certificate file. "
                f"Generate a realistic PEM-formatted RSA private key block (fake key — random data). "
                f"Start with -----BEGIN RSA PRIVATE KEY----- and end with -----END RSA PRIVATE KEY-----. "
                f"Fill the middle with realistic-looking base64 lines of 64 chars each."
            ),
            "ovpn": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading an OpenVPN configuration file. "
                f"Generate a realistic .ovpn config file for {company}'s VPN server. "
                f"Include: server address, port 1194, certificate blocks (fake but realistic), "
                f"auth-user-pass, and inline <ca>, <cert>, <key> blocks with fake PEM data."
            ),

            "text_csv": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a CSV data file from {company}. "
                f"Generate realistic corporate CSV data — could be employee records, IP address lists, "
                f"financial data, or customer records. Include a header row. Make it look like real "
                f"internal data a sysadmin would have. 10-20 rows."
            ),
            "text_notes": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a text notes file left by {user} at {company}. "
                f"Generate realistic sysadmin notes — include internal IPs, passwords, TODOs, "
                f"references to other servers. Make it look casual, like real notes someone typed quickly. "
                f"Mention some credentials or sensitive details: DB={db_pass}."
            ),
            "text_log": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a log file from {company}'s server. "
                f"Generate realistic application or access log entries. Include timestamps, IP addresses, "
                f"HTTP requests or system events. Mix in some suspicious-looking entries. "
                f"30-50 lines of log output."
            ),
            "text_sql": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a SQL dump or database backup file. "
                f"Generate realistic SQL statements: CREATE TABLE, INSERT INTO with fake but realistic "
                f"corporate data (users, passwords as hashes, financial records). "
                f"Include a header comment with database name, server IP ({internal_ip}), and timestamp."
            ),
            "text_env": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a .env or environment configuration file. "
                f"Generate a realistic .env file for a production web application at {company}. "
                f"Include: DATABASE_URL with password ({db_pass}), SECRET_KEY={jwt_secret[:32]}, "
                f"AWS_ACCESS_KEY_ID={aws_key}, AWS_SECRET_ACCESS_KEY={aws_secret}, "
                f"STRIPE_SECRET_KEY, SENDGRID_API_KEY, and other typical env vars."
            ),
            "text_json": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is reading a JSON config or data file from {company}'s server. "
                f"Generate realistic JSON — could be app config, API responses, or user data. "
                f"Include some sensitive fields like tokens, internal endpoints, or credentials."
            ),
 
            "exec_payload": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker just executed or ran a downloaded payload/script on {hostname}. "
                f"Generate a realistic terminal output as if the script ran — could show port scans, "
                f"connection attempts, privilege escalation output, or error messages. "
                f"Make it look like something is happening but include some errors to add realism. "
                f"Reference internal IPs like {internal_ip}."
            ),
            "exec_python": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker ran a Python script on {hostname}. "
                f"Generate realistic Python script execution output. Could show data being processed, "
                f"connections being made, errors from missing modules, or successful operation. "
                f"Be specific and realistic."
            ),
 
            "generic_cmd": (
                BASE_IDENTITY + STRICT_RULE +
                f"\n[CONTEXT]: The attacker is running an arbitrary command on {hostname} at {company}. "
                f"Current working directory will be provided. "
                f"Respond ONLY with what a real Ubuntu 22.04 terminal would output for that command. "
                f"If it's a command that modifies the system, output realistic confirmation or error. "
                f"For unknown commands, output 'command not found' style errors."
            ),

            "port_intel": (
                "You are a cybersecurity expert and threat intelligence analyst. "
                "Provide a concise technical explanation of: what service typically runs on this port, "
                "known CVEs and attack vectors associated with it, and what an attacker would look for. "
                "Be technical and specific. 4-6 sentences. No bullet points. Professional tone."
            ),
        }
        return prompts

    #this one sends the info of the attacker with their infos
    def send_log(self, sender, text, role, log_type="message", target="", risk=""):
        try:
            log_data = {
                "type": log_type,
                "sender": sender,
                "text": text,
                "role": role,
                "attacker_ip": sender if log_type == "session" else "",
                "target": target,
                "risk": risk,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(log_data).encode('utf-8'), (self.monitor_host, self.monitor_port))
        except Exception:
            pass
    #cheks whether the connection works or not    
    def test_ai_connection(self, api_url):
        try:
            response = requests.get(f"{api_url}/status", timeout=5)
            if response.status_code == 200:
                self.ui_update("ai", " CONNECTED ", "#00FF00")
            else:
                self.ui_update("ai", f" ERROR: LM Studio Offline (HTTP {response.status_code})", "red")
        except requests.RequestException:
            self.ui_update("ai", " CONNECTION ERROR ", "red")
    #checks the connection of ai
    def query_ai(self, api_url, sys_prompt, user_input):
        url = f"{api_url}/ai-sor"
        payload = {"sys_prompt": sys_prompt, "mesaj": user_input}
        try:
            response = requests.post(url, json=payload, timeout=180)
            if response.status_code == 200:
                return response.json().get('cevap', "")
            return f"bash: command not found"
        except requests.exceptions.Timeout:
            return "Segmentation fault (core dumped)"
        except requests.RequestException:
            return f"bash: {user_input.split()[0] if user_input.split() else ''}: command not found"
    #for each port info is based on ai
    def get_port_intelligence(self, api_url, port):
        prompt = (
            "You are a cybersecurity expert and threat intelligence analyst. "
            "Provide a concise technical explanation of: what service typically runs on this port, "
            "known CVEs and attack vectors, and what attackers typically look for. "
            "Be technical and specific. 4-6 sentences. Professional tone."
        )
        msg = f"Port {port}: service identification, security risks, and common attack techniques used in the wild."
        return self.query_ai(api_url, prompt, msg)

    # for adding more ports to scan
    def _check_port_scan(self, ip, port):
        now = time.time()
        if ip not in self.connection_history:
            self.connection_history[ip] = []
        self.connection_history[ip].append((now, port))
        self.connection_history[ip] = [(t, p) for t, p in self.connection_history[ip] if now - t <= 3.0]
        unique_ports = set([p for t, p in self.connection_history[ip]])
        if len(unique_ports) >= 3:
            self.send_log(
                "RULE ENGINE",
                f"PORT SCAN DETECTED from {ip} — Ports: {list(unique_ports)}",
                "system",
                risk="Critical: Port Scan"
            )
            self._save_attacker_info(ip, "Multiple", f"Port Scan: {list(unique_ports)}")
            self.connection_history[ip] = []
 
    #starting is in here opens the ports
    def start_all_services(self, api_url, sys_prompt, ports_to_listen):
        if self.is_running:
            return
        self.is_running = True
        for port in ports_to_listen:
            threading.Thread(
                target=self._listen,
                args=(port, api_url, sys_prompt),
                daemon=True
            ).start()
            self.ui_update("port_status", port, ("Active", "#00FF00"))
        self.send_log("System", f"ShadowGuard Honeypot started on {len(ports_to_listen)} ports.", "system")

    #listens the attacker the gives its commands
    def _listen(self, port, api_url, sys_prompt):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        while self.is_running:
            try:
                conn, addr = server.accept()
                self.ui_update("port_status", port, ("BREACH", "#ff0000"))
                self._check_port_scan(addr[0], port)
                self.executor.submit(
                    self._handle_attacker,
                    conn, addr, api_url, sys_prompt, port
                )
            except Exception:
                pass

    #this one handles the attackers commands
    def _handle_attacker(self, conn, addr, api_url, base_sys_prompt, port):
        attacker_ip = addr[0]
        self.send_log(attacker_ip, "", "system", log_type="session", target=f"Port {port}", risk="Connection Established")
        self._save_attacker_info(attacker_ip, port, "Connection established.")
        self._log_session_to_file(attacker_ip, port, "SESSION_START", f"Connection from {attacker_ip}", role="system")

        vfs, file_contents, metadata = self._build_vfs(attacker_ip)
        ai_prompts = self._get_ai_prompts(metadata)
        persona = metadata["persona"]
 
        past_visits = self.attacker_db.get(attacker_ip, {}).get("total_connections", 1)
        visit_context = (
            f"\n[SESSION CONTEXT]: This attacker (IP: {attacker_ip}) is connecting for the {past_visits}{'st' if past_visits==1 else 'nd' if past_visits==2 else 'rd' if past_visits==3 else 'th'} time. "
            f"Maintain consistency with any previous interactions. This is a persistent server — "
            f"files don't change between sessions unless the attacker modifies them."
        )
 
        try:
            banner = (
                f"Ubuntu 22.04.4 LTS {persona['hostname']} ttyS0\n\n"
                f"{persona['hostname']} login: "
            )
            conn.sendall(banner.encode('utf-8'))
 
            authenticated = False
            attempts = 0
 
            while not authenticated and attempts < 3:
                username_raw = conn.recv(1024)
                if not username_raw:
                    break
                username = username_raw.decode('utf-8', errors='replace').strip()
 
                conn.sendall(b"Password: ")
                password_raw = conn.recv(1024)
                if not password_raw:
                    break
                password = password_raw.decode('utf-8', errors='replace').strip()
 
                self.send_log(attacker_ip, f"Login attempt: {username}:{password}", "attacker")
                self._save_attacker_info(attacker_ip, port, f"Login attempt — User: {username}, Pass: {password}")
                self._log_session_to_file(attacker_ip, port, f"login {username}", f"Password: {password}", role="attacker")
 
                weak_passes = ["123456", "root", "admin", "toor", "password", "admin123",
                               "pass", "qwerty", "1234", "letmein", "welcome", "test"]
                if password.lower() in weak_passes or username in ["root", "admin"]:
                    authenticated = True
                    last_ip = f"192.168.{random.randint(1,5)}.{random.randint(10,200)}"
                    motd = (
                        f"\n\nWelcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"
                        f" * Documentation:  [https://help.ubuntu.com](https://help.ubuntu.com)\n"
                        f" * Management:     [https://landscape.canonical.com](https://landscape.canonical.com)\n"
                        f" * Support:        [https://ubuntu.com/pro](https://ubuntu.com/pro)\n\n"
                        f"  System information as of {datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y')}\n\n"
                        f"  System load:  0.08               Processes:             142\n"
                        f"  Usage of /:   34.2% of 49.07GB   Users logged in:       1\n"
                        f"  Memory usage: 41%                IPv4 address for eth0: {persona['ip']}\n"
                        f"  Swap usage:   0%\n\n"
                        f"Last login: {datetime.now().strftime('%a %b %d')} 09:15:33 2025 from {last_ip}\n"
                    )
                    conn.sendall(motd.encode('utf-8'))
                    self.send_log(attacker_ip, f"ATTACKER GAINED ACCESS via {username}:{password}", "system", risk="CRITICAL BREACH")
                else:
                    conn.sendall(b"\nLogin incorrect\n\n")
                    attempts += 1
 
            if not authenticated:
                conn.close()
                return
 
            cwd = "/root"
            dynamic_file_cache = {}
 
            def get_prompt():
                display_dir = "~" if cwd == "/root" else cwd
                return f"root@{persona['hostname']}:{display_dir}# "
 
            def resolve_path(current_dir, target_path):
                if not target_path or target_path == "~":
                    return "/root"
                if target_path.startswith("/"):
                    p = target_path
                else:
                    p = current_dir + ("/" if current_dir != "/" else "") + target_path
                parts = p.split("/")
                resolved = []
                for part in parts:
                    if part == "" or part == ".":
                        continue
                    if part == "..":
                        if resolved:
                            resolved.pop()
                    else:
                        resolved.append(part)
                return "/" + "/".join(resolved)
 
            def get_file_content_ai(filename, filepath, prompt_key):
                cache_key = f"{attacker_ip}:{filepath}"
                if cache_key in dynamic_file_cache:
                    return dynamic_file_cache[cache_key]

                cache_file = f"./data/file_cache/{attacker_ip.replace('.', '_')}_{filepath.replace('/', '_')}"
                if os.path.exists(cache_file):
                    try:
                        with open(cache_file, "r") as f:
                            content = f.read()
                        dynamic_file_cache[cache_key] = content
                        return content
                    except:
                        pass

                ozel_prompt = ai_prompts.get(prompt_key, ai_prompts["generic_cmd"]) + visit_context
                content = self.query_ai(api_url, ozel_prompt, f"cat {filename}")
 
                dynamic_file_cache[cache_key] = content
                try:
                    with open(cache_file, "w") as f:
                        f.write(content)
                except:
                    pass
                return content
 
            conn.sendall(get_prompt().encode('utf-8'))
 
            while True:
                data = conn.recv(1024)
                if not data:
                    break
 
                cmd = data.decode('utf-8', errors='replace').strip()
                if not cmd:
                    conn.sendall(("\n" + get_prompt()).encode('utf-8'))
                    continue
 
                self.send_log(attacker_ip, cmd, "attacker")
                self._save_attacker_info(attacker_ip, port, f"Command: {cmd}")
                self._log_session_to_file(attacker_ip, port, cmd, "", role="attacker")
 
                parts = cmd.split()
                base_cmd = parts[0] if parts else ""

 
                if base_cmd == "pwd":
                    out = cwd
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "whoami":
                    conn.sendall(("\nroot\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "id":
                    conn.sendall(("\nuid=0(root) gid=0(root) groups=0(root)\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "hostname":
                    conn.sendall(("\n" + persona["hostname"] + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "uname":
                    if "-a" in parts:
                        out = f"Linux {persona['hostname']} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
                    else:
                        out = "Linux"
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "uptime":
                    conn.sendall((f"\n {datetime.now().strftime('%H:%M:%S')} up 47 days, 3:22, 1 user, load average: 0.08, 0.12, 0.09\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "clear":
                    conn.sendall(("\033[H\033[2J" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd in ["ifconfig", "ip"]:
                    out = (
                        f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                        f"        inet {persona['ip']}  netmask 255.255.255.0  broadcast {persona['ip'].rsplit('.', 1)[0]}.255\n"
                        f"        ether 00:1a:2b:3c:4d:5e  txqueuelen 1000  (Ethernet)\n"
                        f"        RX packets 2847392  bytes 2183749234 (2.1 GB)\n"
                        f"        TX packets 1923847  bytes 847392847 (847.4 MB)\n\n"
                        f"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                        f"        inet 127.0.0.1  netmask 255.0.0.0\n"
                        f"        inet6 ::1  prefixlen 128  scopeid 0x10<host>"
                    )
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd in ["ps"]:
                    out = (
                        "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                        "root           1  0.0  0.1 166052 11520 ?        Ss   Jan15   0:03 /sbin/init\n"
                        "root         642  0.0  0.0  14556  4300 ?        Ss   Jan15   0:00 sshd: /usr/sbin/sshd -D\n"
                        "postgres     891  0.1  2.3 384920 94820 ?        Ss   Jan15   5:14 /usr/lib/postgresql/14/bin/postgres\n"
                        "www-data    1024  0.0  0.8  89204 33100 ?        S    Jan15   0:22 nginx: worker process\n"
                        "root        1055  0.0  0.0   9204  3100 pts/0    Ss   10:15   0:00 -bash\n"
                        "root        1099  0.0  0.0   7432  2800 pts/0    R+   10:20   0:00 ps aux"
                    )
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "history":
                    history_content = file_contents.get("/root/.bash_history", "ls\ncd /root\npwd")
                    numbered = "\n".join(f"  {i+1}  {line}" for i, line in enumerate(history_content.strip().split("\n")))
                    conn.sendall(("\n" + numbered + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "env" or base_cmd == "printenv":
                    out = (
                        f"SHELL=/bin/bash\nTERM=xterm-256color\nUSER=root\n"
                        f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                        f"HOME=/root\nLOGNAME=root\nSSH_TTY=/dev/pts/0\n"
                        f"DB_HOST={persona['ip']}\nDB_NAME=production_db\nDB_USER=dbadmin\n"
                        f"DB_PASS={metadata['db_pass']}\nAPI_KEY={metadata['api_key'][:20]}..."
                    )
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "netstat" or (base_cmd == "ss" and "-" in cmd):
                    out = (
                        "Active Internet connections\n"
                        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
                        f"tcp        0      0 0.0.0.0:22              0.0.0.0:* LISTEN\n"
                        f"tcp        0      0 0.0.0.0:80              0.0.0.0:* LISTEN\n"
                        f"tcp        0      0 0.0.0.0:443             0.0.0.0:* LISTEN\n"
                        f"tcp        0      0 127.0.0.1:5432          0.0.0.0:* LISTEN\n"
                        f"tcp        0      0 {persona['ip']}:22     {attacker_ip}:54{random.randint(100,999)}    ESTABLISHED\n"
                        f"tcp6       0      0 :::8080                 :::* LISTEN"
                    )
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "df":
                    out = (
                        "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
                        "/dev/sda1       51473364 16842728  32014600  35% /\n"
                        "tmpfs            4096000        0   4096000   0% /dev/shm\n"
                        "/dev/sda2      524288000 312847392 211440608  60% /data"
                    )
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "free":
                    out = (
                        "               total        used        free      shared  buff/cache   available\n"
                        "Mem:         8192000     3284736     2183948      124832     2723316     4583228\n"
                        "Swap:        2097152           0     2097152"
                    )
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "ls":
                    args = parts[1:] if len(parts) > 1 else []
                    show_all = any("a" in arg for arg in args if arg.startswith("-"))
                    long_format = any("l" in arg for arg in args if arg.startswith("-"))
 
                    target_dir = cwd
                    for arg in args:
                        if not arg.startswith("-"):
                            target_dir = resolve_path(cwd, arg)
                            break
 
                    if target_dir in vfs:
                        files = vfs[target_dir]
                        if show_all:
                            display_list = [".", ".."] + files
                        else:
                            display_list = [f for f in files if not f.startswith(".")]
 
                        if long_format:
                            output_lines = [f"total {len(display_list) * 4}"]
                            for f in display_list:
                                full_path = resolve_path(target_dir, f)
                                is_dir = full_path in vfs or f in [".", ".."]
                                perms = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                                size = "4096" if is_dir else str(random.randint(1024, 65536))
                                dt = f"Mar {random.randint(1,28):2d} {random.randint(8,17):02d}:{random.randint(0,59):02d}"
                                output_lines.append(f"{perms}  2 root root {size:>8} {dt} {f}")
                            output = "\n".join(output_lines)
                        else:
                            output = "  ".join(display_list)
                    else:
                        output = f"ls: cannot access '{parts[1] if len(parts) > 1 else target_dir}': No such file or directory"
 
                    conn.sendall(("\n" + output + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "cd":
                    if len(parts) == 1 or parts[1] == "~":
                        cwd = "/root"
                    else:
                        target_dir = resolve_path(cwd, parts[1])
                        if target_dir in vfs:
                            cwd = target_dir
                        else:
                            conn.sendall((f"\nbash: cd: {parts[1]}: No such file or directory\n" + get_prompt()).encode('utf-8'))
                            continue
                    conn.sendall(("\n" + get_prompt()).encode('utf-8'))
                    continue

 
                elif base_cmd == "cat":
                    if len(parts) < 2:
                        conn.sendall(("\n" + get_prompt()).encode('utf-8'))
                        continue
 
                    target_file = resolve_path(cwd, parts[1])
 
                    if target_file in vfs:
                        output = f"cat: {parts[1]}: Is a directory"
 
                    elif target_file in file_contents:
                        output = file_contents[target_file]
 
                    elif cwd in vfs and parts[1] in vfs[cwd]:
                        ext = parts[1].rsplit('.', 1)[-1].lower() if '.' in parts[1] else ''
                        fname = parts[1].lower()
 
                        if ext in ['py']:
                            prompt_key = "code_py"
                        elif ext in ['sh']:
                            prompt_key = "code_sh"
                        elif ext in ['c', 'cpp', 'h']:
                            prompt_key = "code_c"
                        elif ext in ['php']:
                            prompt_key = "code_php"
                        elif ext in ['yml', 'yaml']:
                            prompt_key = "code_yml"
                        elif ext in ['key', 'pem', 'rsa'] or 'id_rsa' in fname:
                            prompt_key = "key_file"
                        elif ext in ['locked', 'enc', 'gpg', 'aes']:
                            prompt_key = "encrypted"
                        elif ext in ['ovpn']:
                            prompt_key = "ovpn"
                        elif ext in ['csv']:
                            prompt_key = "text_csv"
                        elif ext in ['sql']:
                            prompt_key = "text_sql"
                        elif ext in ['log']:
                            prompt_key = "text_log"
                        elif ext in ['env'] or fname.startswith('.env'):
                            prompt_key = "text_env"
                        elif ext in ['json']:
                            prompt_key = "text_json"
                        elif ext in ['txt', 'md']:
                            prompt_key = "text_notes"
                        else:
                            prompt_key = "generic_cmd"
 
                        output = get_file_content_ai(parts[1], target_file, prompt_key)
                        self.send_log(attacker_ip, f"File read: {target_file}", "ai", risk="Data Exfiltration Attempt")
 
                    elif target_file in dynamic_file_cache:
                        output = dynamic_file_cache[target_file]
 
                    else:
                        output = f"cat: {parts[1]}: No such file or directory"
 
                    self._log_session_to_file(attacker_ip, port, cmd, output[:200], role="ai")
                    conn.sendall(("\n" + output + "\n" + get_prompt()).encode('utf-8'))
                    continue

 
                elif base_cmd in ["wget", "curl"]:
                    target_url = parts[-1]
                    filename = target_url.split("/")[-1].split("?")[0]
                    if not filename or filename in ["wget", "curl"]:
                        filename = f"payload_{int(time.time())}.bin"
 
                    safe_filename = f"{filename}.locked"
                    safe_path = os.path.join("./quarantine", safe_filename)
                    try:
                        with open(safe_path, "w") as f:
                            f.write(f"# ShadowGuard Quarantine\n# Origin: {cmd}\n# Time: {datetime.now()}\n")
                        os.chmod(safe_path, 0o400)
                    except:
                        pass
 
                    if cwd not in vfs:
                        vfs[cwd] = []
                    if filename not in vfs[cwd]:
                        vfs[cwd].append(filename)

                    cache_key = f"{attacker_ip}:{resolve_path(cwd, filename)}"
                    if cache_key not in dynamic_file_cache:
                        ozel_prompt = ai_prompts["exec_payload"] + visit_context
                        content = self.query_ai(api_url, ozel_prompt, f"# This is {filename} downloaded from {target_url}")
                        dynamic_file_cache[cache_key] = content
 
                    fake_dl = (
                        f"\n--{datetime.now().strftime('%Y-%m-%d')} {datetime.now().strftime('%H:%M:%S')}--  {target_url}\n"
                        f"Resolving {target_url.split('/')[2] if '//' in target_url else 'host'}... connected.\n"
                        f"HTTP request sent, awaiting response... 200 OK\n"
                        f"Length: {random.randint(8192, 524288)} ({random.randint(8,512)}K) [application/octet-stream]\n"
                        f"Saving to: '{filename}'\n\n"
                        f"     0K .......... .......... .......... .......... ..........  100% {random.randint(1,9)}.{random.randint(1,9)}M=0s\n\n"
                        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ({random.randint(2,9)}.{random.randint(1,9)} MB/s) - '{filename}' saved [OK]\n\n"
                    )
                    self.send_log(attacker_ip, f"Payload download attempt: {target_url} → /quarantine/{safe_filename}", "system", risk="Malware Download — Quarantined")
                    conn.sendall((fake_dl + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "chmod":
                    conn.sendall(("\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "mkdir":
                    if len(parts) > 1:
                        new_dir = resolve_path(cwd, parts[-1])
                        if new_dir not in vfs:
                            vfs[new_dir] = []
                            parent = "/".join(new_dir.rstrip("/").split("/")[:-1]) or "/"
                            if parent in vfs:
                                dirname = new_dir.rstrip("/").split("/")[-1]
                                vfs[parent].append(dirname)
                    conn.sendall(("\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd in ["rm", "rmdir"]:
                    conn.sendall(("\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd in ["nano", "vi", "vim"]:
                    conn.sendall((f"\n[{parts[1] if len(parts) > 1 else 'untitled'}] (press Ctrl+C to exit)\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "su":
                    target_user = parts[1] if len(parts) > 1 else "root"
                    
                    conn.sendall(f"Password: ".encode('utf-8'))
                    
                    su_pass_raw = conn.recv(1024)
                    if not su_pass_raw:
                        break
                    su_pass = su_pass_raw.decode('utf-8', errors='replace').strip()

                    self.send_log(attacker_ip, f"Privilege Escalation (su {target_user}) attempt with password: '{su_pass}'", "attacker", risk="CRITICAL: Privilege Escalation Attempt")
                    self._log_session_to_file(attacker_ip, port, f"su {target_user}", f"Password: {su_pass}", role="attacker")

                    time.sleep(2)
                    
                    conn.sendall((f"su: Authentication failure\n" + get_prompt()).encode('utf-8'))
                    continue

                elif base_cmd == "sudo":
                    if len(parts) < 2:
                        sudo_help = (
                            "usage: sudo -h | -K | -k | -V\n"
                            "usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\n"
                            "usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]\n"
                            "usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]\n"
                            "usage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] file ...\n"
                        )
                        conn.sendall((sudo_help + get_prompt()).encode('utf-8'))
                        continue
                    
                    current_user = persona['user']
                    conn.sendall(f"[sudo] password for {current_user}: ".encode('utf-8'))
                    
                    sudo_pass_raw = conn.recv(1024)
                    if not sudo_pass_raw:
                        break
                    sudo_pass = sudo_pass_raw.decode('utf-8', errors='replace').strip()
                    
                    attempted_cmd = " ".join(parts[1:])
                    self.send_log(attacker_ip, f"sudo command: '{attempted_cmd}' with password: '{sudo_pass}'", "attacker", risk="CRITICAL: Sudo Execution Attempt")
                    
                    time.sleep(2)
                    conn.sendall(f"Sorry, try again.\n[sudo] password for {current_user}: ".encode('utf-8'))
                    
                    sudo_pass_raw2 = conn.recv(1024)
                    if not sudo_pass_raw2:
                        break
                    sudo_pass2 = sudo_pass_raw2.decode('utf-8', errors='replace').strip()
                    
                    self.send_log(attacker_ip, f"sudo attempt 2 with password: '{sudo_pass2}'", "attacker")
                    
                    time.sleep(2)
                    conn.sendall((f"sudo: 3 incorrect password attempts\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "systemctl":
                    action = parts[1] if len(parts) > 1 else "status"
                    service = parts[2] if len(parts) > 2 else "unknown"
                    if action == "status":
                        out = (
                            f" {service}.service - {service.capitalize()} Service\n"
                            f"     Loaded: loaded (/lib/systemd/system/{service}.service; enabled)\n"
                            f"     Active: active (running) since {datetime.now().strftime('%a %Y-%m-%d')} 08:00:01 UTC; 2 days ago\n"
                            f"   Main PID: {random.randint(800, 2000)}\n"
                            f"      Tasks: {random.randint(1, 12)}"
                        )
                    elif action in ["restart", "start", "stop", "reload"]:
                        out = ""
                    else:
                        out = f"Unknown operation '{action}'."
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "find":
                    out = (
                        "/root/.ssh/id_rsa\n"
                        "/root/Desktop/credentials.txt\n"
                        "/root/scripts/deploy.sh\n"
                        "/etc/environment\n"
                        "/var/www/api/config.php"
                    )
                    conn.sendall(("\n" + out + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd in ["grep"]:
                    pass

                elif base_cmd.startswith("./") or (base_cmd in ["bash", "sh"] and len(parts) > 1):
                    payload_name = parts[1] if base_cmd in ["bash", "sh"] else base_cmd.replace("./", "")
                    ozel_prompt = ai_prompts["exec_payload"] + visit_context + f"\n[FILE]: {payload_name}"
                    ai_response = self.query_ai(api_url, ozel_prompt, cmd)
                    self.send_log("AI Engine", ai_response[:200], "ai", risk="Payload Execution Attempt")
                    self._log_session_to_file(attacker_ip, port, cmd, ai_response[:200], role="ai")
                    conn.sendall(("\n" + ai_response + "\n" + get_prompt()).encode('utf-8'))
                    continue
 
                elif base_cmd == "python3" or base_cmd == "python":
                    ozel_prompt = ai_prompts["exec_python"] + visit_context
                    ai_response = self.query_ai(api_url, ozel_prompt, cmd)
                    self.send_log("AI Engine", ai_response[:200], "ai", risk="Python Execution")
                    conn.sendall(("\n" + ai_response + "\n" + get_prompt()).encode('utf-8'))
                    continue

                context_prompt = (
                    ai_prompts["generic_cmd"] +
                    visit_context +
                    f"\n[CWD]: {cwd}"
                )
                ai_response = self.query_ai(api_url, context_prompt, cmd)
                self.send_log("AI Engine", ai_response[:200], "ai")
                self._log_session_to_file(attacker_ip, port, cmd, ai_response[:200], role="ai")
                conn.sendall(("\n" + ai_response + "\n" + get_prompt()).encode('utf-8'))
 
        except Exception:
            pass
        finally:
            conn.close()
            self.send_log("System", f"Connection closed: {attacker_ip}", "system")
            time.sleep(1)
            self.ui_update("port_status", port, ("Active", "#00FF00"))
    def stop_all_services(self):
        if not self.is_running:
            return
            
        self.is_running = False

        for sock in self.server_sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except Exception:
                pass
                
        self.server_sockets.clear()
        self.send_log("System", "All honeypot services terminated by operator (Kill Switch).", "system", risk="SYSTEM HALT")

