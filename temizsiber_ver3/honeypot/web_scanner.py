import os
import re
import requests
from urllib.parse import urlparse

class SecurityWebScanner:
    def __init__(self, ai_bridge_url="http://shadow_ai_koprusu:5000"):
        self.ai_bridge_url = ai_bridge_url
        
        self.allowed_networks = ["localhost", "127.0.0.1", "10.", "192.168.", "172."]
        self.allowed_extensions = [".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".php", ".txt"]

    # Check if the web address is a safe local address or a Docker container name
    def _is_url_in_scope(self, target_url):
        if target_url.startswith("http://") or target_url.startswith("https://"):
            domain = urlparse(target_url).hostname

            if domain and ("." not in domain):
                return True
                
            if domain and (any(domain.startswith(net) for net in self.allowed_networks) or domain == "localhost"):
                return True
        return False

    # Check if the file type is allowed to be scanned
    def _is_file_in_scope(self, file_path):
        if os.path.exists(file_path):
            ext = os.path.splitext(file_path)[1].lower()
            if ext in self.allowed_extensions or file_path.endswith(""):
                return True
        return False

    # Download the code from web link safely
    def fetch_from_url(self, target_url):
        if not self._is_url_in_scope(target_url):
            return None, "Target URL out of scope. Only local networks are permitted."

        try:
            headers = {'User-Agent': 'ShadowGuard-SecScanner/2.0'}
            res = requests.get(target_url, headers=headers, timeout=5)
            res.raise_for_status()
            return res.text, None
        except Exception as e:
            return None, f"Failed to fetch source code from URL: {str(e)}"

    # Fetch from a file on computer
    def fetch_from_file(self, file_path):
        if not self._is_file_in_scope(file_path):
            return None, "Invalid file path or unsupported file extension."

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read(), None
        except Exception as e:
            return None, f"Failed to read uploaded file: {str(e)}"

    # Scan the code using simple text search rules to find basic threats
    def static_analysis(self, code):
        findings = []
        
        patterns = {
            "Cookie Harvesting": r"document\.cookie",
            "Hidden Iframe Injection": r"<iframe[^>]*style=[\"'][^>]*display:\s*none",
            "Malicious Redirection": r"window\.location|location\.href",
            "Code Obfuscation": r"eval\(|atob\(|btoa\(|fromCharCode",
            "Data Exfiltration Endpoint": r"fetch\(|XMLHttpRequest\(|\$\.ajax\(",
            "Suspicious Form Action": r"<form[^>]*action=[\"']http",
            "Web3/Crypto Drainer Interaction": r"window\.ethereum|eth_requestAccounts|sendTransaction"
        }

        for risk_name, pattern in patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            match_list = [m.group(0) for m in matches]
            if match_list:
                findings.append({
                    "risk": risk_name,
                    "count": len(match_list),
                    "samples": match_list[:3] 
                })
                
        return findings

    # Ask the AI to look at the code and find smart threats
    def ai_analysis(self, code):

        code_snippet = code[:8000] if len(code) > 8000 else code
        
        sys_prompt = (
            "You are an elite Blue Team cybersecurity analyst and source code auditor. "
            "You will be provided with an HTML/JS/JSX code snippet. "
            "Analyze this code for malicious intent, including Phishing, Data Exfiltration, XSS, or Cryptocurrency Drainers. "
            "Provide your technical findings, specifying a strict SEVERITY RATING (Critical/High/Medium/Low), and cite specific code samples. "
            "If the code is completely benign, state: 'No malicious activity detected.'"
        )
        
        try:
            payload = {"sys_prompt": sys_prompt, "mesaj": f"TARGET SOURCE CODE:\n```\n{code_snippet}\n```"}
            res = requests.post(f"{self.ai_bridge_url}/ai-sor", json=payload, timeout=70)
            if res.status_code == 200:
                return res.json().get("cevap", "AI engine failed to generate a response.")
            return f"AI Bridge Error: HTTP {res.status_code}"
        except requests.exceptions.RequestException:
            return "AI Bridge unreachable. Verify shadow_ai_koprusu status."

    # Manage the complete scanning order: static search first, then AI
    def _run_analysis_pipeline(self, code, target_name):
        print(f"\n[*] INITIATING SCAN: {target_name}")
        print(f"[+] Source code retrieved successfully. Size: {len(code)} characters.")
        
        report = []

        print("\n 1. STATIC ANALYSIS ")
        static_results = self.static_analysis(code)
        if static_results:
            for finding in static_results:
                msg = f"[!] DETECTED: {finding['risk']} ({finding['count']} matches)\n    Samples: {', '.join(finding['samples'])}"
                print(msg)
                report.append(msg)
        else:
            msg = "[+] No known malicious patterns detected during static analysis."
            print(msg)
            report.append(msg)

        print("\n 2. AI BEHAVIORAL ANALYSIS")
        print("[~] Transmitting code to Threat Intelligence Engine, please wait...")
        ai_report = self.ai_analysis(code)
        
        print("\n[THREAT INTELLIGENCE REPORT]:")
        print(ai_report)
        print("-" * 50)
        
        report.append("\n[THREAT INTELLIGENCE REPORT]:\n" + ai_report)
        return "\n".join(report)

    # Start the scanning process for a web link
    def scan_url(self, url):
        code, error = self.fetch_from_url(url)
        if error:
            print(f"[!] ERROR: {error}")
            return None, error
        return code, self._run_analysis_pipeline(code, url)

    # Start the scanning process for a file
    def scan_file(self, file_path):
        code, error = self.fetch_from_file(file_path)
        if error:
            print(f"[!] ERROR: {error}")
            return None, error
        return code, self._run_analysis_pipeline(code, file_path)

if __name__ == "__main__":
    scanner = SecurityWebScanner(ai_bridge_url="http://localhost:5000") 
    
    while True:
        choice = input("\nSelect input method (1: URL, 2: Upload File, q: Quit): ")
        if choice.lower() == 'q':
            break
            
        if choice == '1':
            hedef = input("Enter Local URL (e.g., http://shadow_kurban:8000/test.html): ")
            code, report = scanner.scan_url(hedef)
        elif choice == '2':
            hedef = input("Enter File Path (e.g., /app/payloads/malware.js): ")
            code, report = scanner.scan_file(hedef)
        else:
            print("Invalid choice.")