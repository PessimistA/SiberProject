import os
import threading
from ui import HoneypotUI
from core import HoneypotCore
from web_scanner import SecurityWebScanner

class HoneypotController:
    def __init__(self):
        # 4 Core Hooks: Start, Stop, Port Intelligence, and Web/File Intelligence
        self.ui = HoneypotUI(
            start_callback=self.handle_start_server,
            stop_callback=self.handle_stop_server, 
            port_info_callback=self.handle_get_ai_port_info,
            analyze_url_callback=self.handle_analyze_target
        )
        self.core = HoneypotCore(ui_update_callback=self.safe_ui_update)
        
        # Initialize the Web/File scanning engine
        self.web_scanner = SecurityWebScanner(ai_bridge_url="http://shadow_ai_koprusu:5000")

    def safe_ui_update(self, component, key, data=None):
        """Dispatches backend data updates to the UI safely (preventing Main Thread freezes)."""
        if component == "port_status":
            status, color = data
            self.ui.after(0, lambda: self.ui.update_port_status(key, status, color))
        elif component == "ai_info":
            self.ui.after(0, lambda: self.ui.show_ai_port_info(key))

    # ==========================================
    # NETWORK DEFENSE CONTROLLER (Ports/Terminal)
    # ==========================================
    def handle_start_server(self):
        config = self.ui.get_config()
        ports_to_listen = config["ports"]
        
        if not ports_to_listen:
            return 

        # Update UI state (Activate the Kill Switch button)
        self.ui.btn_start.configure(state="disabled", text="Listening...") 
        self.ui.btn_stop.configure(state="normal") 
        
        self.core.start_all_services(config["api_url"], config["sys_prompt"], ports_to_listen)

    def handle_stop_server(self):
        """Forcefully terminates the system and resets UI status."""
        self.core.stop_all_services()
        
        # Revert UI state
        self.ui.btn_stop.configure(state="disabled")
        self.ui.btn_start.configure(state="normal", text="Listen on Selected Ports")
        
        # Reset the color and status text of previously active ports
        config = self.ui.get_config()
        for port in config["ports"]:
            self.safe_ui_update("port_status", port, ("Stopped", "gray"))

    def handle_get_ai_port_info(self, port):
        config = self.ui.get_config()
        threading.Thread(target=self._fetch_port_intelligence, args=(config["api_url"], port), daemon=True).start()

    def _fetch_port_intelligence(self, api_url, port):
        ai_response = self.core.get_port_intelligence(api_url, port)
        self.safe_ui_update("ai_info", ai_response)

    # ==========================================
    # WEB DEFENSE CONTROLLER (Honeyclient)
    # ==========================================
    def handle_analyze_target(self, target):
        config = self.ui.get_config()
        # Dynamically assign the API URL from the UI to the scanner
        self.web_scanner.ai_bridge_url = config["api_url"]
        
        # Initiate scan in the background to keep the UI responsive
        threading.Thread(target=self._run_web_defense_scanner, args=(target,), daemon=True).start()

    def _run_web_defense_scanner(self, target):
        # 1. Fetch Source Code: Determine if target is a local file or a URL
        if os.path.exists(target):
            html_code, error = self.web_scanner.fetch_from_file(target)
        else:
            html_code, error = self.web_scanner.fetch_from_url(target)
        
        if error:
            # Report out-of-scope violations or read errors directly to the UI
            error_msg = f"[!] PROCESS ABORTED:\n{error}"
            self.ui.after(0, lambda: self.ui.update_web_defense_ui("", error_msg))
            return

        # 2. Generate Static Analysis Report
        static_results = self.web_scanner.static_analysis(html_code)
        report_lines = ["=== STATIC ANALYSIS (HEURISTICS) ==="]
        
        if static_results:
            for finding in static_results:
                report_lines.append(f"[!] DETECTED: {finding['risk']} ({finding['count']} matches)")
                report_lines.append(f"    Samples: {', '.join(finding['samples'])}")
        else:
            report_lines.append("[+] No known malicious patterns detected by heuristics.")

        report_lines.append("\n=== AI BEHAVIORAL ANALYSIS ===")
        report_lines.append("[~] Awaiting threat intelligence engine response...")
        
        # Push the intermediate report to the UI to indicate ongoing processing
        temp_report = "\n".join(report_lines)
        self.ui.after(0, lambda: self.ui.update_web_defense_ui(html_code, temp_report))

        # 3. Retrieve AI Analysis and finalize the report
        ai_report = self.web_scanner.ai_analysis(html_code)
        report_lines[-1] = ai_report 

        final_report = "\n".join(report_lines)
        
        # Push the finalized results to the UI
        self.ui.after(0, lambda: self.ui.update_web_defense_ui(html_code, final_report))

    def run(self):
        self.ui.mainloop()

if __name__ == "__main__":
    app = HoneypotController()
    app.run()