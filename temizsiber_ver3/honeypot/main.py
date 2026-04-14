import os
import threading
from ui import HoneypotUI
from core import HoneypotCore
from web_scanner import SecurityWebScanner

class HoneypotController:
    def __init__(self):
        self.ui = HoneypotUI(
            start_callback=self.handle_start_server,
            stop_callback=self.handle_stop_server, 
            port_info_callback=self.handle_get_ai_port_info,
            analyze_url_callback=self.handle_analyze_target
        )
        self.core = HoneypotCore(ui_update_callback=self.safe_ui_update)

        self.web_scanner = SecurityWebScanner(ai_bridge_url="http://shadow_ai_koprusu:5000")
    #Update the screen safely when data comes from a background process
    def safe_ui_update(self, component, key, data=None):
        if component == "port_status":
            status, color = data
            self.ui.after(0, lambda: self.ui.update_port_status(key, status, color))
        elif component == "ai_info":
            self.ui.after(0, lambda: self.ui.show_ai_port_info(key))
    # Read the selected ports from the screen and start listening them
    def handle_start_server(self):
        config = self.ui.get_config()
        ports_to_listen = config["ports"]
        
        if not ports_to_listen:
            return 

        self.ui.btn_start.configure(state="disabled", text="Listening...") 
        self.ui.btn_stop.configure(state="normal") 
        
        self.core.start_all_services(config["api_url"], config["sys_prompt"], ports_to_listen)
    # Stop all active port connections and reset the buttons
    def handle_stop_server(self):
        self.core.stop_all_services()

        self.ui.btn_stop.configure(state="disabled")
        self.ui.btn_start.configure(state="normal", text="Listen on Selected Ports")

        config = self.ui.get_config()
        for port in config["ports"]:
            self.safe_ui_update("port_status", port, ("Stopped", "gray"))
    #Ask ai to get info about spesific port
    def handle_get_ai_port_info(self, port):
        config = self.ui.get_config()
        threading.Thread(target=self._fetch_port_intelligence, args=(config["api_url"], port), daemon=True).start()
    #Get ai response for a port and show it on the screen
    def _fetch_port_intelligence(self, api_url, port):
        ai_response = self.core.get_port_intelligence(api_url, port)
        self.safe_ui_update("ai_info", ai_response)
    # Start checking a web address or file in the background
    def handle_analyze_target(self, target):
        config = self.ui.get_config()
        self.web_scanner.ai_bridge_url = config["api_url"]
        threading.Thread(target=self._run_web_defense_scanner, args=(target,), daemon=True).start()
    #This one analyzing the web files to check simple threats
    def _run_web_defense_scanner(self, target):
        if os.path.exists(target):
            html_code, error = self.web_scanner.fetch_from_file(target)
        else:
            html_code, error = self.web_scanner.fetch_from_url(target)
        
        if error:
            error_msg = f"[!] PROCESS ABORTED:\n{error}"
            self.ui.after(0, lambda: self.ui.update_web_defense_ui("", error_msg))
            return

        static_results = self.web_scanner.static_analysis(html_code)
        report_lines = [" STATIC ANALYSIS"]
        
        if static_results:
            for finding in static_results:
                report_lines.append(f"[!] DETECTED: {finding['risk']} ({finding['count']} matches)")
                report_lines.append(f"    Samples: {', '.join(finding['samples'])}")
        else:
            report_lines.append("[+] No known malicious patterns detected by heuristics.")

        report_lines.append("\n AI BEHAVIORAL ANALYSIS")
        report_lines.append("[~] Awaiting threat intelligence engine response...")
     
        temp_report = "\n".join(report_lines)
        self.ui.after(0, lambda: self.ui.update_web_defense_ui(html_code, temp_report))

        ai_report = self.web_scanner.ai_analysis(html_code)
        report_lines[-1] = ai_report 

        final_report = "\n".join(report_lines)
        
        self.ui.after(0, lambda: self.ui.update_web_defense_ui(html_code, final_report))

    def run(self):
        self.ui.mainloop()

if __name__ == "__main__":
    app = HoneypotController()
    app.run()