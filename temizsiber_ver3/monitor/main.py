import threading
from ui import MonitorUI
from core import MonitorCore
 
 
class MonitorController:
    def __init__(self):
        self.ui = MonitorUI(
            on_load_history=self.handle_load_history,
            on_load_dates=self.handle_load_dates,
            on_load_ips=self.handle_load_ips,
            on_load_stats=self.handle_load_stats,
        )
        self.core = MonitorCore(
            on_new_log=self.handle_new_log,
            on_new_session=self.handle_new_session,
            on_profile_update=self.handle_profile_update,
        )
 
    # Sends a new text log to the UI screen.
    def handle_new_log(self, sender, text, role):
        self.ui.after(0, self.ui.add_interaction_card, sender, text, role)
    # Tells the UI to show a new active connection.
    def handle_new_session(self, attacker_ip, target, risk):
        self.ui.after(0, self.ui.add_active_session, attacker_ip, target, risk)
    # Updates the attacker's threat level on the screen.
    def handle_profile_update(self, ip, profile, risk_score):
        self.ui.after(0, self.ui.update_attacker_profile, ip, profile, risk_score)
 
    # Gets the available dates from Core and sends them to the UI.
    def handle_load_dates(self):
        dates = self.core.get_available_dates()
        self.ui.after(0, self.ui.populate_dates, dates)
    # Gets the available IPs for a specific date from Core.
    def handle_load_ips(self, date):
        return self.core.get_available_ips(date if date not in ["No logs found", "Loading..."] else None)
    # Starts a background task to load old logs.
    def handle_load_history(self, date, ip=None):
        threading.Thread(target=self._fetch_history, args=(date, ip), daemon=True).start()
    # Gets the old logs from Core and puts them on the screen.
    def _fetch_history(self, date, ip):
        entries = self.core.load_historical_logs(
            filter_ip=ip,
            filter_date=date if date not in ["No logs found", "Loading..."] else None
        )
        self.ui.after(0, self.ui.populate_history, entries)
 
    # Starts a background task to calculate and show statistics. 
    def handle_load_stats(self):
        threading.Thread(target=self._fetch_stats, daemon=True).start()
    # Gets the calculated stats from Core and sends them to the UI.
    def _fetch_stats(self):
        stats = self.core.get_session_stats()
        attacker_db = self.core.get_attacker_summary()
        self.ui.after(0, self.ui.populate_stats, stats, attacker_db)
 
    # Starts the network listener and opens the main application window.
    def run(self):
        self.core.start_listening()
 
        threading.Thread(target=self._startup_load, daemon=True).start()
 
        self.ui.mainloop()
    # Waits half a second, then loads initial data when the app opens.
    def _startup_load(self):
        import time
        time.sleep(0.5)
        self.handle_load_dates()
        self.handle_load_stats()
 
 
if __name__ == "__main__":
    app = MonitorController()
    app.run()
