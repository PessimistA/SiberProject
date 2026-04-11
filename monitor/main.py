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
 
    # ── LIVE EVENTS ──────────────────────────────────────────────
 
    def handle_new_log(self, sender, text, role):
        self.ui.after(0, self.ui.add_interaction_card, sender, text, role)
 
    def handle_new_session(self, attacker_ip, target, risk):
        self.ui.after(0, self.ui.add_active_session, attacker_ip, target, risk)
 
    def handle_profile_update(self, ip, profile, risk_score):
        self.ui.after(0, self.ui.update_attacker_profile, ip, profile, risk_score)
 
    # ── HISTORY ──────────────────────────────────────────────────
 
    def handle_load_dates(self):
        dates = self.core.get_available_dates()
        self.ui.after(0, self.ui.populate_dates, dates)
 
    def handle_load_ips(self, date):
        return self.core.get_available_ips(date if date not in ["No logs found", "Loading..."] else None)
 
    def handle_load_history(self, date, ip=None):
        """Runs in background thread so UI doesn't freeze."""
        threading.Thread(target=self._fetch_history, args=(date, ip), daemon=True).start()
 
    def _fetch_history(self, date, ip):
        entries = self.core.load_historical_logs(
            filter_ip=ip,
            filter_date=date if date not in ["No logs found", "Loading..."] else None
        )
        self.ui.after(0, self.ui.populate_history, entries)
 
    # ── STATS ────────────────────────────────────────────────────
 
    def handle_load_stats(self):
        threading.Thread(target=self._fetch_stats, daemon=True).start()
 
    def _fetch_stats(self):
        stats = self.core.get_session_stats()
        attacker_db = self.core.get_attacker_summary()
        self.ui.after(0, self.ui.populate_stats, stats, attacker_db)
 
    # ── STARTUP ──────────────────────────────────────────────────
 
    def run(self):
        self.core.start_listening()
 
        # Pre-load dates on startup
        threading.Thread(target=self._startup_load, daemon=True).start()
 
        self.ui.mainloop()
 
    def _startup_load(self):
        import time
        time.sleep(0.5)
        self.handle_load_dates()
        self.handle_load_stats()
 
 
if __name__ == "__main__":
    app = MonitorController()
    app.run()
