"""
AntiGravity Shield v2.0 -- Live Monitoring Dashboard
=====================================================
Runs the shield + a web-based live dashboard so you can
watch alerts streaming in real-time from your browser.

Usage: python shield_dashboard.py
Then open: http://<VM_IP>:8877
"""
import sys
import os
import time
import json
import threading
import http.server
import html

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "antigravity-shield", "src"))

from agshield.detection.engine import DetectionEngine
from agshield.config import Config

WATCH_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "evidence_workspace")
DASHBOARD_PORT = 8877

# Global state
shield_alerts = []
shield_status = {"running": False, "backend": "unknown", "start_time": 0}
shield_lock = threading.Lock()


def alert_callback_wrapper(original_callback):
    """Wrap the engine's alert callback to also feed the dashboard."""
    def wrapper(alert):
        with shield_lock:
            shield_alerts.append(alert)
        original_callback(alert)
    return wrapper


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AntiGravity Shield v2.0 -- Live Monitor</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0a0e17;
    color: #e0e0e0;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
  }
  .header {
    background: linear-gradient(135deg, #1a1f36 0%%, #0d1117 100%%);
    border-bottom: 2px solid #00ff88;
    padding: 15px 25px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .header h1 {
    color: #00ff88;
    font-size: 20px;
    letter-spacing: 2px;
  }
  .header .status {
    display: flex;
    gap: 20px;
    align-items: center;
  }
  .header .status .dot {
    width: 10px; height: 10px;
    border-radius: 50%%;
    display: inline-block;
    animation: pulse 1.5s infinite;
  }
  .dot.active { background: #00ff88; box-shadow: 0 0 8px #00ff88; }
  .dot.inactive { background: #ff4444; }
  @keyframes pulse {
    0%%, 100%% { opacity: 1; }
    50%% { opacity: 0.4; }
  }
  .stats-bar {
    background: #111827;
    padding: 12px 25px;
    display: flex;
    gap: 30px;
    border-bottom: 1px solid #1e293b;
  }
  .stat {
    text-align: center;
  }
  .stat .value {
    font-size: 28px;
    font-weight: bold;
  }
  .stat .label { color: #6b7280; font-size: 11px; text-transform: uppercase; }
  .stat.critical .value { color: #ff4444; }
  .stat.warning .value { color: #ffaa00; }
  .stat.info .value { color: #3b82f6; }
  .stat.total .value { color: #00ff88; }
  .alerts-container {
    padding: 10px 15px;
    height: calc(100vh - 150px);
    overflow-y: auto;
    display: flex;
    flex-direction: column-reverse;
  }
  .alert-row {
    padding: 4px 10px;
    border-left: 3px solid transparent;
    margin: 1px 0;
    display: flex;
    gap: 10px;
    align-items: baseline;
    animation: fadeIn 0.3s ease-in;
    border-radius: 2px;
  }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateX(-10px); }
    to { opacity: 1; transform: translateX(0); }
  }
  .alert-row.CRITICAL {
    border-left-color: #ff4444;
    background: rgba(255, 68, 68, 0.08);
  }
  .alert-row.WARNING {
    border-left-color: #ffaa00;
    background: rgba(255, 170, 0, 0.05);
  }
  .alert-row.INFO {
    border-left-color: #3b82f6;
    background: rgba(59, 130, 246, 0.05);
  }
  .alert-time { color: #6b7280; min-width: 90px; }
  .alert-severity { min-width: 70px; font-weight: bold; }
  .alert-severity.CRITICAL { color: #ff4444; }
  .alert-severity.WARNING { color: #ffaa00; }
  .alert-severity.INFO { color: #3b82f6; }
  .alert-event { color: #e2e8f0; min-width: 180px; }
  .alert-path { color: #94a3b8; }
  .alert-reason { color: #9ca3af; font-size: 12px; margin-left: 100px; }
  .alert-pid { color: #8b5cf6; min-width: 70px; }
  .footer {
    position: fixed; bottom: 0; left: 0; right: 0;
    background: #111827; padding: 8px 25px;
    border-top: 1px solid #1e293b;
    font-size: 11px; color: #6b7280;
    display: flex; justify-content: space-between;
  }
</style>
</head>
<body>
<div class="header">
  <h1>[SHIELD] ANTIGRAVITY SHIELD v2.0</h1>
  <div class="status">
    <span>Backend: <strong id="backend">--</strong></span>
    <span>Uptime: <strong id="uptime">0s</strong></span>
    <span><span class="dot active" id="statusDot"></span> MONITORING</span>
  </div>
</div>
<div class="stats-bar">
  <div class="stat total"><div class="value" id="totalCount">0</div><div class="label">Total Alerts</div></div>
  <div class="stat critical"><div class="value" id="criticalCount">0</div><div class="label">Critical</div></div>
  <div class="stat warning"><div class="value" id="warningCount">0</div><div class="label">Warning</div></div>
  <div class="stat info"><div class="value" id="infoCount">0</div><div class="label">Info</div></div>
</div>
<div class="alerts-container" id="alertsContainer">
  <div id="alerts"></div>
</div>
<div class="footer">
  <span>AntiGravity Shield v2.0 -- Kernel-Level Defense Framework</span>
  <span>Watching: <strong>%s</strong></span>
</div>
<script>
let lastCount = 0;
function fetchAlerts() {
  fetch('/api/alerts?since=' + lastCount)
    .then(r => r.json())
    .then(data => {
      document.getElementById('backend').textContent = data.backend;
      document.getElementById('totalCount').textContent = data.total;
      document.getElementById('criticalCount').textContent = data.critical;
      document.getElementById('warningCount').textContent = data.warning;
      document.getElementById('infoCount').textContent = data.info;
      if (data.uptime) document.getElementById('uptime').textContent = data.uptime + 's';
      const container = document.getElementById('alerts');
      data.new_alerts.forEach(a => {
        const row = document.createElement('div');
        row.className = 'alert-row ' + a.severity;
        row.innerHTML =
          '<span class="alert-time">' + a.time + '</span>' +
          '<span class="alert-severity ' + a.severity + '">' + a.severity + '</span>' +
          '<span class="alert-event">' + a.event_type + '</span>' +
          '<span class="alert-pid">PID:' + (a.pid || '-') + '</span>' +
          '<span class="alert-path">' + a.path + '</span>';
        container.appendChild(row);
        if (a.reason) {
          const rrow = document.createElement('div');
          rrow.className = 'alert-reason';
          rrow.textContent = a.reason;
          container.appendChild(rrow);
        }
      });
      lastCount = data.total;
      // Auto-scroll to bottom
      const c = document.getElementById('alertsContainer');
      c.scrollTop = c.scrollHeight;
    })
    .catch(() => {});
}
setInterval(fetchAlerts, 500);
fetchAlerts();
</script>
</body>
</html>""" % WATCH_DIR.replace("\\", "\\\\")


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for the live dashboard."""

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))

        elif self.path.startswith("/api/alerts"):
            since = 0
            if "since=" in self.path:
                try:
                    since = int(self.path.split("since=")[1])
                except ValueError:
                    since = 0

            with shield_lock:
                alerts_copy = list(shield_alerts)
                status_copy = dict(shield_status)

            new_alerts = alerts_copy[since:]
            critical = sum(1 for a in alerts_copy if a.get("severity") == "CRITICAL")
            warning = sum(1 for a in alerts_copy if a.get("severity") == "WARNING")
            info_count = sum(1 for a in alerts_copy if a.get("severity") == "INFO")
            uptime = int(time.time() - status_copy.get("start_time", time.time()))

            formatted = []
            for a in new_alerts:
                ts = a.get("detection_wall_time", time.time())
                from datetime import datetime
                time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
                path = a.get("path", "")
                if os.sep in path:
                    path = os.path.basename(path)
                formatted.append({
                    "time": time_str,
                    "severity": a.get("severity", "INFO"),
                    "event_type": a.get("event_type", "UNKNOWN"),
                    "path": html.escape(path),
                    "pid": a.get("pid", a.get("details", {}).get("pid", "")),
                    "reason": html.escape(
                        a.get("details", {}).get("reason", "")[:120]
                    ),
                })

            response = {
                "total": len(alerts_copy),
                "critical": critical,
                "warning": warning,
                "info": info_count,
                "backend": status_copy.get("backend", "unknown"),
                "uptime": uptime,
                "new_alerts": formatted,
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress HTTP logs


def run_dashboard(port):
    """Run the web dashboard server."""
    server = http.server.HTTPServer(("0.0.0.0", port), DashboardHandler)
    print(f"  [DASHBOARD] Live dashboard: http://0.0.0.0:{port}")
    server.serve_forever()


def main():
    print("=" * 60)
    print("  AntiGravity Shield v2.0 -- Live Monitor")
    print("=" * 60)

    os.makedirs(WATCH_DIR, exist_ok=True)
    reports_dir = os.path.join(WATCH_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    # Ensure evidence files exist
    for name, content in [
        ("financial_report.txt", "CONFIDENTIAL: Q2 Financial Data"),
        ("employee_data.csv", "name,role,salary\nJohn,CEO,250000"),
        ("access_log.txt", "2026-07-16 10:00:00 LOGIN admin from 10.0.0.1"),
        ("audit_trail.log", "AUDIT: System initialized"),
    ]:
        fpath = os.path.join(WATCH_DIR, name)
        if not os.path.exists(fpath):
            with open(fpath, "w") as f:
                f.write(content)

    # Configure shield
    config = Config()
    config._config.setdefault("general", {})
    config._config["general"]["watch_paths"] = [WATCH_DIR]
    config._config["general"]["reports_dir"] = reports_dir
    config._config["general"]["database_path"] = os.path.join(WATCH_DIR, "baseline.db")
    config._config["general"]["log_file"] = os.path.join(WATCH_DIR, "shield.log")

    # Create engine with dashboard-aware callback
    engine = DetectionEngine(config)

    # Monkey-patch the alert callback to also feed the dashboard
    original_on_alert = engine._on_alert
    def dashboard_alert(alert):
        original_on_alert(alert)
        with shield_lock:
            shield_alerts.append(alert)
    engine._on_alert = dashboard_alert

    # Start web dashboard in background
    dash_thread = threading.Thread(target=run_dashboard, args=(DASHBOARD_PORT,), daemon=True)
    dash_thread.start()

    # Start shield
    engine.start(deploy_canaries=True, canary_count=2)

    with shield_lock:
        shield_status["running"] = True
        shield_status["backend"] = engine._monitor_backend
        shield_status["start_time"] = engine.start_time

    print(f"\n  Dashboard URL: http://0.0.0.0:{DASHBOARD_PORT}")
    print(f"  Watching: {WATCH_DIR}")
    print(f"  Press Ctrl+C to stop\n")

    # Keep running until interrupted
    engine.wait()


if __name__ == "__main__":
    main()
