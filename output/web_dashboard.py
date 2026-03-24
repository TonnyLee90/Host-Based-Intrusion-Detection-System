"""
Flask web dashboard.

Provides a HTML page that auto-refreshes every 15 seconds,
plus a /api/alerts JSON endpoint for programmatic access.
"""

import threading

from IDS.config        import FLASK_PORT
from IDS.alert_manager import get_db_connection
from flask import Flask, render_template_string, jsonify

# HTML template
_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="15">
  <title>HIDS Dashboard</title>
  <style>
    body  { font-family: Arial, sans-serif; background: #0f1117;
            color: #e0e0e0; margin: 0; padding: 20px; }
    h1    { color: #5b9bd5; margin-bottom: 4px; }
    p     { color: #888; margin-top: 0; font-size: 13px; }
    table { border-collapse: collapse; width: 100%; margin-top: 16px; }
    th    { background: #1e2a38; color: #8ab4f8;
            padding: 10px; text-align: left; font-size: 13px; }
    td    { padding: 8px 10px; border-bottom: 1px solid #2a2a2a;
            font-size: 13px; }
    tr:hover { background: #1a2236; }
    /* Severity badge styles */
    .badge          { display: inline-block; padding: 2px 8px;
                      border-radius: 4px; font-size: 11px; font-weight: bold; }
    .badge.CRITICAL { background: #3a0a0a; color: #ff5555; }
    .badge.HIGH     { background: #3a2000; color: #ffb86c; }
    .badge.MEDIUM   { background: #3a3000; color: #f1fa8c; }
    .badge.LOW      { background: #003a3a; color: #8be9fd; }
  </style>
</head>
<body>
  <h1>HIDS — Live Alert Dashboard</h1>
  <p>
    Auto-refreshes every 15 s &bull;
    Showing last 200 alerts &bull;
    Total: <strong style="color:#5b9bd5">{{ total }}</strong>
  </p>
  <table>
    <tr>
      <th>Time</th>
      <th>Severity</th>
      <th>Category</th>
      <th>Message</th>
    </tr>
    {% for row in alerts %}
    <tr>
      <td style="color:#888; white-space:nowrap">{{ row.ts }}</td>
      <td>
        <span class="badge {{ row.severity }}">{{ row.severity }}</span>
      </td>
      <td style="color:#ccc">{{ row.category }}</td>
      <td>{{ row.message }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""


def _create_app() -> "Flask":
    """
    Routes:
        GET /            — HTML dashboard 
        GET /api/alerts  
    """
    app = Flask(__name__)

    @app.route("/")
    def dashboard():
        conn, lock = get_db_connection()
        with lock:
            rows = conn.execute(
                "SELECT ts, severity, category, message "
                "FROM alerts ORDER BY id DESC LIMIT 200"
            ).fetchall()

        alerts = [
            {"ts": r[0], "severity": r[1], "category": r[2], "message": r[3]}
            for r in rows
        ]
        return render_template_string(
            _DASHBOARD_HTML, alerts=alerts, total=len(alerts)
        )

    @app.route("/api/alerts")
    def api_alerts():
        conn, lock = get_db_connection()
        with lock:
            rows = conn.execute(
                "SELECT id, ts, severity, category, message "
                "FROM alerts ORDER BY id DESC LIMIT 200"
            ).fetchall()

        return jsonify([
            {"id": r[0], "ts": r[1], "severity": r[2],
             "category": r[3], "message": r[4]}
            for r in rows
        ])

    return app

def start_web_dashboard() -> None:
    """
    Launch the Flask dashboard in a background daemon thread.
    """
    app = _create_app()

    thread = threading.Thread(
        target=lambda: app.run(
            host="0.0.0.0",      # Accept connections from all interfaces
            port=FLASK_PORT,
            debug=False,         
            use_reloader=False,
        ),
        daemon=True,
    )
    thread.start()
    print(f"  [WEB] Dashboard running → http://localhost:{FLASK_PORT}")
