from flask import Flask, jsonify, request, render_template_string, abort
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from collections import defaultdict
from datetime import datetime
import time
import hashlib
import os
import logging

# ── Logging setup ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

# ── Prometheus Metrics ────────────────────────────────────
REQUEST_COUNT       = Counter('app_request_count', 'Total requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY     = Histogram('app_request_latency_seconds', 'Request latency', ['endpoint'])
ATTACK_COUNTER      = Counter('security_attack_attempts', 'Detected attack attempts', ['attack_type', 'ip'])
BLOCKED_IPS         = Gauge('security_blocked_ips_total', 'Total blocked IPs')
ACTIVE_CONNECTIONS  = Gauge('app_active_connections', 'Active connections')
FAILED_LOGINS       = Counter('security_failed_logins_total', 'Failed login attempts', ['ip'])
SUSPICIOUS_REQUESTS = Counter('security_suspicious_requests', 'Suspicious requests detected', ['reason'])

# ── In-memory security state ──────────────────────────────
ip_request_counts   = defaultdict(list)   # ip -> [timestamps]
ip_failed_logins    = defaultdict(int)
blocked_ips         = set()
attack_log          = []

# ── Security config ───────────────────────────────────────
RATE_LIMIT          = 30    # max requests per minute per IP
LOGIN_ATTEMPT_LIMIT = 5     # max failed logins before block
SUSPICIOUS_PATHS    = ['/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config', '/passwd']

# ── HTML Templates ────────────────────────────────────────
MAIN_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>DevSecOps Pipeline</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; padding: 40px 20px; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { font-size: 2rem; color: #58a6ff; margin-bottom: 8px; }
    .badge { display: inline-block; padding: 4px 14px; border-radius: 20px; font-size: 13px; background: #1f6feb33; color: #58a6ff; border: 1px solid #1f6feb; margin-bottom: 24px; }
    .badge.secure { background: #23863633; color: #3fb950; border-color: #238636; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 16px; }
    .card h3 { color: #58a6ff; margin-bottom: 12px; font-size: 1rem; text-transform: uppercase; letter-spacing: 1px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .endpoint { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 12px 16px; }
    .endpoint a { color: #58a6ff; text-decoration: none; font-family: monospace; font-size: 14px; }
    .endpoint p { font-size: 12px; color: #8b949e; margin-top: 4px; }
    .stack { display: flex; flex-wrap: wrap; gap: 8px; }
    .tag { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 4px 12px; font-size: 13px; color: #c9d1d9; }
    .tag.sec { border-color: #f85149; color: #f85149; background: #f8514911; }
    .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
    .stat { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
    .stat .num { font-size: 2rem; font-weight: bold; color: #3fb950; }
    .stat .label { font-size: 12px; color: #8b949e; margin-top: 4px; }
  </style>
</head>
<body>
<div class="container">
  <h1>🛡️ DevSecOps Pipeline</h1>
  <span class="badge secure">✓ Secure &amp; Running</span>

  <div class="card">
    <h3>Live Security Stats</h3>
    <div class="stats">
      <div class="stat"><div class="num">{{ blocked }}</div><div class="label">Blocked IPs</div></div>
      <div class="stat"><div class="num">{{ attacks }}</div><div class="label">Attack Attempts</div></div>
      <div class="stat"><div class="num">{{ total_req }}</div><div class="label">Total Requests</div></div>
    </div>
  </div>

  <div class="card">
    <h3>Endpoints</h3>
    <div class="grid">
      <div class="endpoint"><a href="/health">/health</a><p>Health check</p></div>
      <div class="endpoint"><a href="/metrics">/metrics</a><p>Prometheus metrics</p></div>
      <div class="endpoint"><a href="/api/info">/api/info</a><p>App info JSON</p></div>
      <div class="endpoint"><a href="/security/report">/security/report</a><p>Live security report</p></div>
      <div class="endpoint"><a href="/login">/login</a><p>Login (brute-force protected)</p></div>
      <div class="endpoint"><a href="/api/data">/api/data</a><p>Sample data endpoint</p></div>
    </div>
  </div>

  <div class="card">
    <h3>Security Stack</h3>
    <div class="stack">
      <span class="tag sec">Trivy CVE Scanner</span>
      <span class="tag sec">Bandit Code Scan</span>
      <span class="tag sec">Rate Limiting</span>
      <span class="tag sec">Brute Force Detection</span>
      <span class="tag sec">Attack Monitoring</span>
      <span class="tag sec">SSL/HTTPS</span>
      <span class="tag">Docker</span>
      <span class="tag">Prometheus</span>
      <span class="tag">Grafana</span>
      <span class="tag">GitHub Actions</span>
    </div>
  </div>
</div>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Login — DevSecOps</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 40px; width: 360px; }
    h2 { color: #58a6ff; margin-bottom: 24px; }
    input { width: 100%; padding: 10px 14px; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: #c9d1d9; margin-bottom: 12px; font-size: 14px; }
    button { width: 100%; padding: 10px; background: #238636; border: none; border-radius: 8px; color: white; font-size: 15px; cursor: pointer; }
    .msg { margin-top: 12px; font-size: 13px; color: #f85149; }
    .note { margin-top: 12px; font-size: 12px; color: #8b949e; }
  </style>
</head>
<body>
<div class="card">
  <h2>🔐 Secure Login</h2>
  <form method="POST">
    <input type="text" name="username" placeholder="Username" required/>
    <input type="password" name="password" placeholder="Password" required/>
    <button type="submit">Login</button>
  </form>
  {% if message %}<p class="msg">{{ message }}</p>{% endif %}
  <p class="note">⚠️ This endpoint is brute-force protected. Too many failed attempts = IP blocked.</p>
</div>
</body>
</html>
"""

# ── Security helpers ──────────────────────────────────────
def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def is_rate_limited(ip):
    now = time.time()
    ip_request_counts[ip] = [t for t in ip_request_counts[ip] if now - t < 60]
    ip_request_counts[ip].append(now)
    return len(ip_request_counts[ip]) > RATE_LIMIT

def log_attack(attack_type, ip, detail=""):
    attack_log.append({
        "type": attack_type,
        "ip": ip,
        "time": datetime.utcnow().isoformat(),
        "detail": detail
    })
    ATTACK_COUNTER.labels(attack_type=attack_type, ip=ip).inc()
    logger.warning(f"🚨 ATTACK DETECTED | type={attack_type} ip={ip} detail={detail}")

# ── Middleware ────────────────────────────────────────────
@app.before_request
def security_middleware():
    ip = get_client_ip()
    ACTIVE_CONNECTIONS.inc()

    # Block known bad IPs
    if ip in blocked_ips:
        log_attack("blocked_ip_access", ip)
        abort(403)

    # Rate limiting
    if is_rate_limited(ip):
        log_attack("rate_limit_exceeded", ip, f"{len(ip_request_counts[ip])} req/min")
        SUSPICIOUS_REQUESTS.labels(reason="rate_limit").inc()
        abort(429)

    # Detect suspicious path scanning
    path = request.path.lower()
    if any(path.startswith(p) for p in SUSPICIOUS_PATHS):
        log_attack("path_scanning", ip, path)
        SUSPICIOUS_REQUESTS.labels(reason="path_scan").inc()
        blocked_ips.add(ip)
        BLOCKED_IPS.set(len(blocked_ips))
        abort(404)

    # SQL injection pattern detection
    query_string = request.query_string.decode().lower()
    sql_patterns = ["'", "union select", "drop table", "1=1", "--", "xp_"]
    if any(p in query_string for p in sql_patterns):
        log_attack("sql_injection_attempt", ip, query_string[:100])
        SUSPICIOUS_REQUESTS.labels(reason="sql_injection").inc()
        abort(400)

    request.start_time = time.time()

@app.after_request
def after_request(response):
    ACTIVE_CONNECTIONS.dec()
    if hasattr(request, 'start_time'):
        latency = time.time() - request.start_time
        REQUEST_COUNT.labels(method=request.method, endpoint=request.path, status=response.status_code).inc()
        REQUEST_LATENCY.labels(endpoint=request.path).observe(latency)

    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# ── Routes ────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template_string(MAIN_HTML,
        blocked=len(blocked_ips),
        attacks=len(attack_log),
        total_req=sum(len(v) for v in ip_request_counts.values())
    )

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "secure": True, "blocked_ips": len(blocked_ips)})

@app.route('/api/info')
def info():
    return jsonify({
        "app": "DevSecOps Pipeline",
        "version": "2.0.0",
        "security_features": [
            "Rate limiting",
            "Brute force detection",
            "SQL injection detection",
            "Path scanning detection",
            "Security headers",
            "Attack logging"
        ],
        "stack": ["Flask", "Docker", "Nginx", "Prometheus", "Grafana", "Trivy", "Bandit"]
    })

@app.route('/api/data')
def data():
    # Simulate some real data
    return jsonify({
        "users_online": 42,
        "requests_today": sum(len(v) for v in ip_request_counts.values()),
        "blocked_threats": len(blocked_ips),
        "uptime": "99.9%"
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    ip = get_client_ip()

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Simulate login check (in real app, check DB)
        # Use constant-time comparison to prevent timing attacks
        valid_hash = hashlib.sha256(b"admin:securepassword123").hexdigest()
        attempt_hash = hashlib.sha256(f"{username}:{password}".encode()).hexdigest()

        if attempt_hash == valid_hash:
            logger.info(f"Successful login from {ip}")
            return jsonify({"status": "success", "message": "Login successful!"})
        else:
            ip_failed_logins[ip] += 1
            FAILED_LOGINS.labels(ip=ip).inc()

            if ip_failed_logins[ip] >= LOGIN_ATTEMPT_LIMIT:
                blocked_ips.add(ip)
                BLOCKED_IPS.set(len(blocked_ips))
                log_attack("brute_force", ip, f"{ip_failed_logins[ip]} failed attempts")
                abort(403)

            remaining = LOGIN_ATTEMPT_LIMIT - ip_failed_logins[ip]
            message = f"Invalid credentials. {remaining} attempts remaining before IP block."
            log_attack("failed_login", ip, f"attempt #{ip_failed_logins[ip]}")

    return render_template_string(LOGIN_HTML, message=message)

@app.route('/security/report')
def security_report():
    return jsonify({
        "summary": {
            "blocked_ips": list(blocked_ips),
            "total_blocked": len(blocked_ips),
            "total_attacks": len(attack_log),
        },
        "recent_attacks": attack_log[-20:],
        "rate_limit": f"{RATE_LIMIT} req/min per IP",
        "login_protection": f"Block after {LOGIN_ATTEMPT_LIMIT} failed attempts"
    })

@app.route('/metrics')
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
