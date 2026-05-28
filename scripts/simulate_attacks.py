#!/usr/bin/env python3
"""
Attack Simulator — run this to demo security features to the panel!
Shows: rate limiting, brute force detection, path scanning detection, SQL injection blocking
"""

import requests
import time

BASE = "http://localhost"

def separator(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print('='*50)

def test(label, method, path, **kwargs):
    url = f"{BASE}{path}"
    try:
        r = getattr(requests, method)(url, timeout=3, **kwargs)
        status = r.status_code
        icon = "✅" if status == 200 else "🚫" if status in [403, 429, 400] else "⚠️"
        print(f"  {icon}  {method.upper()} {path} → HTTP {status}")
        return r
    except Exception as e:
        print(f"  ❌  {method.upper()} {path} → ERROR: {e}")

# ── 1. Normal traffic ─────────────────────────────────────
"""separator("1. Normal Traffic (should all be 200)")
test("normal homepage",        "get",  "/")
test("health check",           "get",  "/health")
test("api info",               "get",  "/api/info")
test("security report",        "get",  "/security/report")"""

# ── 2. Hacker path scanning ───────────────────────────────
separator("2. Hacker Path Scanning (should be blocked 404)")
test("WordPress admin scan",   "get",  "/wp-admin")
test("phpMyAdmin scan",        "get",  "/phpmyadmin")
test("env file grab",          "get",  "/.env")
test("config scan",            "get",  "/config")

# ── 3. SQL Injection ──────────────────────────────────────
separator("3. SQL Injection Attempts (should be 400)")
test("classic SQLi",           "get",  "/api/data?id=1' OR '1'='1")
test("union select SQLi",      "get",  "/api/data?q=union select * from users")
test("drop table SQLi",        "get",  "/api/data?id=1; drop table users--")

# ── 4. Brute force login ──────────────────────────────────
separator("4. Brute Force Login Attack (should block after 5 attempts)")
for i in range(1, 8):
    r = test(f"login attempt #{i}", "post", "/login",
             data={"username": "admin", "password": f"wrongpass{i}"})
    time.sleep(0.3)

# ── 5. Check security report ──────────────────────────────
separator("5. Security Report — What Was Detected?")
r = requests.get(f"{BASE}/security/report")
print(f"  HTTP Status: {r.status_code}")

if r.status_code == 403:
    print("\n  🔒 Your IP was blocked during the brute force test!")
    print("  This means the security system is working perfectly.")
    print("  To view the report, restart docker: docker compose restart")
elif r.status_code == 200 and r.text.strip():
    data = r.json()
    print(f"\n  Blocked IPs:     {data['summary']['total_blocked']}")
    print(f"  Total Attacks:   {data['summary']['total_attacks']}")
    print(f"\n  Recent attacks:")
    for attack in data.get('recent_attacks', [])[-5:]:
        print(f"    🚨 {attack.get('type','unknown')} from {attack.get('ip','?')} at {attack.get('time','?')}")
else:
    print(f"  Response: {r.text[:200] or '(empty)'}")

print(f"\n{'='*50}")
print("  ✅ Demo complete! Check Grafana at http://localhost:3000")
print("     to see all attacks visualised on the dashboard!")
print('='*50)