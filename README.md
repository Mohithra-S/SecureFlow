# 🛡️ DevSecOps Pipeline — Security-First CI/CD

A production-grade **DevSecOps** project that integrates security at every stage of the pipeline. Built to demonstrate real-world security automation for DevOps internship interviews.

## What This Project Does

```
Code Push
   ↓
Bandit (code scan) + Safety (dependency CVE scan)
   ↓
pytest (includes security tests)
   ↓
Docker Build
   ↓
Trivy (Docker image CVE scan)
   ↓
Push to Docker Hub
   ↓
Deploy to Cloud VM
   ↓
Nginx (rate limiting + attack blocking)
   ↓
Flask App (brute force detection, SQL injection detection, security headers)
   ↓
Prometheus (scrapes security metrics)
   ↓
Grafana (live security dashboard with alerts)
```

## Security Features

| Layer | Tool/Feature | What it protects against |
|---|---|---|
| Code | Bandit | Insecure code patterns |
| Dependencies | Safety | Known CVEs in packages |
| Docker Image | Trivy | OS + library vulnerabilities |
| Network | Nginx rate limiting | DDoS, brute force |
| Network | Nginx bot blocking | Scanners (Nikto, SQLMap) |
| App | Brute force detection | Password attacks |
| App | SQL injection detection | Database attacks |
| App | Path scanning detection | Reconnaissance attacks |
| App | Security headers | XSS, clickjacking |
| Monitoring | Prometheus alerts | Real-time threat detection |
| Monitoring | Grafana dashboard | Visual security monitoring |

---

## 🚀 Run Locally

```bash
# Clone and start
git clone https://github.com/YOUR_USERNAME/devsecops-project.git
cd devsecops-project
docker compose up --build

# Open in browser
http://localhost        # Main app
http://localhost:3000   # Grafana security dashboard (admin/admin123)
http://localhost:9090   # Prometheus
```

## 🎯 Demo the Security Features

Run the attack simulator to show the panel live attack detection:

```bash
pip install requests
python scripts/simulate_attacks.py
```

This will:
1. Send normal traffic (200 OK)
2. Try path scanning — `/wp-admin`, `/.env` (blocked!)
3. Try SQL injection (blocked!)
4. Simulate brute force login (blocked after 5 attempts!)
5. Show the security report with all detected attacks

Then open Grafana to see everything visualised on the dashboard!

---

## CI/CD Pipeline Stages

The GitHub Actions pipeline has **7 security-gated stages:**

1. **Code Security Scan** — Bandit scans Python code for vulnerabilities
2. **Dependency Scan** — Safety checks packages against CVE database
3. **Tests** — pytest runs including 15 security-specific tests
4. **Build** — Docker image built with non-root user
5. **Image CVE Scan** — Trivy scans Docker image for critical CVEs
6. **Push** — Only reaches Docker Hub if all scans pass
7. **Deploy** — SSH deploy to cloud VM with health check

---

## Security Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard with live security stats |
| `GET /health` | Health check |
| `GET /security/report` | Full JSON security report with attack log |
| `POST /login` | Brute-force protected login |
| `GET /metrics` | Prometheus security metrics |

---

## What This Demonstrates for Interview

- **DevSecOps mindset** — security at every pipeline stage, not bolted on at the end
- **SAST** — Static Application Security Testing with Bandit
- **SCA** — Software Composition Analysis with Safety
- **Container security** — Trivy image scanning, non-root Docker user
- **Network security** — Nginx rate limiting, bot blocking, security headers
- **Runtime security** — Real-time attack detection and IP blocking
- **Security observability** — Prometheus metrics + Grafana alerts for threats
- **Incident response** — Security report endpoint shows all detected attacks
