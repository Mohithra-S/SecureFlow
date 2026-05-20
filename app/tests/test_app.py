import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, blocked_ips, ip_failed_logins

@pytest.fixture
def client():
    app.config['TESTING'] = True
    blocked_ips.clear()
    ip_failed_logins.clear()
    with app.test_client() as client:
        yield client

# ── Basic endpoint tests ──────────────────────────────────
def test_home_returns_200(client):
    response = client.get('/')
    assert response.status_code == 200

def test_health_endpoint(client):
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'
    assert data['secure'] == True

def test_api_info_has_security_features(client):
    response = client.get('/api/info')
    data = response.get_json()
    assert 'security_features' in data
    assert len(data['security_features']) > 0

def test_metrics_endpoint(client):
    response = client.get('/metrics')
    assert response.status_code == 200

def test_security_report_endpoint(client):
    response = client.get('/security/report')
    assert response.status_code == 200
    data = response.get_json()
    assert 'summary' in data
    assert 'recent_attacks' in data

# ── Security header tests ─────────────────────────────────
def test_security_headers_present(client):
    response = client.get('/')
    assert 'X-Content-Type-Options' in response.headers
    assert 'X-Frame-Options' in response.headers
    assert 'X-XSS-Protection' in response.headers

def test_xframe_options_is_deny(client):
    response = client.get('/')
    assert response.headers['X-Frame-Options'] == 'DENY'

def test_xcontent_type_nosniff(client):
    response = client.get('/')
    assert response.headers['X-Content-Type-Options'] == 'nosniff'

# ── Attack detection tests ────────────────────────────────
def test_suspicious_path_blocked(client):
    response = client.get('/wp-admin')
    assert response.status_code == 404

def test_env_file_access_blocked(client):
    response = client.get('/.env')
    assert response.status_code == 404

def test_phpmyadmin_blocked(client):
    response = client.get('/phpmyadmin')
    assert response.status_code == 404

def test_sql_injection_blocked(client):
    response = client.get("/api/data?id=1' OR '1'='1")
    assert response.status_code == 400

# ── Login / brute force tests ─────────────────────────────
def test_login_page_loads(client):
    response = client.get('/login')
    assert response.status_code == 200

def test_invalid_login_fails(client):
    response = client.post('/login', data={'username': 'hacker', 'password': 'wrong'})
    assert response.status_code == 200  # shows error message

def test_brute_force_blocks_ip(client):
    # Simulate 5 failed logins
    for _ in range(5):
        client.post('/login', data={'username': 'hacker', 'password': 'wrong'})
    # 6th attempt should be blocked
    response = client.post('/login', data={'username': 'hacker', 'password': 'wrong'})
    assert response.status_code == 403
