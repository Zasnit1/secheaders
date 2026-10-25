import json

import secheaders as sh


def test_hsts():
    assert sh._hsts("max-age=31536000; includeSubDomains")[0]
    assert not sh._hsts("max-age=100")[0]
    assert not sh._hsts(None)[0]


def test_csp():
    assert sh._csp("default-src 'self'")[0]
    assert not sh._csp("default-src 'self' 'unsafe-inline'")[0]
    assert not sh._csp("upgrade-insecure-requests")[0]  # no default/script-src
    assert not sh._csp(None)[0]


def test_frame_covered_by_csp():
    assert sh._frame(None, "default-src 'self'; frame-ancestors 'none'")[0]
    assert sh._frame("DENY", None)[0]
    assert not sh._frame(None, None)[0]


def test_server_version_disclosure():
    assert not sh._server("nginx/1.25.3")[0]
    assert sh._server("nginx")[0]
    assert sh._server(None)[0]


def test_audit_headers_scoring():
    good = {
        "strict-transport-security": "max-age=63072000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "server": "nginx",
    }
    r = sh.Report("https://x", 200, checks=sh.audit_headers(good))
    assert r.score == 100 and r.grade == "A"
    # Empty headers: only the Server check passes (absent banner = no version leak).
    r2 = sh.Report("https://x", 200, checks=sh.audit_headers({}))
    assert r2.grade == "F" and r2.score < 10


def test_cookie_flags():
    checks = sh.audit_cookies(["sid=abc; Secure; HttpOnly; SameSite=Lax"])
    assert checks and checks[0].passed
    bad = sh.audit_cookies(["sid=abc"])
    assert bad and not bad[0].passed and "Secure" in bad[0].detail


def test_cors_wildcard_with_credentials_fails():
    c = sh.audit_cors({"access-control-allow-origin": "*", "access-control-allow-credentials": "true"})
    assert not c.passed
    assert sh.audit_cors({"access-control-allow-origin": "*"}).passed
    assert sh.audit_cors({}).passed  # no CORS headers is fine


def test_json_output_shape():
    r = sh.Report("https://x", 200, checks=sh.audit_headers({"x-content-type-options": "nosniff"}))
    d = sh.to_dict(r)
    assert d["url"] == "https://x" and "checks" in d and isinstance(d["score"], int)
    json.dumps(d)  # must be serialisable
