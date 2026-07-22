import ssl
import urllib.request

context = ssl.create_default_context(cafile="/certs/ca.crt")
context.load_cert_chain("/certs/api.crt", "/certs/api.key")
with urllib.request.urlopen("https://localhost:8443/healthz", context=context, timeout=3) as response:
    raise SystemExit(0 if response.status == 200 else 1)

