import os
import ssl
import urllib.request

context = ssl.create_default_context(cafile="/certs/ca.crt")
context.load_cert_chain("/certs/api.crt", "/certs/api.key")
instance_name = os.environ.get("INSTANCE_NAME", "api")
with urllib.request.urlopen(
    f"https://{instance_name}:8443/healthz", context=context, timeout=3
) as response:
    raise SystemExit(0 if response.status == 200 else 1)
