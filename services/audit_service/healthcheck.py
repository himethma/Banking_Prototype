import ssl
import sys
import urllib.request

url, cert, key, ca = sys.argv[1:5]
context = ssl.create_default_context(cafile=ca)
context.load_cert_chain(cert, key)
with urllib.request.urlopen(url, context=context, timeout=3) as response:
    raise SystemExit(0 if response.status == 200 else 1)

