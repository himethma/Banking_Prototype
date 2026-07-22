import ssl

import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="/certs/api.key",
        ssl_certfile="/certs/api.crt",
        ssl_ca_certs="/certs/ca.crt",
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )

