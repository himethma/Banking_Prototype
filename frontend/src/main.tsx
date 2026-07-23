import React from "react";
import ReactDOM from "react-dom/client";
import Keycloak from "keycloak-js";
import App from "./App";
import "./styles.css";
import {
  logBanner,
  logTlsConnection,
  logNetworkSegmentation,
  logOidcFlow,
  logJwtToken,
} from "./securityConsole";

const keycloak = new Keycloak({
  url: `${window.location.origin}/auth`,
  realm: "secure-bank",
  clientId: "bank-spa",
});

logBanner();
logTlsConnection();
logNetworkSegmentation();

keycloak
  .init({ onLoad: "check-sso", pkceMethod: "S256", checkLoginIframe: false })
  .then(() => {
    if (keycloak.authenticated && keycloak.token) {
      logOidcFlow(keycloak);
      logJwtToken(keycloak.token, "Access Token");
    }
    ReactDOM.createRoot(document.getElementById("root")!).render(
      <React.StrictMode>
        <App keycloak={keycloak} />
      </React.StrictMode>,
    );
  })
  .catch(() => {
    ReactDOM.createRoot(document.getElementById("root")!).render(
      <div className="fatal">Identity service initialization failed. Check the container health and local CA.</div>,
    );
  });

