import React from "react";
import ReactDOM from "react-dom/client";
import Keycloak from "keycloak-js";
import App from "./App";
import "./styles.css";

const keycloak = new Keycloak({
  url: `${window.location.origin}/auth`,
  realm: "secure-bank",
  clientId: "bank-spa",
});

keycloak
  .init({ onLoad: "check-sso", pkceMethod: "S256", checkLoginIframe: false })
  .then(() => {
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

