FROM quay.io/keycloak/keycloak:26.3
COPY --chown=1000:0 --chmod=0755 entrypoint.sh /opt/keycloak/entrypoint.sh
USER 1000
ENTRYPOINT ["/opt/keycloak/entrypoint.sh"]
