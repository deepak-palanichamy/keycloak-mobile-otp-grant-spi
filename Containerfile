FROM quay.io/keycloak/keycloak:26.6

# Copy the custom SPI provider jar
COPY ./output/*.jar /opt/keycloak/providers/

# Build Keycloak with standard production build flags pre-baked
RUN /opt/keycloak/bin/kc.sh build --db=postgres --health-enabled=true --metrics-enabled=true

# Start using the --optimized flag so Keycloak doesn't try to re-build on startup
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]