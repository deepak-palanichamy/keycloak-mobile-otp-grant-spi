FROM quay.io/keycloak/keycloak:26.6
COPY ./output/*.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start"]