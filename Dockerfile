FROM payara/server-full:6.2024.6-jdk21@sha256:aafd98426dd07293d33d2bbf32fbe73ac13f986b82142181526fb2cb07f03c24

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*
USER payara
COPY --chown=payara:payara target/secbret.war /opt/payara/deployments/secbret.war
ENV DEPLOY_PROPS="--contextroot /"
RUN echo "set configs.config.server-config.network-config.protocols.protocol.http-listener-1.http.allow-payload-for-undefined-http-methods=true" >> $PREBOOT_COMMANDS
EXPOSE 8080

