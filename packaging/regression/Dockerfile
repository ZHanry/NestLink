ARG NESTLINK_BASE
FROM ${NESTLINK_BASE}
ARG NESTLINK_SOURCE
LABEL org.opencontainers.image.title="NestLink regression server" \
      org.opencontainers.image.version="0.7.0-rc.1" \
      org.opencontainers.image.revision="${NESTLINK_SOURCE}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Regression only; full product acceptance pending" \
      lat.hap.nestlink.purpose="regression"
COPY --chmod=0755 nestlink-server /usr/local/bin/nestlink-server
COPY notices/ /usr/share/doc/nestlink/notices/
USER 65532:65532
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/nestlink-server"]
CMD ["control", "--config", "/data/deployment/server.toml"]
