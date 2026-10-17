ARG NESTLINK_BASE
FROM ${NESTLINK_BASE}
ARG NESTLINK_VERSION
ARG NESTLINK_SOURCE
LABEL org.opencontainers.image.title="NestLink RC" \
      org.opencontainers.image.version="${NESTLINK_VERSION}" \
      org.opencontainers.image.revision="${NESTLINK_SOURCE}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Development candidate; fixed signing and full user acceptance pending"
COPY --chmod=0755 nestlink-server /usr/local/bin/nestlink-server
COPY web/ /usr/share/nestlink/web/
COPY notices/ /usr/share/doc/nestlink/notices/
USER 65532:65532
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/nestlink-server"]
CMD ["control", "--config", "/data/server.toml"]
