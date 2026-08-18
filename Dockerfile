FROM alpine:3.24

WORKDIR /app

ARG TARGETARCH
ARG BINARY_SOURCE_DIR=dist

RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S app && \
    adduser -S app -G app && \
    mkdir -p /data /data/certificates && \
    chown -R app:app /app /data

COPY ${BINARY_SOURCE_DIR}/portlyn-linux-${TARGETARCH} /app/server
RUN chmod +x /app/server

USER app

EXPOSE 8080 80 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 CMD wget -qO- http://127.0.0.1:8080/readyz >/dev/null || exit 1

ENTRYPOINT ["/app/server"]
