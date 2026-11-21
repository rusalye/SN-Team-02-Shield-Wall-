FROM debian:trixie-slim
ARG CRS_VERSION=4.7.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      nginx libnginx-mod-http-modsecurity libnginx-mod-http-headers-more-filter \
      gettext-base openssl ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz | tar -xz -C /opt \
    && mv /opt/coreruleset-${CRS_VERSION} /opt/crs
RUN mkdir -p /var/log/shield /var/cache/modsecurity /etc/nginx/dynamic /etc/nginx/certs /etc/nginx/templates /etc/nginx/snippets \
    && chown -R www-data:www-data /var/log/shield /var/cache/modsecurity
COPY nginx.conf.template /etc/nginx/templates/nginx.conf.template
COPY snippets/ /etc/nginx/snippets/
COPY modsec/ /etc/nginx/modsec/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80 443
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD curl -fs http://127.0.0.1/healthz || exit 1
ENTRYPOINT ["/entrypoint.sh"]
