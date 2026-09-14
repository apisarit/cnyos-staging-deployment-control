FROM nginx:1.29.3-alpine@sha256:b3c656d55d7ad751196f21b7fd2e8d4da9cb430e32f646adcf92441b72f82b14
COPY nginx.conf /etc/nginx/nginx.conf
COPY --chown=101:101 dist/ /usr/share/nginx/html/
USER 101:101
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1/healthz || exit 1
