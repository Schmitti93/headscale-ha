FROM nginx:1.27.4-alpine@sha256:4ff102c5d78d254a6f0da062b3cf39eaf07f01eec0927fd21e219d0af8bc0591
RUN mkdir -p /etc/nginx/tls && chmod 0555 /etc/nginx/tls
COPY --chmod=0444 nginx.conf /etc/nginx/conf.d/default.conf
COPY --chmod=0444 certs/server.crt /etc/nginx/tls/server.crt
COPY --chmod=0444 certs/server.key /etc/nginx/tls/server.key
