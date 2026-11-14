FROM ghcr.io/home-assistant/home-assistant:2026.11.1@sha256:6785d1eca68747a524c156faae1b139ed415c07357386ae6fe17291986e59e82
COPY --chmod=0555 custom_components/headscale_monitor /opt/headscale_monitor
COPY --chmod=0444 tests/mock_headscale/certs/ca.crt /opt/mock-ca.crt
COPY --chmod=0555 scripts/compose_smoke.py /opt/compose_smoke.py
COPY --chmod=0555 tests/homeassistant/install-test-fixtures.sh /etc/cont-init.d/99-headscale-test-fixtures.sh
