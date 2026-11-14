FROM ghcr.io/home-assistant/home-assistant:2025.2.5@sha256:a81e875974c909957da5407a85d42409581a1f3c1ae202642519430389baf1ad
COPY --chmod=0555 custom_components/headscale_monitor /opt/headscale_monitor
COPY --chmod=0444 tests/mock_headscale/certs/ca.crt /opt/mock-ca.crt
COPY --chmod=0555 scripts/compose_smoke.py /opt/compose_smoke.py
COPY --chmod=0555 tests/homeassistant/install-test-fixtures.sh /etc/cont-init.d/99-headscale-test-fixtures.sh
