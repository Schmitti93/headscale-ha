#!/usr/bin/with-contenv bash
set -eu
mkdir -p /config/custom_components
rm -rf /config/custom_components/headscale_monitor
cp -R /opt/headscale_monitor /config/custom_components/headscale_monitor
cp /opt/mock-ca.crt /config/mock-ca.crt
chmod -R a+rwX /config/custom_components/headscale_monitor /config/mock-ca.crt
