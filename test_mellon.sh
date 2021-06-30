#!/bin/bash

set -x 

################

echo Secret123 | \
keycloak-httpd-client-install   \
    --client-originate-method registration \
    --keycloak-server-url https://$(hostname):8443 \
    --keycloak-admin-username admin \
    --keycloak-admin-password-file - \
    --app-name mellon_example_app \
    --keycloak-realm master \
    --mellon-root "/mellon_root" \
    --mellon-https-port 60443 \
    --mellon-protected-locations "/mellon_root/private" \
    --force

################

semanage port -a -t http_port_t -p tcp 60443 || echo "semanage port 60443 already added"
setsebool httpd_can_network_connect=on || echo "setsebool httpd_can_network_connect=on already"

systemctl restart httpd

sleep 10

################

py.test-3 --idp-realm master \
          --idp-url https://$(hostname):8443 \
          --sp-url https://$(hostname):60443/mellon_root \
          --username testuser --password Secret123 \
          --url https://$(hostname):60443/mellon_root/private \
          --logout-url=https://$(hostname):60443/mellon_root/private \
          --info-url=https://$(hostname):60443/mellon_root/private/static \
          --nested-protected-url=https://$(hostname):60443/mellon_root/private/static/private_static \
	  test_mellon.py
rv=$?
if [ $rv -ne 0 ]; then
    echo "Mellon test failed"
    exit 1
fi

################
# mellon-diagnostics test

# Just exit if mod_auth_mellon-diagnostics can't be installed,
# at the moment it's not present in any of the repos
# (see RCM-59421)
rpm -q mod_auth_mellon-diagnostics || \
    dnf -y install mod_auth_mellon-diagnostics || \
    exit 0

rm -f /var/log/httpd/mellon_diagnostics

cat > /etc/httpd/conf.d/mellon_diag.conf <<EOF
MellonDiagnosticsEnable on
EOF

# This just rewrites the contents so we should either make the test smarter and
# revert the contents or keep this test last
echo "LoadModule auth_mellon_module modules/mod_auth_mellon-diagnostics.so" > /etc/httpd/conf.modules.d/10-auth_mellon.conf

systemctl restart httpd || exit 1

# Re-run the web POST flow again
py.test-3 --idp-realm master \
          --idp-url https://$(hostname):8443 \
          --sp-url https://$(hostname):60443/mellon_root \
          --username testuser \
          --password Secret123 \
          --url https://$(hostname):60443/mellon_root/private \
          --logout-url=https://$(hostname):60443/mellon_root/private \
          --info-url=https://$(hostname):60443/mellon_root/private/static \
          --nested-protected-url=https://$(hostname):60443/mellon_root/private/static/private_static \
          -k test_web_sso_post_redirect
rv=$?
if [ $rv -ne 0 ]; then
    echo "Mellon diagnostics test failed"
    exit 1
fi

# Make sure /something/ was written
if [ ! -f /var/log/httpd/mellon_diagnostics ]; then
    echo "The diagnostics file does not exist"
    exit 1
fi

size=$(stat -t --format="%b" /var/log/httpd/mellon_diagnostics)
if [ $size -eq 0 ]; then
    echo "No diagnostics were written"
    exit 1
fi