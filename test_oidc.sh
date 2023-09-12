#!/bin/bash

set -x

################

echo Secret123 | \
keycloak-httpd-client-install   \
    --client-originate-method registration \
    --client-hostname $(hostname) \
    --keycloak-server-url https://$(hostname):8443 \
    --keycloak-admin-username admin \
    --keycloak-admin-password-file - \
    --keycloak-realm master \
    --app-name openidc_example_app \
    --client-type openidc \
    --location-root "/openidc_root" \
    --protected-locations "/openidc_root/private" \
    --client-https-port 60443 \
    --oidc-remote-user-claim preferred_username \
    --oidc-logout-uri "/openidc_root/logged_out.html" \
    --force

################

conf_path=/etc/httpd/conf.d/openidc_example_app_oidc_keycloak_master.conf
oidc_secret=$(grep OIDCClientSecret $conf_path | awk '{print $2}')
oidc_client_id=$(grep OIDCClientID $conf_path | awk '{print $2}')

mkdir -p /var/www/html/openidc_root/oauth
cp /var/www/html/openidc_root/private/index.html /var/www/html/openidc_root/oauth

cat >> $conf_path <<EOF

<Location /openidc_root/oauth>
    AuthType oauth20
    Require claim email:testuser@master
</Location>

# Substitute the IDP name and the realm name. My realm is called federation.test. The rest is a well-known URI
OIDCOAuthIntrospectionEndpoint https://$(hostname):8443/auth/realms/master/protocol/openid-connect/token/introspect
# We'll be verifying the access token against the keycloak introspection point
OIDCOAuthIntrospectionEndpointParams token_type_hint=access_token
# This must match the client ID as set on the keycloak side
OIDCOAuthClientID $oidc_client_id
# Grab the secret from the credentials tab of the client settings in keycloak
OIDCOAuthClientSecret $oidc_secret
# Otherwise the KC-issued JWT tokens are too large for the cache
OIDCCacheEncrypt On

# Opening up allowed redirects to test redirect url validation
OIDCRedirectURLsAllowed ^.*$
EOF

systemctl restart httpd

################

semanage port -a -t http_port_t -p tcp 60443
setsebool httpd_can_network_connect=on

systemctl restart httpd

################

py.test-3 --log-cli-level=INFO \
          --url https://$(hostname):60443/openidc_root/private \
          --idp-url https://$(hostname):8443 \
          --username testuser --password Secret123 \
          --oidc-redirect-url https://$(hostname):60443/openidc_root/private/redirect_uri \
          --logout-redirect-url https://$(hostname):60443/openidc_root/private \
          --idp-realm=master \
          --oidc-client-secret=$oidc_secret \
          --oidc-client-id=$oidc_client_id \
          --oauth-url=https://$(hostname):60443/openidc_root/oauth \
          --neg-username=neguser --neg-password=Secret123 \
          --sp-type=mod_auth_openidc \
          --bad-logout-redirect-url=http:www.redhat.com,'/%09redhat.com','\/redhat.com','\//redhat.com','\///redhat.com' \
          --junit-xml=result_oidc.xml \
          test_oidc.py

rv=$?
if [ $rv -ne 0 ]; then
    echo "OIDC test failed"
    exit 1
fi

