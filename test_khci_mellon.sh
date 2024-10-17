#!/bin/bash

#################

set -x
set -e

./setup.sh /auth

function run_web_sso_test() {
    keycloak_realm=$1
    username=$2
    password=$3

    py.test-3 --idp-realm $keycloak_realm \
              --idp-url https://$(hostname):8443 \
              --sp-url https://$(hostname):60443/mellon_root \
              --username $username \
              --password $password \
              --url https://$(hostname):60443/mellon_root/private \
              --logout-url=https://$(hostname):60443/mellon_root/private \
              --junit-xml=result_khci_${keycloak_realm}.xml \
              -k test_web_sso_post_redirect
}

function does_realm_exist {
    keycloak_server=$1
    keycloak_realm=$2
    keycloak_password=$3

    TOKEN=$(curl -q -XPOST http://$keycloak_server:8080/auth/realms/master/protocol/openid-connect/token -d"grant_type=password&username=admin&password=$keycloak_password&client_id=admin-cli" | jq '.access_token')
    exists=$(curl -v -w"%{response_code}" -H"Bearer: $TOKEN" http://$keycloak_server:8080/realms/$keycloak_realm)
    if [ "$exists" == "200" ]; then
        return 0;
    else
        return 1;
    fi
}


######## Test 1: #######################################################

echo Secret123 | \
keycloak-httpd-client-install   \
    --client-originate-method registration \
    --client-hostname $(hostname) \
    --keycloak-server-url https://$(hostname):8443/auth \
    --keycloak-admin-username admin \
    --keycloak-admin-password-file - \
    --app-name mellon_example_app \
    --keycloak-realm master \
    --mellon-root "/mellon_root/" \
    --mellon-https-port 60443 \
    --mellon-protected-locations "/mellon_root/private" \
    --client-type mellon \
    --force

systemctl restart httpd

# Make sure the WebSSO flow works
run_web_sso_test master testuser Secret123

######## Test 2: #######################################################

##
# Test that a new realm is created
NEW_REALM=khci.test
set +e
does_realm_exist localhost $NEW_REALM Secret123
if [ $? -eq 0 ]; then
echo "Realm $NEW_REALM not expected to exist"
exit 1
fi
set -e

systemctl stop httpd

if [ -d /etc/httpd/federation ]; then
    mv /etc/httpd/federation /etc/httpd/federation.test1.$(date +%Y%m%d%H%M%S)
fi

rm -f /etc/httpd/conf.d/mellon_example_app_mellon_keycloak_master.conf

echo Secret123 | \
keycloak-httpd-client-install   \
    --client-originate-method registration \
    --client-hostname $(hostname) \
    --keycloak-server-url https://$(hostname):8443/auth \
    --keycloak-admin-username admin \
    --keycloak-admin-password-file - \
    --app-name mellon_example_app \
    --keycloak-realm $NEW_REALM \
    --location-root "/mellon_root" \
    --client-https-port 60443 \
    --protected-locations "/mellon_root/private" \
    --client-type mellon \
    --force

sleep 5

systemctl start httpd

kcadm="podman exec keycloak /opt/keycloak/bin/kcadm.sh"

$kcadm config credentials --server https://$(hostname):8443/auth/ \
        --realm master --user admin --password Secret123

USERID=$($kcadm get users -r $NEW_REALM | jq -r '.[]|select(.username=="testuser").id')
if [ -z "$USERID" ]; then
    $kcadm create users -r $NEW_REALM -s username=testuser -s enabled=true
    $kcadm set-password -r $NEW_REALM --username testuser --new-password Secret123
fi

sleep 5

# Make sure the WebSSO flow works against the newly created domain
run_web_sso_test $NEW_REALM testuser Secret123

rm -f /etc/httpd/conf.d/mellon_example_app_mellon_keycloak_khci.test.conf
