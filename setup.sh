#!/bin/bash -x

#################

set -x
set -e

AUTHDIR=${1:-""}

echo "Running test on: $(hostname)"
echo "Hostname -f shows: $(hostname)"
echo "Running test for AUTHDIR=${AUTHDIR}"

#KC_VERSION=16.1.1
#KC_VERSION=latest
KC_VERSION=22.0.1

#################

if [ -f /etc/os-release ]; then
    . /etc/os-release
    VER_MAJOR=$(echo $VERSION_ID|cut -f1 -d.)
    VER_MINOR=$(echo $VERSION_ID|cut -f2 -d.)
    if [ "$ID" = "rhel" ]; then
        dnf config-manager --enable rhel-*
        if [ $VER_MAJOR -eq 8 -a $VER_MINOR -le 3 ]; then
            KC_VERSION=18.0.2
            echo "$(hostname -i|awk '{print $1}') $(hostname)" >> /etc/hosts
        fi
    fi
fi

dnf -y install \
    keycloak-httpd-client-install \
    mod_auth_openidc \
    python3-lxml \
    python3-requests \
    python3-pytest \
    python3-distro \
    dnf-utils \
    openssl \
    mod_ssl \
    httpd \
    podman

if [ "$ID" = "rhel" -o "$ID" = "centos" ] && [ $VER_MAJOR -lt 10 ]; then
    dnf -y install \
        java-11-openjdk-headless \
        mod_auth_mellon \
        python3-lasso
else
    dnf -y install \
        java-17-openjdk-headless
fi

#################

if [ -d /etc/httpd/federation ]; then
    tar zcvf /tmp/httpd.federation.$(date +%Y%m%d-%H%M%S).tgz /etc/httpd/federation
fi

if [ -d /tmp/https ]; then
    tar zcvf /tmp/https.$(date +%Y%m%d-%H%M%S).tgz /tmp/https
    rm -rf /tmp/https
fi

if [ -f /etc/httpd/conf.d/example_app_ssl.conf ]; then
    rm /etc/httpd/conf.d/example_app_ssl.conf
fi

podman container rm -af || echo "No containers to remove...continuing"

#################

mkdir /tmp/https
pushd /tmp/https

cat > ca.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = .
database         = \$dir/index.txt
new_certs_dir    = \$dir/newcerts

certificate      = \$dir/rootCA.crt
serial           = \$dir/serial
private_key      = \$dir/rootCA.key
RANDFILE         = \$dir/rand

default_days     = 365
default_crl_days = 30
default_md       = sha256

policy           = policy_any
email_in_dn      = no

name_opt         = ca_default
cert_opt         = ca_default
copy_extensions  = copy

[ usr_cert ]
authorityKeyIdentifier = keyid, issuer

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ policy_any ]
organizationName       = supplied
organizationalUnitName = supplied
commonName             = supplied
emailAddress           = optional

[ req ]
distinguished_name = req_distinguished_name
prompt             = no

[ req_distinguished_name ]
O  = IdM Federation Example 
OU = IdM Federation Example Test
CN = IdM Federation Example Test CA
EOF

#################

cat > tls.cnf <<EOF
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[ req_distinguished_name ]
O = IdM Federation Example
OU = IdM Federation Example Test
CN = $(hostname)

[ req_ext ]
subjectAltName = @alt_names

[ v3_ca ]
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $(hostname)
EOF

#################

touch serial index.txt crlnumber index.txt.attr
mkdir newcerts
echo 'unique_subject = no' > index.txt.attr
openssl rand -hex 16 > serial

# Key/Cert pair for RootCA
openssl genrsa -out rootCA.key 4096
openssl req -batch -config ca.cnf \
    -x509 -new -nodes -key rootCA.key -sha256 -days 10000 \
    -set_serial 0 -extensions v3_ca -out rootCA.crt

# Key/Cert pair for Keycloak
openssl genrsa -out tls.key 4096
openssl req -new -nodes -key tls.key \
    -reqexts req_ext -config tls.cnf -out tls.csr
openssl ca -config ca.cnf -batch -notext -keyfile rootCA.key \
    -extensions v3_ca -extfile tls.cnf \
    -in tls.csr -days 365 -out tls.crt

# Key/Cert pair for Web server
openssl genrsa -out web.key 4096
openssl req -new -nodes -key web.key \
    -reqexts req_ext -config tls.cnf -out web.csr
openssl ca -config ca.cnf -batch -notext -keyfile rootCA.key \
    -extensions v3_ca -extfile tls.cnf \
    -in web.csr -days 365 -out web.crt

cp /tmp/https/web.crt /etc/pki/tls/certs/web.crt
cp /tmp/https/web.key /etc/pki/tls/private/web.key

cp /tmp/https/rootCA.crt /etc/pki/ca-trust/source/anchors/
cp /tmp/https/tls.crt /etc/pki/ca-trust/source/anchors/
cp /tmp/https/web.crt /etc/pki/ca-trust/source/anchors/
update-ca-trust

# keycloak runs as UID 1000 so we need the certs to be accessible to the
# keycloak user
chown -R 1000:1000 /tmp/https

popd

#################

if [ -f /usr/bin/firewall-cmd ]; then
    systemctl start firewalld
    firewall-cmd --add-port 80/tcp
    firewall-cmd --add-port 443/tcp
    firewall-cmd --add-port 8443/tcp
    firewall-cmd --add-port 60443/tcp
    firewall-cmd --runtime-to-permanent
fi

################

keytool -import \
    -keystore /tmp/https/truststore.keystore \
    -file /tmp/https/rootCA.crt \
    -alias federation_example \
    -trustcacerts -storepass Secret123 -noprompt

podman pull quay.io/keycloak/keycloak:$KC_VERSION

# podman unshare not needed for rootful containers
# podman unshare chown 1000 -R /tmp/https

podman run --name keycloak -d \
    -p 8080:8080 \
    -p 8443:8443 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=Secret123 \
    -e KC_LOG_LEVEL=debug \
    -e KC_HOSTNAME=$(hostname) \
    -e KC_HTTPS_CERTIFICATE_FILE=/etc/x509/https/tls.crt \
    -e KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/x509/https/tls.key \
    -e KC_HTTPS_TRUST_STORE_FILE=/etc/x509/https/truststore.keystore \
    -e KC_HTTPS_TRUST_STORE_PASSWORD=Secret123 \
    -e KC_HTTP_RELATIVE_PATH=${AUTHDIR} \
    -v /tmp/https:/etc/x509/https:Z \
    quay.io/keycloak/keycloak:$KC_VERSION start

# Removing deprecated auto-build option
# --auto-build

sleep 15

kcadm="podman exec keycloak /opt/keycloak/bin/kcadm.sh"

set +e

for count in {1..10}; do
    $kcadm config truststore --trustpass Secret123 \
        /etc/x509/https/truststore.keystore
    if [ $? -eq 0 ]; then
        break
    else
        sleep 30
    fi
done

if [ $count -eq 10 ]; then
    echo "----- Begin keycloak container logs for iteration $count"
    podman logs keycloak
    echo "----- End keycloak container logs for iteration $count"
    exit 1
fi

for count in {1..3}; do
    $kcadm config credentials --server https://$(hostname):8443${AUTHDIR}/ \
        --realm master --user admin --password Secret123

    if [ $? -eq 0 ]; then
        break
    else
        sleep 30
    fi
done

if [ $count -eq 3 ]; then
    echo "----- Begin keycloak container logs for iteration $count"
    podman logs keycloak
    echo "----- End keycloak container logs for iteration $count"
    exit 1
fi

set -e

# For positive tests
$kcadm create users -r master -s username=testuser -s enabled=true -s email=testuser@master
$kcadm set-password -r master --username testuser --new-password Secret123

# For negative tests
$kcadm create users -r master -s username=neguser -s enabled=true -s email=neguser@master
$kcadm set-password -r master --username neguser --new-password Secret123

################

cp /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/example_app_ssl.conf
sed -i 's/443/60443/g' /etc/httpd/conf.d/example_app_ssl.conf
sed -i 's/localhost.crt/web.crt/' /etc/httpd/conf.d/example_app_ssl.conf
sed -i 's/localhost.key/web.key/' /etc/httpd/conf.d/example_app_ssl.conf

################

mkdir -p /var/www/html/openidc_root/private/static/private_static

cat > /var/www/html/openidc_root/logged_out.html <<EOF
<html>
<title>Logout</title>
<p>
Congratulations, you've been logged out!
</p>
<p>
Now try to <a href="/openidc_root/private/">log back in</a>
</p>
</html>
EOF

cat > /var/www/html/openidc_root/private/index.html <<EOF
<html><title>Secure</title>Hello there...from SP ...<br>
<a href="/openidc_root/private/redirect_uri?logout=https://$(hostname):60443/openidc_root/logged_out.html">Logout</a>
<hr>
<pre><!--#printenv --></pre>
EOF

cat > /etc/httpd/conf.d/openidc_example_app_private.conf <<EOF
<Directory /var/www/html/openidc_root/private>
    Options +Includes
    AddOutputFilter INCLUDES .html
</Directory>
EOF

cp /var/www/html/openidc_root/private/index.html \
    /var/www/html/openidc_root/private/static/
cp /var/www/html/openidc_root/private/index.html \
    /var/www/html/openidc_root/private/static/private_static/


systemctl start httpd

################

if [ "$ID" = "rhel" -o "$ID" = "centos" ] && [ $VER_MAJOR -ge 10 ]; then
    echo "mod_auth_mellon not supported in RHEL-10 and later"
    echo "Skipping mellon setup"
    exit 0
fi

mkdir -p /var/www/html/mellon_root/private/static/private_static

cat > /var/www/html/mellon_root/logged_out.html <<EOF
<html>
<title>Logout</title>
<p>
Congratulations, you've been logged out!
</p>
<p>
Now try to <a href="/mellon_root/private/">log back in</a>
</p>
</html>
EOF

cat > /var/www/html/mellon_root/private/index.html <<EOF
<html><title>Secure</title>Hello there...from SP ...<br>
<a href="https://$HOSTNAME:60443/mellon_root/mellon/logout?ReturnTo=https://$HOSTNAME:60443/mellon_root/logged_out.html">Log out</a>
<hr>
<pre><!--#printenv --></pre>
EOF

cat > /etc/httpd/conf.d/mellon_example_app_private.conf <<EOF
<Directory /var/www/html/mellon_root/private>
    Options +Includes
    AddOutputFilter INCLUDES .html
</Directory>
EOF

cat > /etc/httpd/conf.d/mellon_example_app_private_static.conf <<EOF
<Location /mellon_root/private/static>
    MellonEnable info
    Require all granted
</Location>

<Location /mellon_root/private/static/private_static>
    MellonEnable auth
    Require valid-user
</Location>
EOF

cp /var/www/html/mellon_root/private/index.html \
    /var/www/html/mellon_root/private/static/
cp /var/www/html/mellon_root/private/index.html \
    /var/www/html/mellon_root/private/static/private_static/

systemctl start httpd
