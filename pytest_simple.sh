
py.test-3 -vs \
--log-cli-level=INFO \
--log-cli-format='[%(name)s] %(levelname)s %(message)s' \
--log-file=/tmp/pytest-run.log \
--log-file-level=DEBUG \
--log-file-format='%(asctime)s [%(name)s] %(levelname)s %(message)s' \
--log-file-date-format=%Y-%m-%dT%H:%M:%S%z \
--idp-realm master \
--idp-url https://$(hostname -f):8443 \
--sp-url https://$(hostname -f):60443 \
--username testuser \
--password Secret123 \
--url https://$(hostname -f):60443/private \
--logout-url=https://$(hostname -f):60443/private \
-k \
test_web_sso_post_redirect
