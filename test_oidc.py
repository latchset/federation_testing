#!/usr/bin/python3

import pytest
import logging
import time
import socket
import shutil
import subprocess

import oidctest
from html.parser import HTMLParser

LOGGER = logging.getLogger(__name__)

class MyPageParser(HTMLParser):
    def __init__(self):
        super(MyPageParser, self).__init__()
        self.title = None
        self._has_title = False

    def handle_starttag(self, tag, attrs):
        if tag == 'title':
            self._has_title = True

    def handle_endtag(self, tag):
        if tag == 'title':
            self._has_title = False

    def handle_data(self, data):
        if self._has_title:
            self.title = data


def is_my_page(html_page):
    parser = MyPageParser()
    parser.feed(html_page)
    if parser.title != "Secure":
        return False
    return True


def is_page_without_redirects(reply, page_check_fn=lambda x: True):
    return reply.ok and \
           len(reply.history) == 0 and \
           page_check_fn(reply.text)


def test_auth_flow(login_user, resource_url, oidc_test_instance):
    """Test the usual authorisation flow

    :id: e8dcc342-f2ca-4c12-935a-d2d7a3a884e8
    :steps:
        1. Run authorisation flow for resource_url with an empty session
        2. Reuse cached session and check page for redirects
        3. Clear session
        4. Make sure we can't access the protected resource
           without authentication
    :expectedresults:
        1. Success
        2. Page should be without redirects
        3. Success
        4. Response should contain IdP authentication request

    """
    LOGGER.info(f"About to run the authorisation flow for {resource_url} "
                 " with an empty session")
    username, password = login_user
    oidc_test_instance.authorisation_flow(resource_url,
                                          username,
                                          password,
                                          is_my_page)

    LOGGER.info(f"Re-using cached session")
    sp_resource = oidc_test_instance.session.get(resource_url)
    assert is_page_without_redirects(sp_resource)
    assert oidctest.same_normalized_url(resource_url, sp_resource.url)
    LOGGER.info(f"OK, retrieved {resource_url} without contacting IdP")

    LOGGER.info(f"Clearing the session")
    oidc_test_instance.clear_session()
    sp_resource = oidc_test_instance.session.get(resource_url)
    assert oidctest.request_is_idp_auth_redirect(resource_url,
                                                 oidc_test_instance,
                                                 sp_resource)
    LOGGER.info(f"OK, got redirected to IdP again")


def test_logout(login_user, resource_url,
                oidc_test_instance, logout_redirect_url):
    """Test that the user can be logged out and is no longer able to
    reach the protected resource after logout

    :id: e5c7ce13-6dbb-4486-996b-a982a08ff6be
    :steps:
        1. Verify that we are logged in by reusing cached session
        2. Check page for redirects
        3. Logout
        4. Make sure we can't access the protected resource
           without being redirected to the IdP again
    :expectedresults:
        1. Success
        2. Page should be without redirects
        3. Success
        4. Response should contain redirect to the IdP auth page
    """
    username, password = login_user
    oidc_test_instance.authorisation_flow(resource_url,
                                          username,
                                          password,
                                          is_my_page)

    LOGGER.info(f"Re-using cached session")
    sp_resource = oidc_test_instance.session.get(resource_url)
    assert is_page_without_redirects(sp_resource)
    assert oidctest.same_normalized_url(resource_url, sp_resource.url)

    # Log out
    oidc_test_instance.logout(logout_redirect_url)

    sp_resource = oidc_test_instance.session.get(resource_url)
    # We can't really use oidctest.request_is_idp_auth_redirect here because
    # KC just reuses the session and sends us back, so let's just check
    # that we get a redirect and not the page..
    assert sp_resource.ok
    assert len(sp_resource.history) > 0


def test_oauth(idp_realm, oidc_client_info,
               login_user, negative_user,
               oauth_resource_url, oidc_test_instance):
    """Test that the OAuth flow works

    :id: 2937dc4c-096a-4023-aa6e-4e267c53e2d3
    :steps:
        1. Run OAuth flow for resource_url with a valid user
        2. Run OAuth flow for resource_url with a invalid user
    :expectedresults:
        1. Success
        2. Should raise OAuthUnauthorizedError
    """
    username, password = login_user
    oidc_client_id, oidc_client_secret = oidc_client_info

    oidc_test_instance.oauth_flow(oauth_resource_url, idp_realm,
                                  username, password,
                                  oidc_client_id, oidc_client_secret,
                                  is_my_page)

    # Negative test
    username, password = negative_user
    with pytest.raises(oidctest.OAuthUnauthorizedError):
        oidc_test_instance.oauth_flow(oauth_resource_url, idp_realm,
                                      username, password,
                                      oidc_client_id, oidc_client_secret,
                                      is_my_page)

def test_bad_logout_uri(login_user, resource_url,
                        oidc_test_instance,
                        bad_logout_redirect_urls):
    """Test that the user cannot be tricked into following a malformed
    URI through the redirect_uri parameter

    :id: dfe480f7-e87f-47f7-b1ae-647d7cf41f4f
    :setup:
        1. Configure system for mod_auth_openidc tests
        2. Add OIDCRedirectURLsAllowed setting to config
    :steps:
        1. Verify that we are logged in by reusing cached session
        2. Check page for redirects
        3. Logout using malformed URI
        4. Check that we are NOT logged out by fetching the resource
        5. Check that we got the protected resource without being redirected
    :expectedresults:
        1. Success
        2. Page should be without redirects
        3. Should receive Malformed Logout reply
        4. Success
        5. Page should be without redirects
    """
    LOGGER.info("Setting OIDCRedirectURLsAllowed option in config")
    conf_path = "/etc/httpd/conf.d/openidc_example_app_oidc_keycloak_master.conf"
    shutil.copy(conf_path, f"{conf_path}.test_backup")
    hostname = socket.getfqdn()
    rule = f"OIDCRedirectURLsAllowed ^https://{hostname}:60443"
    with open(conf_path, "a") as conf_file:
        conf_file.write(rule)
    subprocess.run(["systemctl", "restart", "httpd"])

    username, password = login_user
    oidc_test_instance.authorisation_flow(resource_url,
                                          username,
                                          password,
                                          is_my_page)

    LOGGER.info(f"Re-using cached session")
    sp_resource = oidc_test_instance.session.get(resource_url)
    assert is_page_without_redirects(sp_resource)
    assert oidctest.same_normalized_url(resource_url, sp_resource.url)

    print(bad_logout_redirect_urls)
    for bad_url in bad_logout_redirect_urls:
        with pytest.raises(oidctest.LogoutReplyError):
            LOGGER.info("Trying to trick the user into following %s", bad_url)
            oidc_test_instance.logout(bad_url)
        # Make sure we were actually NOT logged out by fetching the resource
        # and checking that we got the protected resource without being
        # redirected
        sp_resource = oidc_test_instance.session.get(resource_url)
        assert is_page_without_redirects(sp_resource)

    shutil.move(f"{conf_path}.test_backup", conf_path)
