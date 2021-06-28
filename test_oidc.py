#!/usr/bin/python3

import pytest
import logging
import time

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
    """
    Test the usual authorisation flow
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
    """
    Test that the user can be logged out and is no longer able to
    reach the protected resource after logout
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
    """
    Test that the OAuth flow works
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
    """
    Test that the user cannot be tricked into following a malformed
    URI through the redirect_uri parameter
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
