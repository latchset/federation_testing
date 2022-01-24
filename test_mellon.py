#!/usr/bin/python3

import pytest
import logging
import time

import samltest
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


def has_request_method(html_page):
    return 'REQUEST_METHOD=GET' in html_page


def has_auth_type_mellon(html_page):
    return 'AUTH_TYPE=Mellon' in html_page


def is_page_without_redirects(reply, page_check_fn=lambda x: True):
    return reply.ok and \
           len(reply.history) == 0 and \
           page_check_fn(reply.text)


def test_web_sso_post_redirect(login_user, resource_url, saml_test_instance):
    """
    Test the web browser SSO profile
    """
    logging.info(f"About to run the WebSSO flow for {resource_url} with "
                  "an empty session")
    username, password = login_user
    saml_test_instance.redirect_post_flow(resource_url,
                                          username,
                                          password,
                                          is_my_page)

    logging.info(f"Re-using cached session")
    sp_resource = saml_test_instance.session.get(resource_url)
    assert is_page_without_redirects(sp_resource)
    assert samltest.same_normalized_url(resource_url, sp_resource.url)
    logging.info(f"OK, retrieved {resource_url} without contacting IdP")

    logging.info(f"Clearing the session")
    saml_test_instance.clear_session()
    sp_resource = saml_test_instance.session.get(resource_url)
    assert samltest.request_is_idp_auth_redirect(resource_url,
                                                 saml_test_instance,
                                                 sp_resource)
    logging.info(f"OK, got redirected to IdP again")


def test_logout(resource_url, logout_url, saml_login_instance):
    """
    Test the SP-initiated logout profile
    """
    # First, verify we are logged in
    logging.info(f"Re-using cached session")
    sp_resource = saml_login_instance.session.get(resource_url)
    assert is_page_without_redirects(sp_resource)
    assert samltest.same_normalized_url(resource_url, sp_resource.url)
    logging.info(f"OK, retrieved {resource_url} without contacting IdP")

    # Logout..
    saml_login_instance.logout(logout_url)

    # ..and make sure we can't access the protected resource
    # without being redirected to the IDP again
    sp_resource = saml_login_instance.session.get(resource_url)
    assert samltest.request_is_idp_auth_redirect(resource_url,
                                                 saml_login_instance,
                                                 sp_resource)
    logging.info(f"OK, got redirected to IdP again")


def test_bad_logout_uri(resource_url, logout_url, saml_login_instance,
                        bad_logout_redirect_urls):
    """
    Test that the user cannot be tricked on logout into following a
    malformed URI through the ReturnTo parameter
    """
    # First, verify we are logged in
    logging.info(f"Re-using cached session")
    sp_resource = saml_login_instance.session.get(resource_url)
    assert is_page_without_redirects(sp_resource)
    assert samltest.same_normalized_url(resource_url, sp_resource.url)
    logging.info(f"OK, retrieved {resource_url} without contacting IdP")

    # Logout..
    for bad_url in bad_logout_redirect_urls:
        with pytest.raises(samltest.LogoutReplyError):
            LOGGER.info("Trying to trick the user into following %s", bad_url)
            saml_login_instance.logout(bad_url)


def test_ecp_flow(login_user, resource_url, saml_test_instance):
    """
    Test ECP profile
    """
    logging.info(f"About to run the ECP flow for {resource_url} with "
                  "an empty session")
    username, password = login_user
    saml_test_instance.ecp_flow(resource_url,
                                username,
                                password,
                                is_my_page)

    logging.info(f"Re-using cached session")
    sp_resource = saml_test_instance.session.get(resource_url,
                                                 headers=samltest.ECP_HEADERS)
    assert is_page_without_redirects(sp_resource)
    assert samltest.same_normalized_url(resource_url, sp_resource.url)
    logging.info(f"OK, retrieved {resource_url} without contacting IdP")

    logging.info(f"Clearing the session")
    saml_test_instance.clear_session()
    sp_resource = saml_test_instance.session.get(resource_url,
                                                 headers=samltest.ECP_HEADERS)
    assert samltest.request_is_ecp_authn(saml_test_instance, sp_resource)
    logging.info(f"OK, got back an ECP AuthnRequest")


def test_mellon_enable_info(login_user,
                            resource_url,
                            info_resource_url,
                            nested_protected_resource_url,
                            saml_test_instance):
    """
    Test that accessing a resource with:
        MellonEnable info
    is allowed without authentication, but the environment is populated when
    accessed as an authenticated user

    To make sure inheriting the access checks works well with mellon,
    the environment should be set up so that:
        - info_resource_url is below resource_url
        - resource_url is protected with MellonEnable auth
        - info_resource_url is "protected" with MellonEnable info
        - nested_protected_resource_url is below resource_url and protected
          with MellonEnable auth

    For example:
    <Location /example_app/private>
        AuthType Mellon
        MellonEnable auth
        Require valid-user
    </Location>

    <Location /example_app/private/static>
        MellonEnable info
        Require all granted
    </Location>

    <Location /example_app/private/static/private>
        MellonEnable auth
        Require valid-user
    </Location>

    The test checks that:
        - you can't access neither resource_url nor
          nested_protected_resource_url without authentication
        - you can access info_resource_url without authentication
        - when you access info_resource_url after authentication, the variables
          would be populated
    """
    # First, check the URLs are nested as we expect
    assert info_resource_url.startswith(resource_url)
    assert nested_protected_resource_url.startswith(info_resource_url)

    # Test that we can access the info resource without authentication
    info_req = saml_test_instance.session.get(info_resource_url)
    assert is_page_without_redirects(info_req, has_request_method)

    # Test that accessing resource_url and nested_protected_resource_url
    # redirects to IDP
    protected_req = saml_test_instance.session.get(resource_url)
    assert samltest.request_is_idp_auth_redirect(resource_url,
                                                 saml_test_instance,
                                                 protected_req)
    nested_protected_req = saml_test_instance.session.get(
                                                 nested_protected_resource_url)
    assert samltest.request_is_idp_auth_redirect(nested_protected_resource_url,
                                                 saml_test_instance,
                                                 nested_protected_req)

    # Now login
    username, password = login_user
    saml_test_instance.redirect_post_flow(resource_url,
                                          username,
                                          password)

    # Request the info resource again
    info_req = saml_test_instance.session.get(info_resource_url)
    assert is_page_without_redirects(info_req, has_auth_type_mellon)
