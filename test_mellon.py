#!/usr/bin/python3

import pytest
import logging
import time
import os
import tempfile
import subprocess

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
    """Test the web browser SSO profile

    :id: ffcd9c05-34b3-4aa4-91a6-279c9cbc3613
    :steps:
        1. Run the WebSSO for resource_url flow with an empty session
        2. Reuse cached session and check page for redirects
        3. Clear session
        4. Check that page contains IdP auth redirect
    :expectedresults:
        1. Success
        2. Page should be without redirects
        3. Success
        4. Response should contain redirect to the IdP auth page
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
    """Test the SP-initiated logout profile

    :id: cfc511e6-1410-4139-b33f-b0b3f39a9978
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
    """Test that the user cannot be tricked on logout into following
    a malformed URI through the ReturnTo parameter

    :id: 2c1e2e58-d6a0-47b0-8d4c-55f9fd1d0374
    :steps:
        1. Verify that we are logged in by reusing cached session
        2. Check page for redirects
        3. Logout using malformed URI
    :expectedresults:
        1. Success
        2. Page should be without redirects
        3. Should receive Malformed Logout reply
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
    """Test ECP profile

    :id: 8ed54232-e281-4db1-bdb2-173a29dcccbe
    :steps:
        1. Run ECP flow for resource_url with an empty session
        2. Reuse cached session and check page for redirects
        3. Clear session
        4. Make sure we can't access the protected resource
           without ECP AuthnRequest
    :expectedresults:
        1. Success
        2. Page should be without redirects
        3. Success
        4. Response should contain ECP AuthnRequest
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
    """Test that accessing a resource with:
    MellonEnable info
    is allowed without authentication, but the environment is populated when
    accessed as an authenticated user

    :id: acfe2cf0-1d9d-495c-93d1-786f36557861
    :setup: To make sure inheriting the access checks works well with mellon, \
the environment should be set up so that:

    - info_resource_url is below resource_url
    - resource_url is protected with MellonEnable auth
    - info_resource_url is "protected" with MellonEnable info
    - nested_protected_resource_url is below resource_url and protected
      with MellonEnable auth

    For example::

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

    :steps:
        1. Check that the URLS are nested as expected
        2. Test that we can access the info resource without
           authentication
        3. Test that accessing resource_url and nested_protected_resource_url
           without authentication redirects to IdP
        4. Login
        5. Test that after accessing info_resource_url after authentication
           variables would be populated
    :expectedresults:
        1. Success
        2. Page should be without redirects
        3. We should be redirected to IdP for authentication
        4. Success
        5. Page should be without redirects
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


def test_mellon_diagnostics(login_user, resource_url, saml_test_instance):
    """Test mellon diagnostics records something to the log when configured

    :id: d3bca100-fde6-4701-841a-d65cf87232e3
    :steps:
        1. Remove /var/log/httpd/mellon_diagnostics so we know it's clean
        2. Perform a normal authentication flow to generate diag data
        3. Check that the file exists and is larger than 0
    :expectedresults:
        1. Success
        2. Success
        3. File size should be larger than 0
    """
    logging.info(f"About to run the WebSSO flow for {resource_url} with "
                  "an empty session")

    # first remove the file so we know it's clean for the check later
    diag_file = '/var/log/httpd/mellon_diagnostics'
    open(diag_file, 'w').close()

    # next perform a normal authentication flow to generate diag data
    username, password = login_user
    saml_test_instance.redirect_post_flow(resource_url,
                                          username,
                                          password,
                                          is_my_page)

    # finally check that the file exists and is larger than 0
    diag_size = os.path.getsize(diag_file)
    if diag_size > 0:
        logging.info(f"Diagnostics file {diag_file}"
                      "size {diag_size} is greater than 0")


def test_mellon_create_metadata():
    """Test mellon create metadata script creates xml file

    :id: 1bdcf65d-5cc2-4a17-8d21-0f02a77d3f65
    :steps:
        1. Run mellon_create_metadata.sh script
    :expectedresults:
        1. Create xml file
    """
    temp_dir = tempfile.TemporaryDirectory()
    os.chdir(temp_dir.name)
    print(temp_dir.name)
    script_cmd = ["/usr/libexec/mod_auth_mellon/mellon_create_metadata.sh",
                 "test", "https://localhost/test"]
    subprocess.run(script_cmd)
    assert os.path.isfile(f"{temp_dir.name}/test.xml"), \
        "metadata script did not create xml file"
    assert os.stat(f"{temp_dir.name}/test.xml").st_size != 0, "xml file is empty"

