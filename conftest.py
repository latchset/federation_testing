#!/usr/bin/python3

import pytest
from samltest import SamlLoginTest
from samltest import IdpFactory as SamlIdpFactory
from samltest import SpFactory as SamlSpFactory
from oidctest import OidcLoginTest
from oidctest import IdpFactory as OidcIdpFactory
from oidctest import SpFactory as OidcSpFactory

def url_with_trailing_slash(url):
    if url.endswith('/'):
        return url
    return url + '/'

@pytest.fixture
def login_user(pytestconfig):
    return (pytestconfig.getoption('username'), pytestconfig.getoption('password'))


@pytest.fixture()
def resource_url(pytestconfig):
    return url_with_trailing_slash(pytestconfig.getoption('url'))


@pytest.fixture()
def info_resource_url(pytestconfig):
    if pytestconfig.getoption('info_url') is None:
        raise ValueError("Please set --info-url")
    return url_with_trailing_slash(pytestconfig.getoption('info_url'))


@pytest.fixture()
def nested_protected_resource_url(pytestconfig):
    if pytestconfig.getoption('nested_protected_url') is None:
        raise ValueError("Please set --nested-protected-url")
    return url_with_trailing_slash(pytestconfig.getoption('nested_protected_url'))


@pytest.fixture()
def logout_url(pytestconfig):
    return pytestconfig.getoption('logout_url')


@pytest.fixture()
def saml_test_instance(pytestconfig):
    idp_f = SamlIdpFactory(pytestconfig.getoption('idp_type'),
                           pytestconfig.getoption('idp_url'),
                           pytestconfig.getoption('idp_realm'),
                           pytestconfig.getoption('idp_soap_binding'))

    sp_f = SamlSpFactory(pytestconfig.getoption('url'),
                         pytestconfig.getoption('sp_type'),
                         pytestconfig.getoption('sp_url'),
                         pytestconfig.getoption('idp_url'))

    login_test = SamlLoginTest(idp_f, sp_f, pytestconfig.getoption('no_verify'))
    return login_test


@pytest.fixture
def saml_login_instance(login_user, resource_url, saml_test_instance):
    username, password = login_user
    saml_test_instance.redirect_post_flow(resource_url,
                                          username,
                                          password,
                                          None)
    return saml_test_instance


def pytest_addoption(parser):
    parser.addoption("--url", action="store", required=True)
    parser.addoption("--info-url", action="store")
    parser.addoption("--nested-protected-url", action="store")
    parser.addoption("--logout-url", action="store", required=False)
    parser.addoption("--logout-redirect-url", action="store", required=False)
    parser.addoption('--idp-url', required=True)
    parser.addoption('--idp-realm', action='store', type=str, required=True)
    parser.addoption('--idp-soap-binding', action='store', type=str)
    parser.addoption('--sp-url', required=False)
    parser.addoption('--username', action='store', type=str, required=True)
    parser.addoption('--password', action='store', type=str, required=True)
    parser.addoption('--idp-type', default='keycloak', choices=['keycloak'])
    parser.addoption('--sp-type', default='mellon', choices=['mellon', 'mod_auth_openidc'])
    parser.addoption('--no-verify', action='store_true')
    parser.addoption("--oauth-url", action="store", required=False)
    parser.addoption('--oidc-redirect-url', required=False)
    parser.addoption('--oidc-client-secret', required=False)
    parser.addoption('--oidc-client-id', required=False)
    parser.addoption("--bad-logout-redirect-url", action="store", nargs="*", type=str, required=False)
    parser.addoption('--neg-username', action='store', type=str, required=False)
    parser.addoption('--neg-password', action='store', type=str, required=False)


########## begin openidc conftest #############################

def url_with_trailing_slash(url):
    if url.endswith('/'):
        return url
    return url + '/'


@pytest.fixture
def negative_user(pytestconfig):
    return (pytestconfig.getoption('neg_username'),
            pytestconfig.getoption('neg_password'))


@pytest.fixture()
def idp_realm(pytestconfig):
    return pytestconfig.getoption('idp_realm')


@pytest.fixture()
def oidc_client_info(pytestconfig):
    return (pytestconfig.getoption('oidc_client_id'),
            pytestconfig.getoption('oidc_client_secret'))


@pytest.fixture()
def oauth_resource_url(pytestconfig):
    return url_with_trailing_slash(pytestconfig.getoption('oauth_url'))


@pytest.fixture()
def logout_redirect_url(pytestconfig):
    return url_with_trailing_slash(pytestconfig.getoption('logout_redirect_url'))


@pytest.fixture()
def bad_logout_redirect_urls(pytestconfig):
    return [ u for u in pytestconfig.getoption('bad_logout_redirect_url')[0].split(",") ]


@pytest.fixture()
def oidc_test_instance(pytestconfig):
    idp_f = OidcIdpFactory(pytestconfig.getoption('idp_type'),
                           pytestconfig.getoption('idp_url'),
                           pytestconfig.getoption('idp_realm'))

    sp_f = OidcSpFactory(pytestconfig.getoption('url'),
                         pytestconfig.getoption('sp_type'),
                         pytestconfig.getoption('oidc_redirect_url'),
                         pytestconfig.getoption('idp_url'))

    login_test = OidcLoginTest(idp_f, sp_f, pytestconfig.getoption('no_verify'))
    return login_test
