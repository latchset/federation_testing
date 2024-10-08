#!/usr/bin/python3

import re
import argparse
import logging
import json
import urllib.parse

import requests
from html.parser import HTMLParser


# Exceptions
class OidcError(Exception):
    def __init__(self, msg, expected=None, got=None):
        self.msg = msg
        self.expected = expected
        self.got = got
        self._base_msg = "Oidc Error"

    def __str__(self):
        str_exc = f"{self._base_msg}: {self.msg}"
        if self.expected and self.got:
            str_exc += f": expected {self.expected} but received {self.got}"
        return str_exc


class NoCredentialsError(OidcError):
    def __init__(self):
        pass

    def __str__(self):
        return "No credentials provided"


class AuthnRequestError(OidcError):
    def __init__(self, msg, expected=None, got=None):
        super().__init__(msg, expected, got)
        self._base_msg = "Malformed AuthnRequest"


class OidcFlowError(OidcError):
    def __init__(self, got_code, expected_code=200):
        self.got_code = got_code
        self.expected_code = expected_code

    def __str__(self):
        return f"Expected HTTP code {self.expected_code} "\
               f"but received {self.got_code}"


class LogoutReplyError(OidcError):
    def __init__(self, msg, expected=None, got=None):
        super().__init__(msg, expected, got)
        self._base_msg = "Malformed Logout reply"


class OAuthUnauthorizedError(OidcError):
    def __init__(self, msg, expected=200, got=401):
        super().__init__(msg, expected, got)
        self._base_msg = "Access denied"


# Utility functions
def get_location_from_redirect(redirect):
    if redirect.is_redirect is False:
        return None
    return redirect.headers.get('Location')


def same_normalized_url(orig, received):
    orig_normalized = urllib.parse.urlunparse(
                                    urllib.parse.urlparse(orig))
    received_normalized = urllib.parse.urlunparse(
                                    urllib.parse.urlparse(orig))
    logging.debug(f"Arrived at {received_normalized}")
    return orig_normalized == received_normalized


def check_query_parameter(parsed_query, key, expected_value):
    val = parsed_query.get(key, [None, ])[0]
    if val != expected_value:
        raise ValueError(f"{key} must be set to {expected_value}, "
                         "was set to {val}")


def query_parameter_exists(parsed_query, key):
    val = parsed_query.get(key)
    if not val:
        raise ValueError(f"{key} was not present in query")


def request_is_idp_auth_redirect(resource, openidc_login_instance, request):
    """
    A convenience checker that returns True if request is
    a chain of redirects from a protected resource to a mod_auth_openidc
    handler to an IDP, False otherwise
    """
    authn_request_parser = openidc_login_instance.sp_factory.authn_request()
    try:
        authn_request_parser.check_request(request)
    except AuthnRequestError:
        return False
    return True


# Parsers for HTML documents we encounter during the flow
class AttrHTMLParser(HTMLParser):
    def __init__(self, html_content):
        super(AttrHTMLParser, self).__init__()
        self._tags = dict()
        self.feed(html_content)

    def handle_starttag(self, tag, attrs):
        if tag in self._tags:
            self._tags[tag].append(dict(attrs))
        else:
            self._tags[tag] = [dict(attrs)]

    def find_tag(self, name, required_attrs=None):
        all_tags = self._tags.get(name)
        if all_tags is None:
            return None

        if required_attrs is None:
            return all_tags[0]

        for tag in all_tags:
            intersection = required_attrs.items() & tag.items()
            if intersection == required_attrs.items():
                return tag

        return None


class AuthenticationRequest(object):
    """
    Class representing:
        https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
    """
    def __init__(self, resource, idp_url):
        self.redirect_uri = None
        self.resource = resource
        self.idp_name = urllib.parse.urlparse(idp_url).hostname

    def _check_idp_redirect_from_reply(self, idp_redirect):
        """
        https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

        3.1.2.1. Authentication Request
        """
        location = get_location_from_redirect(idp_redirect)
        if location is None:
            raise AuthnRequestError("No Location found in redirect")

        parsed_loc = urllib.parse.urlparse(location)
        logging.debug("Parsed %s from the location" % parsed_loc.hostname)
        if parsed_loc.hostname != self.idp_name:
            logging.error("Did not find the expected %s instead found %s" %
                          (self.idp_name, parsed_loc.hostname))
            raise AuthnRequestError("AuthnRequest does not redirect to IDP",
                                    self.idp_name,
                                    parsed_loc.hostname)

        parsed_qs = urllib.parse.parse_qs(parsed_loc.query)

        # scope (REQUIRED)
        #
        # OpenID Connect requests MUST contain the openid scope value. If
        # the openid scope value is not present, the behavior is entirely
        # unspecified. Other scope values MAY be present. Scope values used
        # that are not understood by an implementation SHOULD be ignored. See
        # Sections 5.4 and 11 for additional scope values defined by this
        # specification.
        check_query_parameter(parsed_qs, "scope", "openid")
        # response_type (REQUIRED)
        # OAuth 2.0 Response Type value that determines the authorization
        # processing flow to be used, including what parameters are returned
        # from the endpoints used. When using the Authorization Code Flow,
        # this value is code.
        check_query_parameter(parsed_qs, "response_type", "code")
        # client_id (REQUIRED)
        # OAuth 2.0 Client Identifier valid at the Authorization Server.
        query_parameter_exists(parsed_qs, "client_id")

        # redirect_uri (REQUIRED)
        # Redirection URI to which the response will be sent. This URI
        # MUST exactly match one of the Redirection URI values for the
        # Client pre-registered at the OpenID Provider
        self.redirect_uri = parsed_qs.get("redirect_uri")

    def check_request(self, reply):
        raise NotImplementedError("Subclasses must implement this method")


class ModAuthOpenidcAuthnRequest(AuthenticationRequest):
    def __init__(self, resource, idp_url):
        super(ModAuthOpenidcAuthnRequest, self).__init__(resource, idp_url)

    def _check_idp_redirect_from_reply(self, idp_redirect):
        # Run the generic tests first
        super(ModAuthOpenidcAuthnRequest,
              self)._check_idp_redirect_from_reply(idp_redirect)

        # mod_auth_openidc specific checks will go here..
        # FIXME: maybe check state as it's recommended?
        # FIXME: check the cookie value here

    def check_request(self, reply):
        if len(reply.history) != 1:
            raise AuthnRequestError("Expected 1 redirect, "
                                    "got %d" % len(reply.history))
        self._check_idp_redirect_from_reply(reply.history[0])


class ModAuthOpenidcLogoutRequest(object):
    def __init__(self, mod_redirect_handler_uri, logout_redirect_uri):
        self.mod_redirect_handler_uri = mod_redirect_handler_uri
        self.logout_redirect_uri = logout_redirect_uri

    def logout_url(self):
        query = "logout=%s" % self.logout_redirect_uri
        parsed = urllib.parse.urlparse(self.mod_redirect_handler_uri)
        logout_fragments = urllib.parse.ParseResult(scheme=parsed.scheme,
                                                    netloc=parsed.netloc,
                                                    path=parsed.path,
                                                    params='',
                                                    query=query,
                                                    fragment='')
        return urllib.parse.urlunparse(logout_fragments)

    def check_from_reply(self, reply):
        if len(reply.history) != 1:
            raise LogoutReplyError("Expected one redirect, got %d"
                                   % len(reply.history))
        if not same_normalized_url(self.logout_redirect_uri, reply.url):
            raise LogoutReplyError("Expected to reach %s, reached %s instead"
                                   % (self.logout_redirect_uri, reply.url))


class OpenIdIdp(object):
    def __init__(self, url, idp_realm, idp_type,
                 login_username_field='username',
                 login_password_field='password'):
        self.url = url

        parsed_url = urllib.parse.urlparse(url)
        self.name = parsed_url.hostname

        self.idp_type = idp_type
        self.login_page = {'username': login_username_field,
                           'password': login_password_field,
                           'action': None}

    def _get_single_html_attr(self, elem, attr_name):
        if len(elem) != 1:
            raise IndexError('Expected one element %s got %d', elem, len(elem))
        return elem[0].get(attr_name)

    def parse_login_form(self,
                         login_page,
                         form_el_name='form',
                         form_el_attrs=None,
                         form_action_attr_name='action'):
        parser = AttrHTMLParser(login_page)
        login_form_elem = parser.find_tag(form_el_name,
                                          required_attrs=form_el_attrs)
        return login_form_elem.get(form_action_attr_name)


class KeycloakIdp(OpenIdIdp):
    def __init__(self, url, realm):
        super(KeycloakIdp, self).__init__(url, realm, 'keycloak')

    def do_login(self, session, login_page, username, password):
        login_url = super(KeycloakIdp, self).parse_login_form(
                                        login_page,
                                        form_el_attrs={'id': 'kc-form-login'})

        logging.debug("Logging in to IDP as %s:%s", username, password)
        form_data = {'username': username, 'password': password}

        login_reply = session.post(url=login_url,
                                   data=form_data,
                                   allow_redirects=False)
        logging.debug("IDP login reply: %s", login_reply)
        return login_reply

    def get_bearer_token(self, session, realm, username, password, client_id, client_secret):
        logging.debug("Getting OAuth token from IDP as %s:%s", username, password)

        token_service_path = "realms/%s/protocol/openid-connect/token" % (realm)
        match = re.search(r'http[s]:\/\/.*(\/.*)$', self.url)
        if match is not None:
            authdir = match.group(1)
            token_service_path = authdir + "/" + token_service_path
        token_service_url = urllib.parse.urljoin(self.url, token_service_path)

        form_data = {'username': username, 'password': password}
        form_data['grant_type'] = 'password'
        form_data['client_id'] = client_id
        form_data['client_secret'] = client_secret

        headers = { "Content-Type" : "application/x-www-form-urlencoded" }

        oauth_reply = session.post(url=token_service_url,
                                   headers=headers,
                                   data=form_data,
                                   allow_redirects=False)
        logging.debug("IDP login reply: %d: %s", oauth_reply.status_code, oauth_reply.content)
        if oauth_reply.ok is False:
            return ""
        decoded_content = json.loads(oauth_reply.content)
        return decoded_content.get("access_token")


class SpFactory(object):
    def __init__(self, resource, sp_type, oidc_redirect_uri, idp_name):
        if sp_type == 'mod_auth_openidc':
            self.authn_req_cls = ModAuthOpenidcAuthnRequest
            self.auth_req_instance_args = (resource, idp_name)

            self.logout_req_cls = ModAuthOpenidcLogoutRequest
            self.logout_req_instance_args = (oidc_redirect_uri, )
        else:
            raise ValueError(f"Unsupported SP type {sp_type}")

    def authn_request(self):
        return self.authn_req_cls(*self.auth_req_instance_args)

    def logout_request(self, logout_uri):
        args = self.logout_req_instance_args + (logout_uri, )
        return self.logout_req_cls(*args)


class IdpFactory(object):
    def __init__(self, idp_type, idp_url, idp_realm):
        self.idp_url = idp_url
        self.idp_realm = idp_realm

        if idp_type == 'keycloak':
            self.idp = KeycloakIdp(idp_url, idp_realm)
        else:
            raise ValueError(f"Unsupported IdP type {idp_type}")

    def idp_login(self, session, login_page, username, password):
        return self.idp.do_login(session, login_page, username, password)

    def get_bearer_token(self, session, realm, username, password, client_id, client_secret):
        return self.idp.get_bearer_token(session, realm,
                                         username, password,
                                         client_id, client_secret)


class OidcLoginTest(object):
    def __init__(self, idp_factory, sp_factory, verify=True):
        self.idp_factory = idp_factory
        self.sp_factory = sp_factory
        self._session = None
        self.verify = verify

    @property
    def session(self):
        if self._session is None:
            self._session = requests.Session()
            self._session.verify = self.verify
        return self._session

    @session.setter
    def session(self, session):
        self._session = session

    def clear_session(self):
        self._session = None

    def authorisation_flow(self, url,
                           username, password,
                           page_check_fn=None, page_check_args={}):
        if username is None or password is None:
            raise NoCredentialsError

        logging.info("Running the OpenID Connect authorisation flow")

        # Eventually we should get a 200..
        document_get = self.session.get(url)
        if document_get.status_code != 200:
            raise OidcFlowError(document_get.status_code)
        logging.debug(document_get.url)

        # ..but behind the scenes we are redirected to the IDP, check
        # the SP-specific redirect
        authn_request = self.sp_factory.authn_request()
        authn_request.check_request(document_get)
        logging.info("The AuthnRequest from SP to IDP is OK")

        # Try to login to the IdP
        login_reply = self.idp_factory.idp_login(self.session,
                                                 document_get.text,
                                                 username, password)
        if not login_reply.is_redirect:
            raise OidcFlowError("Expected a redirect back to SP")

        reply = self.session.get(get_location_from_redirect(login_reply))
        logging.info(f"Logged in to the IDP as {username}")

        if not same_normalized_url(url, reply.url):
            raise ValueError("Expected to reach a different location")
        logging.info(f"Retrieved {url} from the SP")

        # And make sure we got the contents we wanted initially
        if page_check_fn is not None and \
                page_check_fn(reply.text) is False:
            raise ValueError("Expected to reach a different content")

    def oauth_flow(self, url, realm, username, password, client_id, client_secret,
                   page_check_fn=None, page_check_args={}):

        token = self.idp_factory.get_bearer_token(self.session, realm,
                                                  username, password,
                                                  client_id, client_secret)

        headers = {"Authorization" : "Bearer %s" % token}
        document_get = self.session.get(url, headers=headers)
        if document_get.is_redirect:
            raise OidcFlowError("Expected to reach the page without redirects")
        elif document_get.status_code == 401:
            raise OAuthUnauthorizedError("Not authorized to access %s\n", url)
        elif document_get.ok is not True:
            raise OidcFlowError("Expected 200 OK, got %d\n" % document_get.status_code)

        # And make sure we got the contents we wanted initially
        if page_check_fn is not None and \
                page_check_fn(document_get.text) is False:
            raise ValueError("Expected to reach a different content, got %s\n", document_get.text)

    def logout(self, logout_redirect_url):
        logout_request = self.sp_factory.logout_request(logout_redirect_url)
        logout_reply = self.session.get(logout_request.logout_url())
        logout_request.check_from_reply(logout_reply)


def has_claim_username(html_page):
    username_claim = "OIDC_CLAIM_preferred_username="
    if username_claim not in html_page:
        return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument('--test-type', default='oidc', choices=['oidc', 'oauth'])
    parser.add_argument('--oidc-redirect-url', required=True)
    parser.add_argument('--logout-follow-url', required=True)
    parser.add_argument('--idp-url', required=True)
    parser.add_argument('--idp-realm', required=True)
    parser.add_argument('--idp-type', default='keycloak', choices=['keycloak'])
    parser.add_argument('--sp-type',
                        default='mod_auth_openidc',
                        choices=['mod_auth_openidc'])
    parser.add_argument('--username', action='store', type=str)
    parser.add_argument('--password', action='store', type=str)
    parser.add_argument('-d', '--debug', action='count', default=0)
    parser.add_argument('--no-verify', action='store_true')

    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels)-1, args.debug)]
    logging.basicConfig(level=level)

    login_test = OidcLoginTest(IdpFactory(args.idp_type, args.idp_url, args.idp_realm),
                               SpFactory(args.url, args.sp_type,
                                         args.oidc_redirect_uri, args.idp_url),
                               not args.no_verify)

    # Gets the page using the WebSSO flow
    if args.test_type == 'oidc':
        logging.info(f"About to run the authorisation flow for {args.url} with "
                    "an empty session")

        login_test.authorisation_flow(args.url,
                                      args.username, args.password,
                                      has_claim_username)
    elif args.test_type == 'oauth':
        login_test.oauth_flow(args.url,
                              args.username, args.password)
    else:
        raise ValueError("Uknown test type %s\n" % args.test_type)
