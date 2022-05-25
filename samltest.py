#!/usr/bin/python3

import argparse
import logging
import lasso
import urllib.parse
from html.parser import HTMLParser

import requests

MEDIA_TYPE_PAOS = 'application/vnd.paos+xml'
PAOS_HEADER = 'ver="%s";"%s"' % (lasso.PAOS_HREF, lasso.ECP_HREF)
ECP_HEADERS = {'Accept': MEDIA_TYPE_PAOS, 'PAOS': PAOS_HEADER}


# Exceptions
class SamlError(Exception):
    def __init__(self, msg, expected=None, got=None):
        self.msg = msg
        self.expected = expected
        self.got = got
        self._base_msg = "Saml Error"

    def __str__(self):
        str_exc = f"{self._base_msg}: {self.msg}"
        if self.expected and self.got:
            str_exc += f": expected {self.expected} but received {self.got}"
        return str_exc


class NoCredentialsError(SamlError):
    def __init__(self):
        pass

    def __str__(self):
        return "No credentials provided"


class SamlFlowError(SamlError):
    def __init__(self, got_code, expected_code=200):
        self.got_code = got_code
        self.expected_code = expected_code

    def __str__(self):
        return f"Expected HTTP code {self.expected_code} "\
                "but received {self.got_code}"


class LogoutReplyError(SamlError):
    def __init__(self, msg, expected=None, got=None):
        super().__init__(msg, expected, got)
        self._base_msg = "Malformed Logout reply"


class ConfigurationError(SamlError):
    def __init__(self, msg):
        super(ConfigurationError, self).__init__(msg)


class AuthnRequestError(SamlError):
    def __init__(self, msg, expected=None, got=None):
        super(AuthnRequestError, self).__init__(msg, expected, got)
        self._base_msg = "Malformed AuthnRequest"


class SamlResponseError(SamlError):
    def __init__(self, msg, expected=None, got=None):
        super(SamlResponseError, self).__init__(msg, expected, got)
        self._base_msg = "Malformed SamlResponse"


# Utility functions
def get_location_from_redirect(redirect):
    if redirect.status_code != 303:
        raise SamlError("reply not a redirect",
                        "303", str(redirect.status_code))
    return redirect.headers.get('Location')


def same_normalized_url(orig, received):
    orig_normalized = urllib.parse.urlunparse(
                                    urllib.parse.urlparse(orig))
    received_normalized = urllib.parse.urlunparse(
                                    urllib.parse.urlparse(received))
    logging.debug(f"Arrived at {received_normalized}")
    return orig_normalized == received_normalized


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


# Classes representing the Authn SP Request and the SAML IDP response
# For generic SP and IDP
class AuthnRequest(object):
    def __init__(self, idp_url):
        # See SAML tech overview 5.1.2: SP-Initiated SSO, step #2
        self.saml_request = None
        self.relay_state = None
        # the IdP name is also not part of the request, but the auth
        # request needs to redirect to the IDP, so it also makes sense
        # to store it here
        self.idp_name = urllib.parse.urlparse(idp_url).hostname

    def _check_idp_redirect_from_reply(self, idp_redirect):
        "Generic AuthnRequest checker"
        location = get_location_from_redirect(idp_redirect)
        if location is None:
            raise AuthnRequestError("No Location found in mellon redirect")

        parsed_loc = urllib.parse.urlparse(location)
        if parsed_loc.hostname != self.idp_name:
            raise AuthnRequestError("AuthnRequest does not redirect to IDP",
                                    self.idp_name,
                                    parsed_redirect.hostname)

        parsed_qs = urllib.parse.parse_qs(parsed_loc.query)

        saml_request = parsed_qs.get('SAMLRequest', [])
        try:
            self.saml_request = saml_request[0]
        except IndexError:
            raise AuthnRequestError("No SAMLRequest found")

        relay_state = parsed_qs.get('RelayState', [])
        try:
            self.relay_state = relay_state[0]
        except IndexError:
            self.relay_state = None

    def check_from_reply(self, resource, reply):
        raise NotImplementedError("Subclasses must implement this method")

    def parse_ecp_auth_request(self, reply):
        server = lasso.Server()
        ecp = lasso.Ecp(server)
        ecp.processAuthnRequestMsg(reply.text)
        return ecp


class LogoutRequest(object):
    def __init__(self, sp_url, logout_service, return_to):
        self.sp_url = sp_url
        self.logout_service = logout_service
        self.return_to = return_to

    def logout_url(self):
        return_to = f"ReturnTo={self.return_to}"
        sp_parsed_url = urllib.parse.urlparse(self.sp_url)
        url_fragments = urllib.parse.ParseResult(scheme='https',
                                                 netloc=sp_parsed_url.netloc,
                                                 path=self.logout_service,
                                                 params='',
                                                 query=return_to,
                                                 fragment='')
        return urllib.parse.urlunparse(url_fragments)

    def check_from_reply(self, reply):
        raise NotImplementedError("Subclasses must implement this method")


class SamlResponse(object):
    def __init__(self):
        self.saml_response = None
        self.relay_state = None
        self.assertion_url = None

    def from_form(self, html_form):
        raise NotImplementedError("Subclasses must implement this method")

    def from_reply(self, reply):
        if reply.status_code != 200:
            raise SamlFlowError(reply.status.code)
        return self.from_form(reply.text)


# Subclasses of the request and response for Mellon and Keycloak
class MellonAuthnRequest(AuthnRequest):
    def __init__(self, sp_url, idp_url):
        super(MellonAuthnRequest, self).__init__(idp_url)
        self.sp_parsed_url = urllib.parse.urlparse(sp_url)

    def _check_mellon_redirect_from_reply(self, resource, mellon_reply):
        # The first redirect will point at the SP again with relative path
        # /mellon/login? the parameters will include ?ReturnTo=DP and ?IdP=
        location = get_location_from_redirect(mellon_reply)
        if location is None:
            raise AuthnRequestError("No Location found in mellon redirect")

        parsed_loc = urllib.parse.urlparse(location)
        if parsed_loc.hostname != self.sp_parsed_url.hostname:
            raise AuthnRequestError("Mellon did redirect to the SP",
                                    self.sp_parsed_url.hostname,
                                    parsed_loc.hostname)
        if parsed_loc.path != '/mellon_root/mellon/login':
            raise AuthnRequestError("Mellon did not redirect to /mellon_root/mellon/login",
                                    "mellon/login", parsed_loc.path)

        parsed_qs = urllib.parse.parse_qs(parsed_loc.query)
        return_to = parsed_qs.get('ReturnTo', [])
        if return_to[0] != resource:
            raise AuthnRequestError("ReturnTo does not redirect to "
                                    "the resource",
                                    resource, return_to)
        idp = parsed_qs.get('IdP', [])
        parsed_idp = urllib.parse.urlparse(idp[0])
        if parsed_idp.hostname != self.idp_name:
            raise AuthnRequestError("Unexpected IdP value",
                                    self.idp_name,
                                    parsed_idp.hostname)

    def _check_idp_redirect_from_reply(self, idp_redirect):
        # Run the generic tests first
        super(MellonAuthnRequest,
              self)._check_idp_redirect_from_reply(idp_redirect)

        # mellon specific checks
        # at this point, mellon should set the cookie to cookietest
        if idp_redirect.cookies.get('mellon-cookie') != 'cookietest':
            raise AuthnRequestError("Unexpected mellon-cookie value",
                                    "cookietest",
                                    idp_redirect.cookies.get('mellon-cookie'))

    def check_from_reply(self, resource, reply):
        # Mellon would return two replies, the first tells that in order to
        # access the protected resource, the client should visit a mellon
        # endpoint, the second redirects from the mellon endpoint to the IDP
        if len(reply.history) != 2:
            raise AuthnRequestError(f"Expected 2 redirects, "
                                     "got {reply.history}")
        mellon_redirect, idp_redirect = reply.history
        self._check_mellon_redirect_from_reply(resource, mellon_redirect)
        self._check_idp_redirect_from_reply(idp_redirect)


class KeycloakSamlResponse(SamlResponse):
    def __init__(self):
        super(KeycloakSamlResponse, self).__init__()

    def from_form(self, html_form):
        print(html_form)
        parser = AttrHTMLParser(html_form)

        rstate_input = parser.find_tag('input',
                                       required_attrs={'name': 'RelayState'})
        self.relay_state = rstate_input.get('value')
        # RelayState should point at the protected resource
        logging.debug(f"RelayState: {self.relay_state}")

        saml_response_input = parser.find_tag(
                                       'input',
                                       required_attrs={'name': 'SAMLResponse'})
        self.saml_response = saml_response_input.get('value')

        assertion_form = parser.find_tag('form')
        self.assertion_url = assertion_form.get('action')
        # AssertionUrl should point at the /mellon/postResponse endpoint
        logging.debug(f"Assertion url: {self.assertion_url}")


class MellonLogoutRequest(LogoutRequest):
    def __init__(self, sp_url, logout_service, return_to):
        super(MellonLogoutRequest, self).__init__(sp_url,
                                                  logout_service,
                                                  return_to)

    def check_from_reply(self, reply):
        if reply.status_code > 300:
            raise LogoutReplyError('Unexpected reply on logout')


class SamlIdp(object):
    def __init__(self, url, idp_type,
                 realm, soap_binding=None,
                 login_username_field='username',
                 login_password_field='password'):
        self.url = url
        self.realm = realm
        self.soap_binding = soap_binding

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


class KeycloakIdp(SamlIdp):
    def __init__(self, url, realm, soap_binding=None):
        if soap_binding is None:
            soap_binding = f"{url}/auth/realms/{realm}/protocol/saml"
        print(soap_binding)
        super(KeycloakIdp, self).__init__(url, 'keycloak', realm, soap_binding)

    def do_login(self, session, login_page, username, password):
        login_url = super(KeycloakIdp, self).parse_login_form(
                                        login_page,
                                        form_el_attrs={'id': 'kc-form-login'})

        logging.debug("Logging in to IDP as %s:%s", username, password)
        form_data = {'username': username, 'password': password}

        login_reply = session.post(url=login_url, data=form_data)
        logging.debug("IDP login reply: %s", login_reply)
        return login_reply

    def parse_saml_response(self, reply):
        saml_response = KeycloakSamlResponse()
        saml_response.from_reply(reply)
        return saml_response


class SpFactory(object):
    def __init__(self, resource, sp_type, sp_url, idp_name):
        if sp_type == 'mellon':
            self.logout_service = "/mellon_root/mellon/logout"
            self.assertion_consumer_svc = "/mellon_root/mellon/postResponse"

            self.authn_req_cls = MellonAuthnRequest
            self.auth_req_instance_args = (sp_url, idp_name)

            self.logout_req_cls = MellonLogoutRequest
            self.logout_req_instance_args = (sp_url, self.logout_service, )
        else:
            raise ValueError(f"Unsupported SP type {sp_type}")

    def authn_request(self):
        return self.authn_req_cls(*self.auth_req_instance_args)

    def logout_request(self, return_to):
        return self.logout_req_cls(*self.logout_req_instance_args, return_to)


class IdpFactory(object):
    def __init__(self, idp_type, idp_url, realm, idp_soap_binding=None):
        self.idp_url = idp_url

        if idp_type == 'keycloak':
            self.saml_response_cls = KeycloakSamlResponse
            self.idp = KeycloakIdp(idp_url, realm, idp_soap_binding)
        else:
            raise ValueError(f"Unsupported IdP type {idp_type}")

    def saml_response_parser(self, reply):
        saml_response = self.saml_response_cls()
        saml_response.from_reply(reply)
        return saml_response

    def idp_login(self, session, login_page, username, password):
        return self.idp.do_login(session, login_page, username, password)


class SamlLoginTest(object):
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

    def _saml_response_post(self, session, response):
        form_data = {'SAMLResponse': response.saml_response,
                     'RelayState': response.relay_state}

        sp_consumer_reply = session.post(url=response.assertion_url,
                                         data=form_data)
        logging.debug(f"SP assertion consumer: {sp_consumer_reply}")
        return sp_consumer_reply

    def redirect_post_flow(self, url, username, password, page_check_fn=None):
        if username is None or password is None:
            raise NoCredentialsError

        logging.info("Running the WebSSO redirect-POST flow")

        # Eventually we should get a 200..
        document_get = self.session.get(url)
        if document_get.status_code != 200:
            raise SamlFlowError(document_get.status_code)
        logging.debug(document_get.url)

        # ..but behind the scenes we are redirected to the IDP, check
        # the SP-specific redirect
        authn_request = self.sp_factory.authn_request()
        authn_request.check_from_reply(url, document_get)
        logging.info("The AuthnRequest from SP to IDP is OK")

        # Try to login to the IdP
        login_reply = self.idp_factory.idp_login(self.session,
                                                 document_get.text,
                                                 username, password)
        if login_reply.status_code != 200:
            raise SamlFlowError(login_reply.status_code)

        logging.info(f"Logged in to the IDP as {username}")

        # check the response from the IDP
        # If the reply contained a ReturnTo, the response must match it
        saml_response = self.idp_factory.saml_response_parser(login_reply)
        if saml_response.relay_state != authn_request.relay_state:
            raise ValueError("The request and reply RelayState do not match")
        # the reply must also point to the SP postResponse endpoint
        assertion_consumer_svc = urllib.parse.urlparse(
                                        saml_response.assertion_url).path
        if assertion_consumer_svc != self.sp_factory.assertion_consumer_svc:
            raise ValueError("The request and reply AssertionUrl do not match")

        logging.info(f"Verified the response from IDP")

        # The login returns 200 and a JS form in body which would normally
        # redirect us to the IDP. Since there is no JS in this python-requests
        # driven script, let's POST the reply ourselves to the SP
        sp_consumer_reply = self._saml_response_post(self.session,
                                                     saml_response)

        # Make sure we finally got to the URL we wanted initially
        if sp_consumer_reply.status_code != 200:
            raise SamlFlowError(sp_consumer_reply.status_code)
        logging.info(f"Reached the SP again")

        if not same_normalized_url(url, sp_consumer_reply.url):
            raise ValueError("Expected to reach a different location")
        logging.info(f"Retrieved {url} from the SP")

        # And make sure we got the contents we wanted initially
        if page_check_fn is not None and \
                page_check_fn(sp_consumer_reply.text) == False:
            raise ValueError("Expected to reach a different content")

    def logout(self, logout_page):
        """
        Run the logout profile against the SP
        """
        logout_req = self.sp_factory.logout_request(logout_page)
        logout_url = logout_req.logout_url()
        logging.debug(f"Will log using {logout_url}")
        document_get = self.session.get(logout_url)
        logout_req.check_from_reply(document_get)
        if document_get.status_code != 200:
            raise SamlFlowError(document_get.status_code)
        logging.debug(document_get.url)

    def ecp_flow(self, url, username, password, page_check_fn=None):
        if username is None or password is None:
            raise NoCredentialsError

        logging.info("Running the ECP flow")

        # Request protected resource, indicate ECP capable
        ecp_authn_req = self.session.get(url, headers=ECP_HEADERS)
        if ecp_authn_req.status_code != 200:
            raise SamlFlowError(ecp_authn_req.status_code)
        logging.debug(ecp_authn_req.url)

        authn_req_handler = self.sp_factory.authn_request()
        idp_auth_req = authn_req_handler.parse_ecp_auth_request(ecp_authn_req)

        if self.idp_factory.idp.soap_binding is None:
            raise ConfigurationError("No SOAP binding provided")

        # Post SOAP wrapped <AuthnRequest> to IdP, use Basic Auth to auth
        auth_reply = self.session.post(url=self.idp_factory.idp.soap_binding,
                                       data=idp_auth_req.msgBody,
                                       auth=(username, password),
                                       headers={'Content-Type': 'text/xml'})
        if auth_reply.status_code != 200:
            raise SamlFlowError(auth_reply.status_code)

        # Process returned SOAP wrapped <Assertion> from IdP
        idp_auth_req.processResponseMsg(auth_reply.text)

        # Post PAOS wrapped <Assertion> to SP, response is protected resource
        sp_response = self.session.post(
                        idp_auth_req.msgUrl,
                        data=idp_auth_req.msgBody,
                        headers={'Content-Type': 'application/vnd.paos+xml'})
        # Make sure we finally got to the URL we wanted initially
        if sp_response.status_code != 200:
            raise SamlFlowError(sp_response.status_code)
        logging.info(f"Reached the SP again")

        if not same_normalized_url(url, sp_response.url):
            raise ValueError("Expected to reach a different location")
        logging.info(f"Retrieved {url} from the SP")

        # And make sure we got the contents we wanted initially
        if page_check_fn is not None and \
                page_check_fn(sp_response.text) == False:
            raise ValueError("Expected to reach a different content")


def request_is_idp_auth_redirect(resource, saml_login_instance, request):
    """
    A convenience checker that returns True if request is
    a chain of redirects from a protected resource to a mellon
    handler to an IDP, False otherwise
    """
    authn_request_parser = saml_login_instance.sp_factory.authn_request()
    try:
        authn_request_parser.check_from_reply(resource, request)
    except AuthnRequestError:
        return False
    return True


def request_is_ecp_authn(saml_login_instance, request):
    authn_request_parser = saml_login_instance.sp_factory.authn_request()
    idp_auth_req = authn_request_parser.parse_ecp_auth_request(request)
    return True


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument('--idp-url', required=True)
    parser.add_argument('--idp-type', default='keycloak', choices=['keycloak'])
    parser.add_argument('--idp-realm', action='store', type=str, required=True)
    parser.add_argument('--idp-soap-binding', action='store', type=str)
    parser.add_argument('--sp-url', required=True)
    parser.add_argument('--sp-type', default='mellon', choices=['mellon'])
    parser.add_argument('--username', action='store', type=str)
    parser.add_argument('--password', action='store', type=str)
    parser.add_argument('-d', '--debug', action='count', default=0)
    parser.add_argument('--no-verify', action='store_true')

    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels)-1, args.debug)]
    logging.basicConfig(level=level)

    logging.debug("Instatiated proxy to %s IdP at %s",
                  args.idp_type, args.idp_url)

    login_test = SamlLoginTest(IdpFactory(args.idp_type, args.idp_url),
                               SpFactory(args.url, args.sp_type,
                                         args.sp_url, args.idp_url),
                               not args.no_verify)

    # Gets the page using the WebSSO flow
    logging.info(f"About to run the WebSSO flow for {args.url} with "
                  "an empty session")
    login_test.redirect_post_flow(args.url,
                                  args.username, args.password,
                                  is_my_page)

    # Let's try fetching the page again, this should just succeed with
    # one redirect to mellon
    logging.info(f"Re-using cached session")
    sp_resource = login_test.session.get(args.url)
    assert len(sp_resource.history) == 1
    if not same_normalized_url(args.url, sp_resource.url):
        raise ValueError("Expected to reach a different location")
    logging.info(f"OK, retrieved {args.url} without contacting IdP")

    # ..but not if we remove the session
    logging.info(f"Clearing the session")
    login_test.clear_session()
    sp_resource = login_test.session.get(args.url)
    assert len(sp_resource.history) == 2
    logging.info(f"OK, got redirected to IdP again")
