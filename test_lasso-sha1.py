import lasso
import distro
import pytest
import os.path
import logging

pytestmark = pytest.mark.xfail(distro.name() == "Red Hat Enterprise Linux"
                               and distro.version() < '9',
                               reason="SHA1 is deprecated in later versions of RHEL")

LOGGER = logging.getLogger(__name__)

dataDir = "./lasso_data"


@pytest.fixture
def lasso_server():
    sp = lasso.Server(
        os.path.join(dataDir, 'sp/metadata.xml'),
        os.path.join(dataDir, 'sp/private-key.pem'))
    return sp


@pytest.fixture
def sp_login(lasso_server):
    sp = lasso_server
    sp.addProvider(
        lasso.PROVIDER_ROLE_IDP,
        os.path.join(dataDir, 'idp/metadata.xml'))
    sp_login = lasso.Login(sp)
    sp_login.initAuthnRequest(None, lasso.HTTP_METHOD_REDIRECT)
    return sp_login


def test_sha256_is_used_as_the_default_signature(sp_login):
    """Test sha256 is used as the default signature

    :id: 69b5ae42-2815-4ff5-9641-253be6c87d5a
    :steps:
        1. Dump server content to an XML string
        2. Check that sha1 is not present in the XML string
        3. Check that sha256 is present in the XML string
    :expectedresults:
        1. Success
        2. sha1 is not present
        3. sha256 is present
    """
    login_dump = sp_login.dump()

    LOGGER.info(
        "Asserting that sha256 is used as the default signature for login requests")
    assert 'sha1' not in login_dump
    assert 'sha256' in login_dump


def test_sha1_signed_metadata_does_not_load(lasso_server):
    """Test that sha1-signed metadata does not load

    :id: 526697f9-3914-45ff-aa3e-ffd8160f9911
    :steps:
        1. Try to load xml file that contains sha1-signed metadata
    :expectedresults:
        1. An exception is raised
    """
    sp = lasso_server
    LOGGER.info(
        "Negative test: Asserting that sha-1 signed metadata does not load")
    # lasso_server_load_metadata() retuns 0 on success, an error code otherwise
    # https://doc.entrouvert.org/lasso/stable/lasso-LassoServer.html#lasso-server-load-metadata
    # When metadata is not loaded, we get
    # >       rc = _lasso.server_load_metadata(self._cptr, role, str2lasso(federation_file), str2lasso(trusted_roots), blacklisted_entity_ids, _loaded_entity_ids_out, flags)
    # E       SystemError: <built-in function server_load_metadata> returned NULL without setting an error
    # So we expect SystemError to be raised when sha-1 signed metadata is loaded.
    with pytest.raises(SystemError):
        sp.loadMetadata(lasso.PROVIDER_ROLE_IDP,
                        os.path.join(dataDir, 'metadata/renater-metadata.xml'),
                        os.path.join(dataDir, 'rootCA.crt'),
                        None,
                        lasso.SERVER_LOAD_METADATA_FLAG_DEFAULT)
