import os
import distro
import pytest
import logging
import subprocess

LOGGER = logging.getLogger(__name__)


def get_outfile(template):
    if template.endswith('.xml'):
        outfile = f"{template[:-4]}-output.xml"
    if os.path.exists(outfile):
        LOGGER.debug(f"File {outfile} exists, removing")
        os.remove(outfile)
    return outfile


def sign_xml_template(outfile, template, private_key):
    LOGGER.info(f"Signing document {template} using {private_key}")
    xmlsec1_sign_cmd = ['xmlsec1', '--sign', '--output', outfile,
                        '--privkey-pem', private_key, template]
    p = subprocess.Popen(xmlsec1_sign_cmd, stderr=subprocess.PIPE,
                         stdout=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = p.communicate()
    LOGGER.debug(stdout)
    LOGGER.debug(stderr)

    return p.returncode


def verify_xml_template(outfile, public_key=None, fips=False):
    LOGGER.info(f"Verifying {outfile} using the embedded public_key")
    xmlsec1_verify_cmd = ['xmlsec1', '--verify']
    if public_key != None:
        xmlsec1_verify_cmd.extend(['--pubkey-pem', public_key])
    xmlsec1_verify_cmd.append(outfile)
    cmd_env = os.environ.copy()
    if fips:
        cmd_env["OPENSSL_FORCE_FIPS_MODE"] = "1"
    LOGGER.info(f"Using env: --\n{cmd_env}\n")
    LOGGER.info(f"RUNNING: {xmlsec1_verify_cmd}")
    p = subprocess.Popen(xmlsec1_verify_cmd, stderr=subprocess.PIPE,
                         stdout=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = p.communicate()
    LOGGER.debug(stdout)
    LOGGER.debug(stderr)

    return p.returncode


def gen_key_ecdsa(private_key):
    LOGGER.info(f"Generating ECDSA private key {private_key} using openssl")
    openssl_cmd = ['openssl', 'ecparam', '-out', private_key, '-name',
                   'secp384r1', '-genkey']
    p = subprocess.Popen(openssl_cmd, stderr=subprocess.PIPE,
                         stdout=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = p.communicate()
    LOGGER.debug(stdout)
    LOGGER.debug(stderr)

    return p.returncode


def gen_pubkey_ecdsa(private_key, public_key):
    LOGGER.info(f"Generating ECDSA public key {public_key} using openssl")
    openssl_cmd = ['openssl', 'ec', '-in', private_key, '-pubout',
                   '-out', public_key]
    p = subprocess.Popen(openssl_cmd, stderr=subprocess.PIPE,
                         stdout=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = p.communicate()
    LOGGER.debug(stdout)
    LOGGER.debug(stderr)

    return p.returncode


def test_sign_and_verify_with_sha256():
    """Test you can sign and verify xml with sha-256

    :id: 856a6f12-80ff-4d05-b751-a9238774b430
    :steps:
        1. Sign xml template using sha-256
        2. Verify signed file using embedded public key
    :expectedresults:
        1. Success
        2. Success
    """
    template = "xmlsec_data/book-template-sha256.xml"
    outfile = get_outfile(template)
    private_key = "/tmp/https/tls.key"
    assert sign_xml_template(outfile, template, private_key) == 0
    assert verify_xml_template(outfile) == 0


@pytest.mark.xfail((distro.id() == "rhel" or distro.id() == "centos")
                   and int(distro.major_version()) >= 9,
                   reason="SHA1 is deprecated")
def test_sign_and_verify_with_sha1():
    """Test you can sign and verify xml with sha-1

    :id: 8ad333d6-c35f-44b1-bdd0-68e8df2be5b8
    :steps:
        1. Sign xml template using sha-1
        2. Verify signed file using embedded public key
    :expectedresults:
        1. Success
        2. Success
    """
    template = "xmlsec_data/book-template-sha1.xml"
    outfile = get_outfile(template)
    private_key = "/tmp/https/tls.key"
    assert sign_xml_template(outfile, template, private_key) == 0
    assert verify_xml_template(outfile) == 0

def test_sign_and_verify_with_ecdsa_sha384():
    """Test you can sign and verify xml with ecdsa sha386

    :id: ca201596-4663-49d3-9c4a-615a9a70aa97
    :steps:
        1. Generate ECDSA private key
        2. Derive public key from private key
        3. Sign xml template using ecdsa sha486
        4. Verify signed file using public key
    :expectedresults:
        1. Success
        2. Success
        3. Success
    """
    template = "xmlsec_data/book-template-ecdsa-sha384.xml"
    outfile = get_outfile(template)
    private_key = "/tmp/https/xmlsec_ecdsa.key"
    public_key = "/tmp/https/xmlsec_ecdsa.pub"
    assert gen_key_ecdsa(private_key) == 0
    assert gen_pubkey_ecdsa(private_key, public_key) == 0
    assert sign_xml_template(outfile, template, private_key) == 0
    assert verify_xml_template(outfile, public_key=public_key, fips=True) == 0
