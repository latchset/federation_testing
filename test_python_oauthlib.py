import sys
import pytest
import distro

import oauthlib
from oauthlib.oauth1 import Client

private_key = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDk1/bxy"
    "S8Q8jiheHeYYp/4rEKJopeQRRKKpZI4s5i+UPwVpupG\nAlwXWfzXw"
    "SMaKPAoKJNdu7tqKRniqst5uoHXw98gj0x7zamu0Ck1LtQ4c7pFMVa"
    "h\n5IYGhBi2E9ycNS329W27nJPWNCbESTu7snVlG8V8mfvGGg3xNjT"
    "MO7IdrwIDAQAB\nAoGBAOQ2KuH8S5+OrsL4K+wfjoCi6MfxCUyqVU9"
    "GxocdM1m30WyWRFMEz2nKJ8fR\np3vTD4w8yplTOhcoXdQZl0kRoaD"
    "zrcYkm2VvJtQRrX7dKFT8dR8D/Tr7dNQLOXfC\nDY6xveQczE7qt7V"
    "k7lp4FqmxBsaaEuokt78pOOjywZoInjZhAkEA9wz3zoZNT0/i\nrf6"
    "qv2qTIeieUB035N3dyw6f1BGSWYaXSuerDCD/J1qZbAPKKhyHZbVaw"
    "Ft3UMhe\n542UftBaxQJBAO0iJy1I8GQjGnS7B3yvyH3CcLYGy296+"
    "XO/2xKp/d/ty1OIeovx\nC60pLNwuFNF3z9d2GVQAdoQ89hUkOtjZL"
    "eMCQQD0JO6oPHUeUjYT+T7ImAv7UKVT\nSuy30sKjLzqoGw1kR+wv7"
    "C5PeDRvscs4wa4CW9s6mjSrMDkDrmCLuJDtmf55AkEA\nkmaMg2PNr"
    "jUR51F0zOEFycaaqXbGcFwe1/xx9zLmHzMDXd4bsnwt9kk+fe0hQzV"
    "S\nJzatanQit3+feev1PN3QewJAWv4RZeavEUhKv+kLe95Yd0su7lT"
    "LVduVgh4v5yLT\nGa6FHdjGPcfajt+nrpB1n8UQBEH9ZxniokR/IPv"
    "dMlxqXA==\n-----END RSA PRIVATE KEY-----"
)

class TestNoSha1:
    def get_client(self, signature_method):
        return Client('client_key',
                      signature_method=signature_method,
                      rsa_key=private_key,
                      timestamp='1234567890',
                      nonce='abc')

    def sign(self, client):
        client.sign('http://example.com')

    @pytest.mark.xfail((distro.id() == "rhel" or distro.id() == "centos")
                       and int(distro.major_version()) >= 9,
                       reason="SHA1 is deprecated")
    def test_sign_hmac_sha1_ok(self):
        """Test signing with HMAC-SHA1 signature

        :id: 95306a6e-0710-4336-ab7c-a13aae501e58
        :steps:
            1. Check that HMAC-SHA1 signature works
        :expectedresults:
            1. Success
        """
        self.sign(self.get_client('HMAC-SHA1'))

    def test_sign_hmac_sha256_ok(self):
        """Test signing with HMAC-SHA256 signature

        :id: 3928f8e4-65f7-4d38-80c2-6ec86b529009
        :steps:
            1. Check that HMAC-SHA256 signature works
        :expectedresults:
            1. Success
        """
        self.sign(self.get_client('HMAC-SHA256'))

    @pytest.mark.xfail((distro.id() == "rhel" or distro.id() == "centos")
                       and int(distro.major_version()) > 9,
                       reason="SHA1 is deprecated")
    def test_sign_rsa_sha1_not_permitted(self):
        """Test signing with RSA-SHA1 signature

        :id: c86141f0-c9f2-40cc-851a-b3df13e20565
        :steps:
            1. Check that RSA-SHA1 signature is not allowed and an error is thrown
        :expectedresults:
            1. Should receive an error that RSA-SHA1 is deprecated
        """
        exp_error = 'RSA-SHA1 is deprecated, use a stronger hash or HMAC-SHA1'
        with pytest.raises(ValueError) as e_info:
            self.sign(self.get_client('RSA-SHA1'))
        assert e_info.value.args[0] == exp_error
