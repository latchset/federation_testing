import lasso
import os.path

if __name__ == "__main__":
    dataDir = "./lasso_data"
    sp = lasso.Server(
            os.path.join(dataDir, 'sp/metadata.xml'),
            os.path.join(dataDir, 'sp/private-key.pem'))

    sp.addProvider(
            lasso.PROVIDER_ROLE_IDP,
            os.path.join(dataDir, 'idp/metadata.xml'))
    sp_login = lasso.Login(sp)
    sp_login.initAuthnRequest(None, lasso.HTTP_METHOD_REDIRECT)
    login_dump = sp_login.dump()

    print("Asserting that sha256 is used as the default signature for login requests")
    assert 'sha1' not in login_dump
    assert 'sha256' in login_dump

    print("Negative test: Asserting that sha-1 signed metadata does not load")
    try:
        sp.loadMetadata(lasso.PROVIDER_ROLE_IDP,
                        os.path.join(dataDir, 'metadata/renater-metadata.xml'),
                        os.path.join(dataDir, 'rootCA.crt'),
                        None,
                        lasso.SERVER_LOAD_METADATA_FLAG_DEFAULT)
    except:
        pass
    else:
        raise ValueError("Expected sha-1 metadata to NOT load")
