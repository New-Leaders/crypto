import unittest
from new_leaders_crypto import Crypto
import tempfile
import secrets

class testCrypto(unittest.TestCase):

    def test_keyfile_based_storage(self):
        password = secrets.token_urlsafe(32)
        priv_key_tempfile = tempfile.NamedTemporaryFile()
        pub_key_tempfile = tempfile.NamedTemporaryFile()
        priv_key_file_name = priv_key_tempfile.name
        pub_key_file_name = pub_key_tempfile.name
        crypt = Crypto(priv_key_password=password,priv_key_filename=priv_key_file_name,pub_key_filename=pub_key_file_name)
        secret_text = 'this is an example on how to use the file / key based storage'
        encrypted_secret = crypt.encrypt(secret_text)
        decrypted_secret_text = crypt.decrypt(encrypted_secret)
        self.assertEqual(secret_text, decrypted_secret_text)
        priv_key_tempfile.close()
        pub_key_tempfile.close()

    def test_secrets_manger_storage(self):
        password = secrets.token_urlsafe(32)
        crypt = Crypto(priv_key_password=password, secret_arn='arn:aws:secretsmanager:us-east-2:640772605323:secret:test/crypto-p7lSES')

        secret_text = 'this is an example of how the secrets manager parameter is specified'
        encrypted_secret = crypt.encrypt(secret_text)
        decrypted_secret_text = crypt.decrypt(encrypted_secret)

        self.assertEqual(secret_text, decrypted_secret_text)


if __name__ == '__main__':
    unittest.main()
