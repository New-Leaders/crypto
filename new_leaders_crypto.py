from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import os
import base64
import boto3
import json
from botocore.exceptions import ClientError
from pprint import pprint as pp
import csv
import pandas as pd


class Crypto:
    def __init__(self,priv_key_password, secret_arn=None, priv_key_filename=None, pub_key_filename=None):
        if priv_key_password is None and secret_arn is None:
            raise Exception(f"priv_key_password is missing.")
        else:
            self.priv_key_password = priv_key_password

        if secret_arn is None:
            if priv_key_filename is None:
                self.priv_key_filename = 'keys/key.priv'
            else:
                self.priv_key_filename = priv_key_filename
            if pub_key_filename is None:
                self.pub_key_filename = 'keys/key.pub'
            else:
                self.pub_key_filename = pub_key_filename

            priv_key_file_exists = self.file_exists_with_data(self.priv_key_filename)
            pub_key_file_exists = self.file_exists_with_data(self.pub_key_filename)
            if priv_key_file_exists and not pub_key_file_exists:
                print("Found private key but not public key.  You will only be able to decrypt with this library")
                self.private_key = self.load_priv_key()
            elif not priv_key_file_exists and pub_key_file_exists:
                print("Found public key but not private key.  You will only be able to encrypt with this library")
                self.public_key = self.load_public_key()
            elif not priv_key_file_exists and not pub_key_file_exists:
                private_key = self.generate_key_pair()
                self.write_keys_to_file(private_key=private_key)
                self.private_key = self.load_priv_key()
                self.public_key = self.load_public_key()
            else:
                self.private_key = self.load_priv_key()
                self.public_key = self.load_public_key()

        else:
            self.secret_arn = secret_arn

            secret = self._get_secrets_manger_secret()
            if 'private_key' not in secret or 'password' not in secret:
                print('no secrets manager key was found, Creating')
                private_key = self.generate_key_pair()
                secret = self.write_keys_to_secrets_manager(private_key=private_key)
            else:
                secret = self._get_secrets_manger_secret()

            self.priv_key_password = secret['password']
            encrypted_private_key = base64.b64decode(secret['private_key'])
            public_key = base64.b64decode(secret['public_key'])
            self.private_key = self.load_priv_key(encrypted_key_string=encrypted_private_key)
            self.public_key = self.load_public_key(key_string=public_key)
    def file_exists_with_data(self,filename):
        if os.path.isfile(filename):
            if os.stat(filename).st_size != 0:
                return True
        return False
    def _get_secrets_manger_secret(self):

        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(service_name="secretsmanager")

        try:
            get_secret_value_response = client.get_secret_value(SecretId=self.secret_arn)
        except ClientError as e:
            # For a list of exceptions thrown, see
            # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
            raise e

        # Decrypts secret using the associated KMS key.
        return json.loads(get_secret_value_response["SecretString"])
    def write_keys_to_secrets_manager(self,private_key):
        session = boto3.session.Session()
        client = session.client(service_name="secretsmanager")

        encrypted_pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.priv_key_password.encode())
        )
        pem_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        secret_value_str = json.dumps(
            {
                "private_key": base64.b64encode(encrypted_pem_private_key).decode(),
                "public_key": base64.b64encode(pem_public_key).decode(),
                "password": self.priv_key_password,
            }
        )

        # Store the secret in AWS Secrets Manager
        response = client.update_secret(
            SecretId=self.secret_arn, SecretString=secret_value_str
        )
        return json.loads(secret_value_str)
    def write_keys_to_file(self,private_key):
        if self.file_exists_with_data(self.priv_key_filename):
            raise Exception(f"Private Key file {self.priv_key_filename} exists and either needs to be removed or renamed to generate a new key file pair.")

        if self.file_exists_with_data(self.pub_key_filename):
            raise Exception(f"Public Key file {self.pub_key_filename} exists and either needs to be removed or renamed to generate a new key file pair.")

        encrypted_pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.priv_key_password.encode())
        )
        with open(self.priv_key_filename, "wb") as file:
            file.write(encrypted_pem_private_key)

        pem_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.pub_key_filename, "wb") as file:
            file.write(pem_public_key)
    def generate_key_pair(self):

        # Generate the RSA private key with acceptable key size.
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        return private_key

    def load_priv_key(self, encrypted_key_string=None):
        if encrypted_key_string is None:
            with open(self.priv_key_filename, 'rb') as pem_in:
                encrypted_key_string = pem_in.read()

        private_key = load_pem_private_key(encrypted_key_string, self.priv_key_password.encode())
        return private_key

    def load_public_key(self, key_string=None):
        if key_string is None:
            with open(self.pub_key_filename, 'rb') as pem_in:
                key_string = pem_in.read()
        public_key = load_pem_public_key(key_string)
        return public_key

    def decrypt(self, encrypted_base64_string):
        if encrypted_base64_string is None:
            return ''
        encrypted_string = base64.b64decode(encrypted_base64_string)

        plaintext = self.private_key.decrypt(
            encrypted_string,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    def decrypt_csv(self,filename):
        if self.file_exists_with_data(filename=filename):
            df = pd.read_csv(filepath_or_buffer=filename)
            if 'SSN' in df.columns:
                df['SSN'] = df['SSN'].apply(self.decrypt)
            if 'DOB' in df.columns:
                df['DOB'] = df['DOB'].apply(self.decrypt)
            return df.to_csv(index=False, quoting=csv.QUOTE_ALL)


        else:
            raise Exception(f"ERROR: {filename} does not exist or is blank")
    def encrypt(self, secret_string):
        if secret_string is None:
            return ''
        # public_key = self.load_public_key()
        message = secret_string.encode()
        ciphertext = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
