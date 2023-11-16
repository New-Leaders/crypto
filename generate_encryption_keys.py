from new_leaders_crypto import Crypto
import random
import string
import os
# import getpass
import secrets
import argparse
import boto3
import json
from botocore.exceptions import ClientError


def confirm():
    answer = ""
    while answer not in ["y", "n"]:
        answer = input("Would you like to remove your New Leaders crypto encryption keys (if they exist) and generate new ones (only New Leaders keys will be affected) [Y/N]? ").lower()
    return answer == "y"
def get_secrets_manger_secret(secret_arn):

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager")

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_arn)
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    return json.loads(get_secret_value_response["SecretString"])

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets-manager-arn",help="AWS Secrets Manager arn to generate keys for", required=False)
    args = parser.parse_args()

    key_password = secrets.token_urlsafe(32)

    key_input = input('Please type a password to use to encrypt the private key, if you do not type one and press enter one will be generated: ')

    if key_input == '':
        print(f"No input received we are using the randomly generated password.")
    else:
        key_password = key_input

    if confirm():

        if args.secrets_manager_arn is None:
            priv_key_filename = 'keys/key.priv'
            if os.path.exists(priv_key_filename):
                os.remove(priv_key_filename)
            pub_key_filename = 'keys/key.pub'
            if os.path.exists(pub_key_filename):
                os.remove(pub_key_filename)
            dotenv_filename = "keys/.env"
            if os.path.exists(dotenv_filename):
                os.remove(dotenv_filename)
            with open(dotenv_filename, "w") as f:
                f.write(f"NEW_LEADERS_KEY_PASS={key_password}\nSECRETS_ARN=")

            crypto = Crypto(priv_key_password=key_password, priv_key_filename=priv_key_filename, pub_key_filename=pub_key_filename)
            print(f"Your private key is located in {crypto.priv_key_filename}")
            print(f"Your public key is located in {crypto.pub_key_filename}")
            print(f"Your decryption key password is written to the \"{dotenv_filename}\" file for easy use by these applications.")
            print("Remember to never share your private key or password with ANYONE. New Leaders will never ask you for anything but the public key.")
            print(f"New Leaders will need your PUBLIC key to encrypt your data.  Please send the file {crypto.pub_key_filename} to helpdesk@newleaders.org")
        else:
            dotenv_filename = "keys/.env"
            if os.path.exists(dotenv_filename):
                os.remove(dotenv_filename)
            with open(dotenv_filename, "w") as f:
                f.write(f"NEW_LEADERS_KEY_PASS=\nSECRETS_ARN={args.secrets_manager_arn}")
            print(f" usingpw {key_password} and  arn {args.secrets_manager_arn}")
            crypto = Crypto(priv_key_password=key_password, secret_arn=args.secrets_manager_arn)
            # crypto.generate_key_pair()
            print(f"AWS secrets manager entry with ARN {args.secrets_manager_arn} updated with generated secrets")
            print("Remember to never share your private key or password with ANYONE. New Leaders will never ask you for anything but the public key.")
            public_key = get_secrets_manger_secret(secret_arn=args.secrets_manager_arn)['public_key']
            print(f"Your public key is: {public_key}")
            print(f"New Leaders will need your PUBLIC key to encrypt your data.  Please this public key to helpdesk@newleaders.org")

    else:
        print("Nothing done.")


if __name__ == '__main__':
    main()
