from new_leaders_crypto import Crypto
from pprint import pprint as pp
import argparse
import os
from dotenv import dotenv_values


def main():
    parser = argparse.ArgumentParser()
    # action_group = parser.add_mutually_exclusive_group(required=True)
    # action_group.add_argument("--encrypt", help="Encrypt a given string", action="store_true")
    # action_group.add_argument("--decrypt", help="Decrypt a given string", action="store_true")
    # action_group.add_argument("--decrypt_csv", help="Decrypt a csv with encrypted data in the columns dob and ssn", action="store_true")

    parser.add_argument('action', choices=['encrypt', 'decrypt', 'decrypt-csv'], help="Action to take")
    parser.add_argument('data', help="Data to use for the required action, this can be an encrypted string or a string to encrypt depending on the action chosen.")

    args = parser.parse_args()
    # pp(args)
    data = args.data
    encryption_password = ''
    secrets_arn = ''
    try:
        config = dotenv_values("keys/.env")
        encryption_password = config['NEW_LEADERS_KEY_PASS']
        secrets_arn = config['SECRETS_ARN']
    except:
        raise Exception("Error: \"keys/.env\" file is missing or corrupt.  Unable to continue until setup is run.")
    if len(secrets_arn) <=0:
        secrets_arn = None
    else:
        encryption_password = None

    crypto = Crypto(priv_key_password=encryption_password, secret_arn=secrets_arn)
    match args.action:
        case 'encrypt':
            data = data.replace('"', '').replace("'", '')
            if len(data) > 0:
                encrypted_data = crypto.encrypt(data)
                print(encrypted_data)
            else:
                print("Error: data is blank.  Please provide a string to encrypt")
        case 'decrypt':
            if len(data) > 0:
                decrypted_data = crypto.decrypt(data)
                print(decrypted_data)
            else:
                print("Error: data is blank.  Please provide a string to decrypt")

        case 'decrypt-csv':
            if len(data) > 0:
                decrypted_csv = crypto.decrypt_csv(data)
                print(decrypted_csv)
            else:
                print("Error: missing filename to read")
        case _:
            raise Exception("something is broken")


if __name__ == '__main__':
    main()
