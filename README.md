# New Leaders Encrypted Data Exchange


These applications are built to facilitate encrypted communication in the exchange of text data.  Remember to never share or send your private key or password to anyone.  Your public key should be the

## How to use:

Prerequisite:
- docker (https://www.docker.com/)
- jq (https://jqlang.github.io/jq/)

To run these applications you will need a modern linux / unix system.  We use docker to install all the python dependencies into a re-usable container. 
Please make sure setup and all other commands are run on the same system.
If using AWS a standard Amazon linux ec2 instance will be enough.  We recommend a minimum of a `T3 Nano` for these applications.

### Initial Setup
1. Decide if you are going to use the AWS secrets manager or file based storage for storing your secrets.
   1. If you are using the secrets manager make sure to setup your command line aws environment.  We will need to run commands to setup and read a secrets manager entry.
   2. If you are using file based storage we will store all configuration information in the directory keys. 
   Please make sure this directory is protected as it will contain all the information necessary to encrypt and decrypt.
2. On your system of choice in a terminal or command line interface.
   1. Clone the github repository and change to that directory.
    `git clone git@github.com:New-Leaders/crypto.git ; cd crypto`
3. run the setup application by typing `./setup`
   1. This will prompt you with some questions and then generate your private and public keys.
   Your public key file location or the public key will be displayed.  Send it to new leaders (helpdesk@newleaders.org).

### Encryption

After running setup simply run `./encrypt  "your secret string"`  The output from this command will be the encrypted value using your public key.

### Decryption

After running setup simply run `./decrypt  "encrypted string"`  The command should output the secret string using your private key.

### Decrypt an entire CSV
This is used when you have a file containing columns ssn and dob that are encrypted.  It will read and decrypt your file then output the file.

To have the output to the screen use the command
`./decrypt-csv encryptedfile.csv `

To have the output redirected to another file use the command 
`./decrypt-csv encryptedfile.csv  > decryptedfile.csv`
 
## Developers
To rebuild the docker container with updated code run the following
```shell
pipenv run pip freeze > requirements.txt
docker build --rm -q --platform linux/amd64 -t new_leaders_crypto .
```

To build a local envionment without docker use the following to setup a python environemnt and shell. 
```shell
pyenv install 3.11.5
pipenv install --python 3.11.5
pipenv shell
```