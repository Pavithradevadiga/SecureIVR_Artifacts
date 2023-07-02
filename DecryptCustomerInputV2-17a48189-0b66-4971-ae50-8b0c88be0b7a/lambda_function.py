#!/usr/bin/env python
import base64

import boto3
import requests
import Crypto
# from Crypto.Cipher import AES


PAD = lambda s: s + (32 - len(s) % 32) * ' '


def get_arn(aws_data):
    return 'arn:aws:kms:{region}:{account_number}:key/{key_id}'.format(**aws_data)


def encrypt_data(aws_data, plaintext_message):
    kms_client = boto3.client(
        'kms',
        region_name=aws_data['region'])

    data_key = kms_client.generate_data_key(
        KeyId=aws_data['key_id'],
        KeySpec='AES_128')

    cipher_text_blob = data_key.get('CiphertextBlob')
    plaintext_key = data_key.get('Plaintext')

    # Note, does not use IV or specify mode... for demo purposes only.
    cypher = AES.new(plaintext_key)
    encrypted_data = base64.b64encode(cypher.encrypt(PAD(plaintext_message)))

    # Need to preserve both of these data elements
    return encrypted_data, cipher_text_blob


def decrypt_data(aws_data, encrypted_data, cipher_text_blob):
    kms_client = boto3.client(
        'kms',
        region_name=aws_data['region'])

    decrypted_key = kms_client.decrypt(CiphertextBlob=cipher_text_blob).get('Plaintext')
    cypher = AES.new(decrypted_key)

    return cypher.decrypt(base64.b64decode(encrypted_data)).rstrip()


def main():
    # Add your account number / region / KMS Key ID here.
    aws_data = {
        'region': 'us-east-1',
        'account_number': '379419836112',
        'key_id': 'b9296038-f9e2-494d-b657-7202a671cb15',
    }

    # And your super secret message to envelope encrypt...
    plaintext = 'Hello, World!'

    # Store encrypted_data & cipher_text_blob in your persistent storage. You will need them both later.
    encrypted_data, cipher_text_blob = encrypt_data(aws_data, plaintext)
    print(encrypted_data)

    # # Later on when you need to decrypt, get these from your persistent storage.
    decrypted_data = decrypt_data(aws_data, encrypted_data, cipher_text_blob)
    print(decrypted_data)

if __name__ == '__main__':
    main()