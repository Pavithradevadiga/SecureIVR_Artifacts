'''
Requires these modules
    pip install aws-encryption-sdk --target .
    pip install cryptography --target .
'''
import boto3
import base64
import aws_encryption_sdk
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider, WrappingKey
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm

ssm = boto3.client('ssm')

PARAM_PRIVATE_KEY = 'CONNECT_INPUT_DECRYPTION_KEY'
PARAM_KEY_ID = 'CONNECT_INPUT_KEY_ID'

class ConnectDecryption(RawMasterKeyProvider):
    provider_id = "AmazonConnect"

    def __init__(self, **kwargs):
        self._static_keys = {}
        
    def _get_raw_key(self, key_id):
        self._static_keys[key_id] = self._privateKey

        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA512_MGF1,
            wrapping_key=self._privateKey,
            wrapping_key_type=EncryptionKeyType.PRIVATE
        )
    
    def setPrivateKey(self, key):
        self._privateKey = key

def lambda_handler(event, context):
    # print (event)
    
    encryptedText64 = event['Details']['ContactData']['Attributes']['EncryptedCreditCard']
    encryptedText = base64.b64decode(encryptedText64)

    response = ssm.get_parameter(
        Name = PARAM_PRIVATE_KEY,
        WithDecryption = True
    )
    privateKey = response['Parameter']['Value']
    privateKeyBytes = bytearray(privateKey, 'utf8')
    
    response = ssm.get_parameter(
        Name = PARAM_KEY_ID,
        WithDecryption = True
    )
    keyId = response['Parameter']['Value']
    
    masterKeyProvider = ConnectDecryption()
    masterKeyProvider.setPrivateKey(privateKeyBytes)
    masterKeyProvider.add_master_key(keyId)
    
    plainTextBytes, decryptedHeader = aws_encryption_sdk.decrypt(
        source=encryptedText,
        key_provider=masterKeyProvider
    )
    plainText = plainTextBytes.decode('utf-8')
    
    print ('The value entered is ' + plainText)
    
    return {
        'statusCode': 200,
        'body': plainText
    }