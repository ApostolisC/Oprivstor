from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

import zlib
import os
import uuid

class Cryptography:
    def __init__(self):
        pass
    ##############################################################
    #### RSA METHODS
    def createRSAKeysWithPem(self):
        private,public = self.createRSAKeys()
        return (private,public,self.getPEMPublicKey(public))
    def createRSAKeys(self):
        private = self.createRSAPrivateKey()
        return (private,private.public_key())

    def createRSAPrivateKey(self):
        private_key = rsa.generate_private_key( public_exponent=65537, key_size=2048,)
        return private_key

    def createRSAPublicKey(self,private):
        return private.public_key()

    def getPrivateFromPEM(self, pem_data):
        private_key = serialization.load_pem_private_key(pem_data)
        return private_key

    def getPublicFromPEM(self, pem_data):
         public_key = serialization.load_pem_public_key(pem_data)
         return public_key

    def getPEMPrivateKey(self, key):
        pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption() )
        return pem

    def getPEMPublicKey(self, key):
        pem = key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo )
        return pem

    def encryptMessageRSA(self, message, public_key):
        ciphertext = public_key.encrypt( message, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None ) )
        return ciphertext

    def decryptMessageRSA(self, message, private_key):
        plaintext = private_key.decrypt( message, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None ) )
        return plaintext

    #### END OF RSA METHODS
    ##################################

    ##############################################################
    #### AES METHODS
    def encryptFileGCM(self, data ,key, iv, tag):
        chacha = ChaCha20Poly1305(key)
        return chacha.encrypt(nonce, data,b'')

    def decryptFileChaCha20Poly1305(self, data ,key, nonce):
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, data,b'')

    def encryptChaCha20Poly1305(self,data):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct = chacha.encrypt(nonce, data,b'')

        return ct,key,nonce

    def decryptChaCha20Poly1305(self,data,key,nonce):
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, data,b'')

    def encryptAES_GCM(self,key, iv, data):
        cipher = Cipher(algorithms.AES(key.encode()), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data)+encryptor.finalize()

        return (ct,encryptor.tag)
    def decryptAES_GCM(self, hash, iv,tag,master_passwd):
        cipher = Cipher(algorithms.AES(hash.encode()), modes.GCM(iv,tag))
        decryptor = cipher.decryptor()
        try:
            master = decryptor.update(master_passwd) + decryptor.finalize()
        except InvalidTag:
            return False # wrong user password
        return master

    #### END OF AES METHODS
    ###############################
    ##################################

    def compress(self, message):
        compress = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL,0)
        deflated=compress.compress(message)
        return deflated+compress.flush()
    def decompress(self,data):
        decompress = zlib.decompressobj(-zlib.MAX_WBITS)
        inflated = decompress.decompress(data)
        inflated += decompress.flush()
        return inflated
    def decryptMessage(self,message,private,compress=True):
        message,signature=message.split(b"0x00")

        hasher=hashlib.sha256()
        hasher.update(message)
        digest = hasher.digest()

        encrypted_message, metadata = message[0:len(message)-256],message[len(message)-256:]
        dmetadata = self.decryptMessageRSA(metadata,private)
        key,nonce = dmetadata[0:32],dmetadata[32:]
        data = self.decryptChaCha20Poly1305(encrypted_message,key,nonce)
        if compress:
            data = self.decompress(data)
        return data
    def createMessage(self, message, public_key, private_key, signature_public_key, compress=True):
        h = hashlib.sha1()
        h.update(message)

        message+=h.hexdigest().encode()


        if compress:
            message = self.compress(message)


        enc_message,key,nonce = self.encryptChaCha20Poly1305(message)

        metadata = self.encryptMessageRSA(key+nonce, public_key)

        message = enc_message+metadata
        hasher=hashlib.sha256()
        hasher.update(message)
        digest = hasher.digest()

        signature = private_key.sign(digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())


        return message+b"0x00"+signature

    def createHash(self, password,salt=None):
        if not salt:salt = uuid.uuid4().hex
        ph = PasswordHasher()
        hash = ph.hash(password)
        return hash

    def validateHash(self, hash,password):
        ph = PasswordHasher()
        try:
            ph.verify(hash, password)
            return True
        except VerifyMismatchError:
            return False
