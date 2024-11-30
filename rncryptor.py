"""Python implementation of RNCryptor."""
from __future__ import print_function

import hashlib
import hmac
import sys

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol import KDF

__all__ = ('RNCryptor', 'decrypt', 'encrypt')
__version__ = '3.3.0'

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY2:
    def to_bytes(s):
        if isinstance(s, str):
            return s
        if isinstance(s, unicode):
            return s.encode('utf-8')

    to_str = to_bytes

    def bchr(s):
        return chr(s)

    def bord(s):
        return ord(s)

elif PY3:
    unicode = str  # hack for pyflakes (https://bugs.launchpad.net/pyflakes/+bug/1585991)

    def to_bytes(s):
        if isinstance(s, bytes):
            return s
        if isinstance(s, str):
            return s.encode('utf-8')

    def to_str(s):
        if isinstance(s, bytes):
            return s.decode('utf-8')
        if isinstance(s, str):
            return s

    def bchr(s):
        return bytes([s])

    def bord(s):
        return s


if hasattr(hmac, 'compare_digest'):
    def compare_in_constant_time(left, right):
        return hmac.compare_digest(left, right)
else:
    def compare_in_constant_time(left, right):
        length_left = len(left)
        length_right = len(right)

        result = length_left - length_right
        for i, byte in enumerate(right):
            result |= bord(left[i % length_left]) ^ bord(byte)
        return result == 0


compare_in_constant_time.__doc__ = """\
Compare two values in time proportional to the second one.

Return True if the values are equal, False otherwise.
"""


class RNCryptorError(Exception):
    """Base error for when anything goes wrong with RNCryptor."""


class DecryptionError(RNCryptorError):
    """Raised when bad data is inputted."""


class RNCryptor(object):
    """Cryptor for RNCryptor."""

    SALT_SIZE = 8
    IV_SIZE = 16
    HMAC_SIZE = 32

    def pre_decrypt_data(self, data):
        """Handle data before decryption."""
        data = to_bytes(data)
        return data

    def post_decrypt_data(self, data):
        """Remove useless symbols which appear over padding for AES (PKCS#7)."""
        data = data[:-bord(data[-1])]
        return to_str(data)

    def decrypt(self, data, password):
        """Decrypt `data` using `password`."""
        data = self.pre_decrypt_data(data)
        password = to_bytes(password)

        n = len(data)

        # version + options + encryption_salt + hmac_salt + iv + hmac
        # = 1 + 1 + 8 + 8 + 16 + 32 = 66
        min_length = 1 + 1 + self.SALT_SIZE + self.SALT_SIZE + self.IV_SIZE + self.HMAC_SIZE

        if n < min_length:
            # data doesn't even match the required header + hmac length
            raise DecryptionError("Invalid length")

        version = data[0]
        if not version == b'\x03':
            # required version is version 3
            raise DecryptionError("Unsupported version")

        options = data[1]

        if not options == b'\x01':
            # when using keys options should be `0`
            raise DecryptionError("Invalid credential type")

        encryption_salt = data[2:10]
        hmac_salt = data[10:18]
        iv = data[18:34]
        cipher_text = data[34:n - 32]
        hmac = data[n - 32:]

        encryption_key = self._pbkdf2(password, encryption_salt)
        hmac_key = self._pbkdf2(password, hmac_salt)

        if not compare_in_constant_time(self._hmac(hmac_key, data[:n - 32]), hmac):
            raise DecryptionError("Bad data")

        decrypted_data = self._aes_decrypt(encryption_key, iv, cipher_text)

        return self.post_decrypt_data(decrypted_data)

    def decrypt_with_keys(self, data, hmac_key, encryption_key):
        """Decrypt `data` using `hmac_key` and `encryption_key`."""
        data = self.pre_decrypt_data(data)

        n = len(data)

        # version + options + iv + hmac = 1 + 1 + 16 + 32 = 50
        min_length = 1 + 1 + self.IV_SIZE + self.HMAC_SIZE

        if n < min_length:
            # data doesn't even match the required header + hmac length
            raise DecryptionError("Invalid length")

        version = data[0]

        if not version == b'\x03':
            # required version is version 3
            raise DecryptionError("Unsupported version")

        options = data[1]

        if not options == b'\x00':
            # when using keys options should be `0`
            raise DecryptionError("Invalid credential type")

        iv = data[2:18]
        cipher_text = data[18:n - 32]
        hmac = data[n - 32:]

        if not compare_in_constant_time(self._hmac(hmac_key, data[:n - 32]), hmac):
            raise DecryptionError("Bad data")

        decrypted_data = self._aes_decrypt(encryption_key, iv, cipher_text)

        return self.post_decrypt_data(decrypted_data)

    def pre_encrypt_data(self, data):
        """Do padding for the data for AES (PKCS#7)."""
        data = to_bytes(data)
        aes_block_size = AES.block_size
        rem = aes_block_size - len(data) % aes_block_size
        return data + bchr(rem) * rem

    def post_encrypt_data(self, data):
        """Handle data after encryption."""
        return data

    def encrypt(self, data, password):
        """Encrypt `data` using `password`."""
        data = self.pre_encrypt_data(data)
        password = to_bytes(password)

        encryption_salt = self.encryption_salt
        encryption_key = self._pbkdf2(password, encryption_salt)

        hmac_salt = self.hmac_salt
        hmac_key = self._pbkdf2(password, hmac_salt)

        iv = self.iv
        cipher_text = self._aes_encrypt(encryption_key, iv, data)

        version = b'\x03'
        options = b'\x01'

        new_data = b''.join([version, options, encryption_salt, hmac_salt, iv, cipher_text])
        encrypted_data = new_data + self._hmac(hmac_key, new_data)

        return self.post_encrypt_data(encrypted_data)

    def encrypt_with_keys(self, data, hmac_key, encryption_key):
        """Encrypt `data` using `hmac_key` and `encryption_key`."""
        data = self.pre_encrypt_data(data)

        iv = self.iv
        cipher_text = self._aes_encrypt(encryption_key, iv, data)

        version = b'\x03'
        options = b'\x00'

        new_data = b''.join([version, options, iv, cipher_text])
        encrypted_data = new_data + self._hmac(hmac_key, new_data)

        return self.post_encrypt_data(encrypted_data)

    def make_key(self, password, salt):
        """Derive a key via PBKDF2 from `password` using `salt`."""
        key = self._pbkdf2(password, salt)
        return key

    @property
    def encryption_salt(self):
        return Random.new().read(self.SALT_SIZE)

    @property
    def hmac_salt(self):
        return Random.new().read(self.SALT_SIZE)

    @property
    def iv(self):
        return Random.new().read(AES.block_size)

    def _aes_encrypt(self, key, iv, text):
        return AES.new(key, AES.MODE_CBC, iv).encrypt(text)

    def _aes_decrypt(self, key, iv, text):
        return AES.new(key, AES.MODE_CBC, iv).decrypt(text)

    def _hmac(self, key, data):
        return hmac.new(key, data, hashlib.sha256).digest()

    def _prf(self, secret, salt):
        return hmac.new(secret, salt, hashlib.sha1).digest()

    def _pbkdf2(self, password, salt, iterations=10000, key_length=32):
        return KDF.PBKDF2(password, salt, dkLen=key_length, count=iterations, prf=self._prf)


def decrypt(data, password):
    cryptor = RNCryptor()
    return cryptor.decrypt(data, password)


decrypt.__doc__ = RNCryptor.decrypt.__doc__


def encrypt(data, password):
    cryptor = RNCryptor()
    return cryptor.encrypt(data, password)


encrypt.__doc__ = RNCryptor.encrypt.__doc__


def encrypt_with_keys(data, hmac_key, encryption_key):
    cryptor = RNCryptor()
    return cryptor.encrypt_with_keys(data, hmac_key, encryption_key)


encrypt_with_keys.__doc__ = RNCryptor.encrypt_with_keys.__doc__


def decrypt_with_keys(data, hmac_key, encryption_key):
    cryptor = RNCryptor()
    return cryptor.decrypt_with_keys(data, hmac_key, encryption_key)


decrypt_with_keys.__doc__ = RNCryptor.decrypt_with_keys.__doc__


def make_key(password, salt):
    cryptor = RNCryptor()
    key = cryptor.make_key(password, salt)
    return key


make_key.__doc__ = RNCryptor.make_key.__doc__
