# coding: utf-8
import pytest

import rncryptor

DATA = (
    'test',
    'текст',
    '',
    '1' * 16,
    '2' * 15,
    '3' * 17,
)
BAD_DATA = (
    'x' * 100,
    'y' * 100,
)
PASSWORD_DATA = (
    'p@s$VV0Rd',
    'пароль',
)
ENCRYPTION_SALT = (
    'lPVVIl6Z',
    'TSDTe9c6',
)
HMAC_SALT = (
    'gtLVYm0F',
    'lMqCcaJw',
)


@pytest.mark.parametrize('data', DATA)
@pytest.mark.parametrize('password', PASSWORD_DATA)
def test_encrypt_decrypt_methods_should_be_correct(data, password):
    cryptor = rncryptor.RNCryptor()
    encrypted_data = cryptor.encrypt(data, password)
    decrypted_data = cryptor.decrypt(encrypted_data, password)
    assert data == decrypted_data


@pytest.mark.parametrize('data', DATA)
@pytest.mark.parametrize('password', PASSWORD_DATA)
def test_encrypt_decrypt_functions_should_be_correct(data, password):
    encrypted_data = rncryptor.encrypt(data, password)
    decrypted_data = rncryptor.decrypt(encrypted_data, password)
    assert data == decrypted_data


@pytest.mark.parametrize('data', BAD_DATA)
@pytest.mark.parametrize('password', PASSWORD_DATA)
def test_decryption_bad_data_should_raise_exception(data, password):
    with pytest.raises(rncryptor.DecryptionError):
        rncryptor.decrypt(data, password)


@pytest.mark.parametrize('encryption_salt', ENCRYPTION_SALT)
@pytest.mark.parametrize('hmac_salt', HMAC_SALT)
@pytest.mark.parametrize('data', DATA)
@pytest.mark.parametrize('password', PASSWORD_DATA)
def test_enc_dec_with_keys_methods_should_be_correct(encryption_salt, hmac_salt, data, password):
    cryptor = rncryptor.RNCryptor()
    encryption_key = cryptor.make_key(password, encryption_salt)
    hmac_key = cryptor.make_key(password, hmac_salt)
    encrypted_data = cryptor.encrypt_with_keys(data, hmac_key, encryption_key)
    decrypted_data = cryptor.decrypt_with_keys(encrypted_data, hmac_key, encryption_key)
    assert data == decrypted_data


@pytest.mark.parametrize('encryption_salt', ENCRYPTION_SALT)
@pytest.mark.parametrize('hmac_salt', HMAC_SALT)
@pytest.mark.parametrize('data', DATA)
@pytest.mark.parametrize('password', PASSWORD_DATA)
def test_enc_dec_with_keys_functions_should_be_correct(encryption_salt, hmac_salt, data, password):
    encryption_key = rncryptor.make_key(password, encryption_salt)
    hmac_key = rncryptor.make_key(password, hmac_salt)
    encrypted_data = rncryptor.encrypt_with_keys(data, hmac_key, encryption_key)
    decrypted_data = rncryptor.decrypt_with_keys(encrypted_data, hmac_key, encryption_key)
    assert data == decrypted_data


@pytest.mark.parametrize('encryption_salt', ENCRYPTION_SALT)
@pytest.mark.parametrize('hmac_salt', HMAC_SALT)
@pytest.mark.parametrize('data', DATA)
@pytest.mark.parametrize('password', PASSWORD_DATA)
def test_enc_keys_dec_pass_func_should_raise_exception(encryption_salt, hmac_salt, data, password):
    # test encryption with keys and decryption with password. should because of the header mismatch.
    # should raise an error because of the header mismatch.
    encryption_key = rncryptor.make_key(password, encryption_salt)
    hmac_key = rncryptor.make_key(password, hmac_salt)
    encrypted_data = rncryptor.encrypt_with_keys(data, hmac_key, encryption_key)
    with pytest.raises(rncryptor.DecryptionError) as exception:
        rncryptor.decrypt(encrypted_data, password)
    assert str(exception.value) == 'Invalid credential type'


@pytest.mark.parametrize('encryption_salt', ENCRYPTION_SALT)
@pytest.mark.parametrize('hmac_salt', HMAC_SALT)
@pytest.mark.parametrize('data', DATA)
@pytest.mark.parametrize('password', PASSWORD_DATA)
def test_enc_pass_dec_keys_func_should_raise_exception(encryption_salt, hmac_salt, data, password):
    # test encryption with password and decryption with keys.
    # should raise an error because of the header mismatch.
    encryption_key = rncryptor.make_key(password, encryption_salt)
    hmac_key = rncryptor.make_key(password, hmac_salt)
    encrypted_data = rncryptor.encrypt(data, password)
    with pytest.raises(rncryptor.DecryptionError) as exception:
        rncryptor.decrypt_with_keys(encrypted_data, hmac_key, encryption_key)
    assert str(exception.value) == 'Invalid credential type'


@pytest.mark.parametrize('password', PASSWORD_DATA)
def test_decryption_short_header_should_raise_exception(password):
    plaintext = "Test string"
    data = rncryptor.encrypt(plaintext, password)

    # minimum length is 66 bytes
    data = data[0:65]

    with pytest.raises(rncryptor.DecryptionError) as exception:
        rncryptor.decrypt(data, password)

    assert str(exception.value) == 'Invalid length'


@pytest.mark.parametrize('password', PASSWORD_DATA)
@pytest.mark.parametrize('enc_salt', ENCRYPTION_SALT)
@pytest.mark.parametrize('hmac_salt', HMAC_SALT)
def test_dec_with_keys_short_header_should_raise_exception(password, enc_salt, hmac_salt):

    encryption_key = rncryptor.make_key(password, enc_salt)
    hmac_key = rncryptor.make_key(password, hmac_salt)

    plaintext = "Test string"
    data = rncryptor.encrypt_with_keys(plaintext, hmac_key, encryption_key)

    # minimum length is 50 bytes
    data = data[0:49]

    with pytest.raises(rncryptor.DecryptionError) as exception:
        rncryptor.decrypt_with_keys(data, hmac_key, encryption_key)

    assert str(exception.value) == 'Invalid length'
