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
