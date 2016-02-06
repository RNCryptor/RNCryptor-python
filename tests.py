# coding: utf-8
import rncryptor

import pytest


DATA = (
    'test',
    'текст',
    '',
    '1' * 16,
    '2' * 15,
    '3' * 17,
)
PASSWORD_DATA = (
    'p@s$VV0Rd',
    'пароль',
)


@pytest.mark.parametrize('data', DATA)
@pytest.mark.parametrize('password', PASSWORD_DATA)
def test_encrypt_decrypt_should_be_correct(data, password):
    cryptor = rncryptor.RNCryptor()
    encrypted_data = cryptor.encrypt(data, password)
    decrypted_data = cryptor.decrypt(encrypted_data, password)
    assert data == decrypted_data
