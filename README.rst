RNCryptor-python
================

.. image:: https://img.shields.io/pypi/v/rncryptor.svg
    :alt: Actual PyPI version
    :target: https://pypi.python.org/pypi/rncryptor/

.. image:: https://travis-ci.org/RNCryptor/RNCryptor-python.svg?branch=master
    :target: https://travis-ci.org/RNCryptor/RNCryptor-python
    :alt: CI status

Python implementation of `RNCryptor <https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md>`_

Installation
------------

.. code-block:: bash

    $ pip install rncryptor

Usage
-----

.. code-block:: python

    import rncryptor

    data = '...'
    password = '...'

    # rncryptor.RNCryptor's methods
    cryptor = rncryptor.RNCryptor()
    encrypted_data = cryptor.encrypt(data, password)
    decrypted_data = cryptor.decrypt(encrypted_data, password)
    assert data == decrypted_data

    # rncryptor's functions
    encrypted_data = rncryptor.encrypt(data, password)
    decrypted_data = rncryptor.decrypt(encrypted_data, password)
    assert data == decrypted_data

    # encrypt_with_keys and decrypt_with keys functions
    encryption_salt = '...' # 8 random bytes
    encryption_key = rncryptor.make_key(password, encryption_salt)
    hmac_key = rncryptor.make_key(password, hmac_salt)
    encrypted_data = rncryptor.encrypt_with_keys(data, hmac_key, encryption_key)
    decrypted_data = rncryptor.decrypt_with_keys(encrypted_data, hmac_key, encryption_key)

Testing
-------

.. code-block:: bash

    $ tox
    $ tox -e py27  # test using only Python2.7
    $ tox $(nproc)  # run tests using all processes

An actual command can be found in `tox.ini <tox.ini>`_, but basically it's a common ``py.test`` with a bunch of plugins.
