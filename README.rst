RNCryptor-python
================

.. image:: https://travis-ci.org/RNCryptor/RNCryptor-python.svg?branch=master
    :target: https://travis-ci.org/RNCryptor/RNCryptor-python
    :alt: CI status

Python implementation of `RNCryptor <https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md>`_

Installation
------------

.. code-block:: bash

    $ pip install git+https://github.com/RNCryptor/RNCryptor-python.git#egg=rncryptor

Usage
-----

.. code-block:: python

    import rncryptor

    data = '...'
    password = '...'

    cryptor = rncryptor.RNCryptor()
    encrypted_data = cryptor.encrypt(data, password)
    decrypted_data = cryptor.decrypt(encrypted_data, password)
    assert data == decrypted_data
