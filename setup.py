from codecs import open
from os import path
from setuptools import setup


here = path.abspath(path.dirname(__file__))


def get_long_description():
    with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
        return f.read()


setup(
    name='rncryptor',
    version='3.2.0',
    description='Python implementation of RNCryptor',
    long_description=get_long_description(),
    url='https://github.com/RNCryptor/RNCryptor-python',
    author='Yan Kalchevskiy',
    author_email='yan.kalchevskiy@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Security :: Cryptography',
    ],
    keywords='RNCryptor cryptography',
    py_modules=['rncryptor'],
    install_requires=['pycrypto>=2.5']
)
