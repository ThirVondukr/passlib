=============================================
:mod:`passlib.utils.des` - DES routines
=============================================

.. module:: passlib.utils.des
    :synopsis: routines for performing DES encryption

.. warning::

    NIST has declared DES to be "inadequate" for encryption purpose.
    These routines, and algorithms based on them,
    should not be used in new applications.

This module contains routines for encrypting blocks of data using the DES algorithm.

They do not support multi-block operation or decryption,
since they are designed for use in password hash algorithms
such as :mod:`~passlib.hash.des_crypt` and :mod:`~passlib.hash.ext_des_crypt`.

.. autofunction:: expand_des_key
.. autofunction:: des_encrypt_block
.. autofunction:: mdes_encrypt_int_block
