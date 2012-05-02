===============================================================
:mod:`passlib.exc` - exceptions and warnings raised by Passlib
===============================================================

.. module:: passlib.exc
    :synopsis: exceptions & warnings raised by Passlib

This module contains all the custom exceptions & warnings that
may be raised by Passlib.

Exceptions
==========
.. autoexception:: MissingBackendError

.. index::
    pair: environmental variable; PASSLIB_MAX_PASSWORD_SIZE

.. autoexception:: PasswordSizeError

Warnings
========
.. autoexception:: PasslibWarning

Minor Warnings
--------------
.. autoexception:: PasslibConfigWarning
.. autoexception:: PasslibHashWarning

Critical Warnings
-----------------
.. autoexception:: PasslibRuntimeWarning
.. autoexception:: PasslibSecurityWarning
