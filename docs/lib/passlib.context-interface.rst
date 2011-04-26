.. index:: CryptContext; interface

.. _cryptcontext-interface:

===============================================
:mod:`passlib.context` - Module Contents
===============================================

.. currentmodule:: passlib.context

This details all the constructors and methods provided by :class:`!CryptContext`
and :class:`!CryptPolicy`.

.. seealso::

    * :doc:`passlib.context-usage`

    * :doc:`passlib.context-options`

The Context Object
==================
.. autoclass:: CryptContext(schemes=None, policy=<default policy>, \*\*kwds)

The Policy Object
=================
.. autoclass:: CryptPolicy(\*\*kwds)

Other Helpers
=============
.. autoclass:: LazyCryptContext([schemes=None,] **kwds [, create_policy=None])
