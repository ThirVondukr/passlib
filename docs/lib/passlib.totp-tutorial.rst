.. index:: TOTP; overview
.. _totp-tutorial:

.. currentmodule:: passlib.totp

===================================
:mod:`passlib.totp` - TOTP Tutorial
===================================

Overview
========
The :mod:`passlib.totp` module provides a set of classes for adding
two-factor authentication (2FA) support into your application,
using the widely supported TOTP / HOTP specifications.

This module provides a number of classes, designed to support a variety
of use cases, including:

    * Low-level methods for calculating tokens on the client side.

    * Low-level methods for generating OTP keys & verifying tokens on the server side.

    * High level methods for server-side storage of OTP keys *along with
      state and history*, making it easy to add TOTP integration.

.. seealso:: The :mod:`passlib.totp` api reference,
    which lists all details of all the classes and methods mentioned here.

.. index:: TOTP; usage examples

.. rst-class:: emphasize-children

Tutorial / Walkthrough
======================

.. todo:: this content needs writing