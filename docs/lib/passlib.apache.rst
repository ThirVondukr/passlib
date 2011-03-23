=============================================
:mod:`passlib.apache` - Apache Password Files
=============================================

.. module:: passlib.apache
    :synopsis: reading/writing htpasswd & htdigest files

This module provides utilities for reading and writing Apache's
htpasswd and htdigest files; though the use of two helper classes.

Htpasswd Files
==============
The :class:`!HTpasswdFile` class allows managing of htpasswd files.
A quick summary of it's usage::

    >>> from passlib.apache import HtpasswdFile

    >>> #when creating a new file, set to autoload=False, add entries, and save.
    >>> ht = HtpasswdFile("test.htpasswd", autoload=False)
    >>> ht.update("someuser", "really secret password")
    >>> ht.save()

    >>> #loading an existing file to update a password
    >>> ht = HtpasswdFile("test.htpasswd")
    >>> ht.update("someuser", "new secret password")
    >>> ht.save()

    >>> #examining file, verifying user's password
    >>> ht = HtpasswdFile("test.htpasswd")
    >>> ht.users()
    [ "someuser" ]
    >>> ht.verify("someuser", "wrong password")
    False
    >>> ht.verify("someuser", "new secret password")
    True

    >>> #making in-memory changes and exporting to string
    >>> ht = HtpasswdFile()
    >>> ht.update("someuser", "mypass")
    >>> ht.update("someuser", "anotherpass")
    >>> print ht.to_string()
    someuser:$apr1$T4f7D9ly$EobZDROnHblCNPCtrgh5i/
    anotheruser:$apr1$vBdPWvh1$GrhfbyGvN/7HalW5cS9XB1

.. autoclass:: HtpasswdFile(path, default=None, autoload=True)

Htdigest Files
==============
The :class:`!HtdigestFile` class allows management of htdigest files
in a similar fashion to :class:`HtpasswdFile`.

.. autoclass:: HtdigestFile(path, autoload=True)

References
==========

.. [#] Htpasswd Manual - `<http://httpd.apache.org/docs/current/programs/htpasswd.html>`_

.. [#] Apache Auth Configuration - `<http://httpd.apache.org/docs/current/howto/auth.html>`_
