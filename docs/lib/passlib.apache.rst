=============================================
:mod:`passlib.apache` - Apache Password Files
=============================================

.. module:: passlib.apache
    :synopsis: reading/writing htpasswd & htdigest files

This module provides utilities for reading and writing Apache's
htpasswd and htdigest files; though the use of two helper classes.

.. versionchanged:: 1.6
    The api for this module was updated to be more flexible,
    and to have less ambiguous method names.
    The old method and keyword names are deprecated, and
    will be removed in Passlib 1.8.
    No more backwards-incompatible changes are currently planned
    for these classes.

.. index:: Apache; htpasswd

Htpasswd Files
==============
The :class:`!HTpasswdFile` class allows managing of htpasswd files.
A quick summary of it's usage::

    >>> from passlib.apache import HtpasswdFile

    >>> # when creating a new file, set to new=True, add entries, and save.
    >>> ht = HtpasswdFile("test.htpasswd", new=True)
    >>> ht.set_password("someuser", "really secret password")
    >>> ht.save()

    >>> # loading an existing file to update a password
    >>> ht = HtpasswdFile("test.htpasswd")
    >>> ht.set_password("someuser", "new secret password")
    >>> ht.save()

    >>> # examining file, verifying user's password
    >>> ht = HtpasswdFile("test.htpasswd")
    >>> ht.users()
    [ "someuser" ]
    >>> ht.check_password("someuser", "wrong password")
    False
    >>> ht.check_password("someuser", "new secret password")
    True

    >>> # making in-memory changes and exporting to string
    >>> ht = HtpasswdFile()
    >>> ht.set_password("someuser", "mypass")
    >>> ht.set_password("someuser", "anotherpass")
    >>> print ht.to_string()
    someuser:$apr1$T4f7D9ly$EobZDROnHblCNPCtrgh5i/
    anotheruser:$apr1$vBdPWvh1$GrhfbyGvN/7HalW5cS9XB1

.. autoclass:: HtpasswdFile(path=None, new=False, autosave=False, ...)

.. index:: Apache; htdigest

Htdigest Files
==============
The :class:`!HtdigestFile` class allows management of htdigest files
in a similar fashion to :class:`HtpasswdFile`.

.. autoclass:: HtdigestFile(path, default_realm=None, new=False, autosave=False, ...)

.. rubric:: Footnotes

.. [#] Htpasswd Manual - `<http://httpd.apache.org/docs/current/programs/htpasswd.html>`_

.. [#] Apache Auth Configuration - `<http://httpd.apache.org/docs/current/howto/auth.html>`_
