=====================
Copyrights & Licenses
=====================

Copyright
=========
The PassLib library is (c) 2008-2011 `Assurance Technologies, LLC <http://www.assurancetechnologies.com>`_,
excepting any code noted below as taken from :ref:`third party sources <third-party-software>`.
Such portions are copyright their respective owners.

License
=======
This library is released under the BSD license; we hope you find it useful.

::

    The PassLib Python Library

    Copyright (c) 2008-2011 Assurance Technologies, LLC

    Permission to use, copy, modify, and distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

.. _third-party-software:

Third Party Software
====================
PassLib contains some code taken from various third-party sources, which have their
own licenses (all of which, it should be noted, are BSD-compatible).
The following is a list of these sources, their owners, licenses, and the parts
of PassLib derived from them.

jBcrypt
-------
`jBCrypt <http://www.mindrot.org/projects/jBCrypt/>`_ is a pure-java
implementation of OpenBSD's BCrypt algorithm, written by Damien Miller,
and released under a BSD license.

:mod:`passlib.utils._slow_bcrypt` is a python translation of this code,
which is used as a fallback backend for :mod:`passlib.hash.bCrypt`
when the external python library `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_
is not installed.

This is the license and copyright for jBCrypt::

    Copyright (c) 2006 Damien Miller <djm@mindrot.org>

    Permission to use, copy, modify, and distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

MD5-Crypt
---------
The fallback pure-python implementation contained in :mod:`passlib.hash.md5_crypt`
was derived from the
`FreeBSD md5-crypt <http://www.freebsd.org/cgi/cvsweb.cgi/~checkout~/src/lib/libcrypt/crypt.c?rev=1.2>`_,
implementation which was released under the following license::

    "THE BEER-WARE LICENSE" (Revision 42):
    <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
    can do whatever you want with this stuff. If we meet some day, and you think
    this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp

UnixCrypt.java
--------------
`UnixCrypt.java <http://www.dynamic.net.au/christos/crypt/UnixCrypt2.txt>`_
is a pure-java implementation of the historic unix-crypt password hash algorithm.
Originally written by Aki Yoshida, and modified by others,
it was released under a BSD-like license.

The DES utility functions in :mod:`passlib.utils.des` are a descendant of
this code, after being translated into python. (These are used for des-crypt,
ext-des-crypt, and nthash support).

This is the license and copyright for UnixCrypt.java::

    UnixCrypt.java	0.9 96/11/25
    Copyright (c) 1996 Aki Yoshida. All rights reserved.
    Permission to use, copy, modify and distribute this software
    for non-commercial or commercial purposes and without fee is
    hereby granted provided that this copyright notice appears in
    all copies.

    modified April 2001
    by Iris Van den Broeke, Daniel Deville

    modified Aug 2005
    by Greg Wilkins (gregw)
