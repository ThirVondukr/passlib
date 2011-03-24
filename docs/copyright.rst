=====================
Copyrights & Licenses
=====================

License for PassLib
===================
PassLib is available under the BSD license, and is (c) `Assurance Technologies <http://www.assurancetechnologies.com>`_::

    Copyright (c) 2008-2011 by Assurance Technologies, LLC.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Licenses for incorporated software
==================================
PassLib contains some code derived from the following sources:

MD5-Crypt
---------
The pure-python fallback used by :class:`passlib.hash.md5_crypt` was derived from the original
`FreeBSD md5-crypt implementation <http://www.freebsd.org/cgi/cvsweb.cgi/~checkout~/src/lib/libcrypt/crypt.c?rev=1.2>`_,
which is available under the following license::

    "THE BEER-WARE LICENSE" (Revision 42):
    <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
    can do whatever you want with this stuff. If we meet some day, and you think
    this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp

UnixCrypt.java
--------------
The DES utility functions in :mod:`passlib.utils.des` are derived
from `UnixCrypt.java <http://www.dynamic.net.au/christos/crypt/UnixCrypt2.txt>`_,
a pure-java implementation of the historic unix-crypt password hash algorithm.
Originally written by Aki Yoshida, and modified by others,
it is available under a BSD-like license::

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
