==================================================================
:mod:`passlib.drivers.apr_md5_crypt` - Apache MD5-Crypt password hash
==================================================================

.. module:: passlib.drivers.apr_md5_crypt
    :synopsis: Apache MD5-Crypt variant

This format is a variation of :mod:`~passlib.drivers.md5_crypt`,
primarily used by the Apache webserver in ``htpasswd`` files.
It contains only minor changes to md5-crypt, and should
be considered just as strong / weak as md5-crypt itself.

Format & Algorithm
==================
This format is identical to md5-crypt, except for two things:
it uses ``$apr1$`` as a prefix where md5-crypt uses ``$1$``,
and inserts ``$apr1$`` where md5-crypt inserts ``$1$`` into
it's internal hash calculation. Thus, hashes generated
by this and md5-crypt are in no way compatible with eachother
(they will not even have the same checksum for the same salt).

For details about usage & algorithm, see :mod:`~passlib.drivers.md5_crypt`.

References
==========
* `<http://httpd.apache.org/docs/2.2/misc/password_encryptions.html>`_
