"""passlib.apache - apache password support

.. todo::

    support htpasswd context

    needs ldap_sha1 support
    detect when crypt should be used, and what ones.

.. todo::
    support htdigest context

.. todo::

    support reading / writing htpasswd & htdigest files using this module.

    references -
        http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
        http://httpd.apache.org/docs/2.0/programs/htpasswd.html

    NOTE: htdigest format is md5(user ":" realm ":" passwd).hexdigest()
        file format is "user:realm:hash"
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from hashlib import md5
import logging; log = logging.getLogger(__name__)
import os
#site
#libs
from passlib.base import CryptContext
#pkg
#local
__all__ = [
]

#=========================================================
#common helpers
#=========================================================
class _CommonFile(object):
    "helper for HtpasswdFile / HtdigestFile"

    def __init__(self, path, create=False):
        self.path = path
        if create:
            self._entry_order = []
            self._entry_map = {}
            self.mtime = 0
        else:
            self.load()

    def reload(self):
        "load only if file has changed; throw error if file not found"
        if self.mtime and self.mtime == os.path.getmtime(self.path):
            return False
        self.load()
        return True

    def load(self):
        "load entries from file; throw error if file not found or malformed"
        pl = self._parse_line
        with file(self.path, "rU") as fh:
            self.mtime = os.path.getmtime(self.path)
            entry_order = self._entry_order = []
            entry_map = self._entry_map = {}
            for line in fh:
                key, value = pl(line)
                if key in entry_map:
                    #XXX: should we use data from first entry, or last entry?
                    #     going w/ first entry for now.
                    continue
                entry_order.append(key)
                entry_map[key] = value
        return True

    #subclass: _parse_line(line) -> (key, hash)

    def save(self):
        "save entries to file"
        rl = self._render_line
        entry_order = self._entry_order
        entry_map = self._entry_map
        assert len(entry_order) == len(entry_map), "internal error in entry list"
        with file(self.path, "wb") as fh:
            fh.writelines(rl(key, entry_map[key]) for key in entry_order)
            self.mtime = os.path.getmtime(self.path)

    #subclass: _render_line(entry) -> line

    def _update_key(self, key, value):
        entry_map = self._entry_map
        if key in entry_map:
            entry_map[key] = value
            return True
        else:
            self._entry_order.append(key)
            entry_map[key] = value
            return False

    def _delete_key(self, key):
        entry_map = self._entry_map
        if key in entry_map:
            del entry_map[key]
            self._entry_order.remove(key)
            return True
        else:
            return False

#=========================================================
#htpasswd editing
#=========================================================
#FIXME: apr_md5_crypt technically the default only for windows, netware and tpf.
#TODO: find out if htpasswd's "crypt" mode is crypt *call* or des_crypt implementation.
htpasswd_context = CryptContext(["apr_md5_crypt", "des_crypt", "ldap_sha1", "plaintext" ])

class HtpasswdFile(_CommonFile):
    "class for reading & writing Htpasswd files"

    def __init__(self, path, default=None, **kwds):
        self.context = htpasswd_context
        if default:
            self.context = self.context.replace(default=default)
        super(HtpasswdFile, self).__init__(path, **kwds)

    def _parse_line(self, line):
        #should be user, hash
        return line.rstrip().split(":")

    def _render_line(self, user, hash):
        return "%s:%s\n" % (user, hash)

    def update(self, user, password):
        "update entry for user; added user if needed"
        hash = self.context.encrypt(password)
        return self._update_key(user, hash)

    def delete(self, user):
        "delete any entries for specified user"
        return self._delete_key(user)

    def verify(self, user, password):
        "verify password for specified user"
        hash = self._entry_map.get(user)
        if hash is None:
            return None
        else:
            return self.context.verify(password, hash)

#=========================================================
#htdigest editing
#=========================================================

class HtdigestFile(_CommonFile):
    "class for reading & writing Htdigest files"

    def _parse_line(self, line):
        user, realm, hash = line.rstrip().split(":")
        return (user, realm), hash

    def _render_line(self, key, hash):
        return "%s:%s:%s\n" % (key[0], key[1], hash)

    def update(self, user, realm, password):
        "update entry for user+realm; added entry if needed"
        key = (user,realm)
        hash = md5("%s:%s:%s" % (user,realm,password)).hexdigest()
        return self._update_key(key, hash)

    def delete(self, user, realm):
        "delete any entries for specified user+realm"
        key = (user,realm)
        return self._delete_key(key)

    def delete_realm(self, realm):
        "delete all entries for specified realm"
        entry_order = self._entry_order
        entry_map = self._entry_map
        keys = [
            key for key in entry_map
            if key[1] == realm
        ]
        if keys:
            for key in keys:
                del entry_map[key]
                entry_order.remove(key)
            return True
        else:
            return False

    def verify(self, user, realm, password):
        "verify password for specified user+realm"
        key = (user, realm)
        hash = self._entry_map.get(key)
        if hash is None:
            return None
        return hash == md5("%s:%s:%s" % (user,realm,password)).hexdigest()

#=========================================================
# eof
#=========================================================
