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
from passlib.context import CryptContext
#pkg
#local
__all__ = [
]

#=========================================================
#common helpers
#=========================================================
class _CommonFile(object):
    "helper for HtpasswdFile / HtdigestFile"

    #NOTE: 'path' is a property so that mtime is wiped if path is changed.
    _path = None
    def _get_path(self):
        return self._path
    def _set_path(self, path):
        if path != self._path:
            self.mtime = 0
        self._path = path
    path = property(_get_path, _set_path)

    def __init__(self, path=None, autoload=True):
        self.path = path
        ##if autoload == "exists":
        ##    autoload = bool(path and os.path.exists(path))
        if autoload and path:
            self.load()
        ##elif raw:
        ##    self._load_lines(raw.split("\n"))
        else:
            self._entry_order = []
            self._entry_map = {}

    def load(self, force=True):
        """load entries from file

        :param force:
            if ``True`` (the default), always loads state from file.
            if ``False``, only loads state if file has been modified since last load.

        :raises IOError: if file not found

        :returns: ``False`` if ``force=False`` and no load performed; otherwise ``True``.
        """
        path = self.path
        if not path:
            raise RuntimeError, "no load path specified"
        if not force and self.mtime and self.mtime == os.path.getmtime(path):
            return False
        with file(path, "rU") as fh:
            self.mtime = os.path.getmtime(path)
            self._load_lines(fh)
        return True

    def _load_lines(self, lines):
        pl = self._parse_line
        entry_order = self._entry_order = []
        entry_map = self._entry_map = {}
        for line in lines:
            key, value = pl(line)
            if key in entry_map:
                #XXX: should we use data from first entry, or last entry?
                #     going w/ first entry for now.
                continue
            entry_order.append(key)
            entry_map[key] = value

    #subclass: _parse_line(line) -> (key, hash)

    def save(self):
        "save entries to file"
        if not self.path:
            raise RuntimeError, "no save path specified"
        rl = self._render_line
        entry_order = self._entry_order
        entry_map = self._entry_map
        assert len(entry_order) == len(entry_map), "internal error in entry list"
        with file(self.path, "wb") as fh:
            fh.writelines(rl(key, entry_map[key]) for key in entry_order)
        self.mtime = os.path.getmtime(self.path)

    def to_string(self):
        "export whole database as a string"
        rl = self._render_line
        entry_order = self._entry_order
        entry_map = self._entry_map
        assert len(entry_order) == len(entry_map), "internal error in entry list"
        return "".join(rl(key, entry_map[key]) for key in entry_order)

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

    invalid_chars = ":\n\r\t\x00"

    def _validate_user(self, user):
        if len(user) > 255:
            raise ValueError, "user must be at most 255 characters: %r" % (user,)
        ic = self.invalid_chars
        if any(c in ic for c in user):
            raise ValueError, "user contains invalid characters: %r" % (user,)
        return True

    def _validate_realm(self, realm):
        if len(realm) > 255:
            raise ValueError, "realm must be at most 255 characters: %r" % (realm,)
        ic = self.invalid_chars
        if any(c in ic for c in realm):
            raise ValueError, "realm contains invalid characters: %r" % (realm,)
        return True

    #FIXME: htpasswd doc sez passwords limited to 255 chars under Windows & MPE,
    # longer ones are truncated.

#=========================================================
#htpasswd editing
#=========================================================
#FIXME: apr_md5_crypt technically the default only for windows, netware and tpf.
#TODO: find out if htpasswd's "crypt" mode is crypt *call* or just des_crypt implementation.
htpasswd_context = CryptContext([
    "apr_md5_crypt", #man page notes supported everywhere, default on Windows, Netware, TPF
    "des_crypt", #man page notes server does NOT support this on Windows, Netware, TPF
    "ldap_sha1", #man page notes only for transitioning <-> ldap
    "plaintext" # man page notes server ONLY supports this on Windows, Netware, TPF
    ])

class HtpasswdFile(_CommonFile):
    """class for reading & writing Htpasswd files.

    :arg path: path to htpasswd file to load from / save to (required)

    :param default:
       optionally specify default scheme to use when encoding new passwords.

       Must be one of ``None``, ``"apr_md5_crypt"``, ``"des_crypt"``, ``"ldap_sha1"``, ``"plaintext"``.

       If no value is specified, this class currently uses ``apr_md5_crypt`` when creating new passwords.

    :param autoload:
        if ``True`` (the default), :meth:`load` will be automatically called
        by constructor.

        Set to ``False`` to disable automatic loading (primarily used when
        creating new htdigest file).

    Loading & Saving
    ================
    .. automethod:: load
    .. automethod:: save
    .. automethod:: to_string

    Inspection
    ================
    .. automethod:: users
    .. automethod:: verify

    Modification
    ================
    .. automethod:: update
    .. automethod:: delete

    .. note::

        All of the methods in this class enforce some data validation
        on the ``user`` parameter:
        they will raise a :exc:`ValueError` if the string
        contains one of the forbidden characters ``:\\r\\n\\t\\x00``,
        or is longer than 255 characters.
    """
    def __init__(self, path=None, default=None, **kwds):
        self.context = htpasswd_context
        if default:
            self.context = self.context.replace(default=default)
        super(HtpasswdFile, self).__init__(path, **kwds)

    def _parse_line(self, line):
        #should be user, hash
        return line.rstrip().split(":")

    def _render_line(self, user, hash):
        return "%s:%s\n" % (user, hash)

    def users(self):
        "return list of all users in file"
        return list(self._entry_order)

    def update(self, user, password):
        """update password for user; adds user if needed.

        :returns: ``True`` if existing user was updated, ``False`` if user added.
        """
        self._validate_user(user)
        hash = self.context.encrypt(password)
        return self._update_key(user, hash)

    def delete(self, user):
        """delete user's entry.

        :returns: ``True`` if user deleted, ``False`` if user not found.
        """
        self._validate_user(user)
        return self._delete_key(user)

    def verify(self, user, password):
        """verify password for specified user.

        :returns:
            * ``None`` if user not found
            * ``False`` if password does not match
            * ``True`` if password matches.
        """
        self._validate_user(user)
        hash = self._entry_map.get(user)
        if hash is None:
            return None
        else:
            return self.context.verify(password, hash)
            #TODO: support migration from deprecated hashes

#=========================================================
#htdigest editing
#=========================================================

class HtdigestFile(_CommonFile):
    """class for reading & writing Htdigest files

    :arg path: path to htpasswd file to load from / save to (required)

    :param autoload:
        if ``True`` (the default), :meth:`load` will be automatically called
        by constructor.

        Set to ``False`` to disable automatic loading (primarily used when
        creating new htdigest file).

    Loading & Saving
    ================
    .. automethod:: load
    .. automethod:: save
    .. automethod:: to_string

    Inspection
    ==========
    .. automethod:: realms
    .. automethod:: users
    .. automethod:: find
    .. automethod:: verify

    Modification
    ============
    .. automethod:: update
    .. automethod:: delete
    .. automethod:: delete_realm

    .. note::

        All of the methods in this class enforce some data validation
        on the ``user`` and ``realm`` parameters:
        they will raise a :exc:`ValueError` if either string
        contains one of the forbidden characters ``:\\r\\n\\t\\x00``,
        or is longer than 255 characters.

    """
    def _parse_line(self, line):
        user, realm, hash = line.rstrip().split(":")
        return (user, realm), hash

    def _render_line(self, key, hash):
        return "%s:%s:%s\n" % (key[0], key[1], hash)

    def realms(self):
        "return all realms listed in file"
        return list(set(key[1] for key in self._entry_order))

    def users(self, realm):
        "return list of all users within specified realm"
        return [ key[0] for key in self._entry_order if key[1] == realm ]

    def update(self, user, realm, password):
        """update password for user under specified realm; adding user if needed

        :returns: ``True`` if existing user was updated, ``False`` if user added.
        """
        self._validate_user(user)
        self._validate_realm(realm)
        key = (user,realm)
        hash = md5("%s:%s:%s" % (user,realm,password)).hexdigest()
        return self._update_key(key, hash)

    def delete(self, user, realm):
        """delete user's entry for specified realm.

        :returns: ``True`` if user deleted, ``False`` if user not found in realm.
        """
        self._validate_user(user)
        self._validate_realm(realm)
        return self._delete_key((user,realm))

    def delete_realm(self, realm):
        """delete all users for specified realm

        :returns: number of users deleted
        """
        self._validate_realm(realm)
        keys = [
            key for key in self._entry_map
            if key[1] == realm
        ]
        for key in keys:
            self._delete_key(key)
        return len(keys)

    def find(self, user, realm):
        """return digest hash for specified user+realm; returns ``None`` if not found"""
        self._validate_user(user)
        self._validate_realm(realm)
        return self._entry_map.get((user,realm))

    def verify(self, user, realm, password):
        """verify password for specified user + realm.

        :returns:
            * ``None`` if user not found
            * ``False`` if password does not match
            * ``True`` if password matches.
        """
        self._validate_user(user)
        self._validate_realm(realm)
        hash = self._entry_map.get((user,realm))
        if hash is None:
            return None
        return hash == md5("%s:%s:%s" % (user,realm,password)).hexdigest()

#=========================================================
# eof
#=========================================================
