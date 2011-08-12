"""passlib.apache - apache password support"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from hashlib import md5
import logging; log = logging.getLogger(__name__)
import os
import sys
#site
#libs
from passlib.context import CryptContext
from passlib.utils import render_bytes, bjoin, bytes, b, to_unicode, to_bytes
#pkg
#local
__all__ = [
]

BCOLON = b(":")

#=========================================================
#common helpers
#=========================================================
DEFAULT_ENCODING = "utf-8" if sys.version_info >= (3,0) else None

class _CommonFile(object):
    "helper for HtpasswdFile / HtdigestFile"

    #XXX: would like to add 'path' keyword to load() / save(),
    #     but that makes .mtime somewhat meaningless.
    #     to simplify things, should probably deprecate mtime & force=False
    #     options.
    #XXX: would also like to make _load_string available via public interface,
    #     such as via 'content' keyword in load() method.
    #     in short, need to clean up the htpasswd api a little bit in 1.6.
    #     keeping _load_string private for now, cause just using it for UTing.

    #NOTE: 'path' is a property instead of attr,
    #      so that .mtime is wiped whenever path is changed.
    _path = None
    def _get_path(self):
        return self._path
    def _set_path(self, path):
        if path != self._path:
            self.mtime = 0
        self._path = path
    path = property(_get_path, _set_path)

    @classmethod
    def _from_string(cls, content, **kwds):
        #NOTE: not public yet, just using it for unit tests.
        self = cls(**kwds)
        self._load_string(content)
        return self

    def __init__(self, path=None, autoload=True,
                 encoding=DEFAULT_ENCODING,
                 ):
        if encoding and u":\n".encode(encoding) != b(":\n"):
            #rest of file assumes ascii bytes, and uses ":" as separator.
            raise ValueError, "encoding must be 7-bit ascii compatible"
        self.encoding = encoding
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

    def _load_string(self, content):
        """UT helper for loading from string

        to be improved/made public in later release.


        :param content:
            if specified, should be a bytes object.
            passwords will be loaded directly from this string,
            and any files will be ignored.
        """
        if isinstance(content, unicode):
            content = content.encode(self.encoding or 'utf-8')
        self.mtime = 0
        #XXX: replace this with iterator?
        lines = content.splitlines()
        self._load_lines(lines)
        return True

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
            raise RuntimeError("no load path specified")
        if not force and self.mtime and self.mtime == os.path.getmtime(path):
            return False
        with open(path, "rb") as fh:
            self.mtime = os.path.getmtime(path)
            self._load_lines(fh)
        return True

    def _load_lines(self, lines):
        pl = self._parse_line
        entry_order = self._entry_order = []
        entry_map = self._entry_map = {}
        for line in lines:
            #XXX: found mention that "#" comment lines may be supported by htpasswd,
            #     should verify this.
            key, value = pl(line)
            if key in entry_map:
                #XXX: should we use data from first entry, or last entry?
                #     going w/ first entry for now.
                continue
            entry_order.append(key)
            entry_map[key] = value

    #subclass: _parse_line(line) -> (key, hash)

    def _iter_lines(self):
        "iterator yielding lines of database"
        rl = self._render_line
        entry_order = self._entry_order
        entry_map = self._entry_map
        assert len(entry_order) == len(entry_map), "internal error in entry list"
        return (rl(key, entry_map[key]) for key in entry_order)

    def save(self):
        "save entries to file"
        if not self.path:
            raise RuntimeError("no save path specified")
        with open(self.path, "wb") as fh:
            fh.writelines(self._iter_lines())
        self.mtime = os.path.getmtime(self.path)

    def to_string(self):
        "export whole database as a byte string"
        return bjoin(self._iter_lines())

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

    invalid_chars = b(":\n\r\t\x00")

    def _norm_user(self, user):
        "encode user to bytes, validate against format requirements"
        return self._norm_ident(user, errname="user")

    def _norm_realm(self, realm):
        "encode realm to bytes, validate against format requirements"
        return self._norm_ident(realm, errname="realm")

    def _norm_ident(self, ident, errname="user/realm"):
        ident = self._encode_ident(ident, errname)
        if len(ident) > 255:
            raise ValueError("%s must be at most 255 characters: %r" % (errname, ident))
        if any(c in self.invalid_chars for c in ident):
            raise ValueError("%s contains invalid characters: %r" % (errname, ident,))
        return ident

    def _encode_ident(self, ident, errname="user/realm"):
        "ensure identifier is bytes encoded using specified encoding, or rejected"
        encoding = self.encoding
        if encoding:
            if isinstance(ident, unicode):
                return ident.encode(encoding)
            raise TypeError("%s must be unicode, not %s" %
                            (errname, type(ident)))
        else:
            if isinstance(ident, bytes):
                return ident
            raise TypeError("%s must be bytes, not %s" %
                            (errname, type(ident)))

    def _decode_ident(self, ident, errname="user/realm"):
        "decode an identifier (if encoding is specified, else return encoded bytes)"
        assert isinstance(ident, bytes)
        encoding = self.encoding
        if encoding:
            return ident.decode(encoding)
        else:
            return ident

    #FIXME: htpasswd doc sez passwords limited to 255 chars under Windows & MPE,
    # longer ones are truncated. may be side-effect of those platforms
    # supporting plaintext. we don't currently check for this.

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

    :param encoding:
        optionally specify encoding used for usernames.

        if set to ``None``,
        user names must be specified as bytes,
        and will be returned as bytes.

        if set to an encoding,
        user names must be specified as unicode,
        and will be returned as unicode.
        when stored, then will use the specified encoding.

        for backwards compatibility with passlib 1.4,
        this defaults to ``None`` under Python 2,
        and ``utf-8`` under Python 3.

        .. note::

            this is not the encoding for the entire file,
            just for the usernames within the file.
            this must be an encoding which is compatible
            with 7-bit ascii (which is used by rest of file).

    :param context:
        :class:`~passlib.context.CryptContext` instance used to handle
        hashes in this file.

        .. warning::

            this should usually be left at the default,
            though it can be overridden to implement non-standard hashes
            within the htpasswd file.

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
    def __init__(self, path=None, default=None, context=htpasswd_context, **kwds):
        self.context = context
        if default:
            self.context = self.context.replace(default=default)
        super(HtpasswdFile, self).__init__(path, **kwds)

    def _parse_line(self, line):
        #should be user, hash
        return line.rstrip().split(BCOLON)

    def _render_line(self, user, hash):
        return render_bytes("%s:%s\n", user, hash)

    def users(self):
        "return list of all users in file"
        return map(self._decode_ident, self._entry_order)

    def update(self, user, password):
        """update password for user; adds user if needed.

        :returns: ``True`` if existing user was updated, ``False`` if user added.
        """
        user = self._norm_user(user)
        hash = self.context.encrypt(password)
        return self._update_key(user, hash)

    def delete(self, user):
        """delete user's entry.

        :returns: ``True`` if user deleted, ``False`` if user not found.
        """
        user = self._norm_user(user)
        return self._delete_key(user)

    def verify(self, user, password):
        """verify password for specified user.

        :returns:
            * ``None`` if user not found
            * ``False`` if password does not match
            * ``True`` if password matches.
        """
        user = self._norm_user(user)
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

    :param encoding:
        optionally specify encoding used for usernames / realms.

        if set to ``None``,
        user names & realms must be specified as bytes,
        and will be returned as bytes.

        if set to an encoding,
        user names & realms must be specified as unicode,
        and will be returned as unicode.
        when stored, then will use the specified encoding.

        for backwards compatibility with passlib 1.4,
        this defaults to ``None`` under Python 2,
        and ``utf-8`` under Python 3.

        .. note::

            this is not the encoding for the entire file,
            just for the usernames & realms within the file.
            this must be an encoding which is compatible
            with 7-bit ascii (which is used by rest of file).

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
    #XXX: don't want password encoding to change if user account encoding does.
    #     but also *can't* use unicode itself. setting this to utf-8 for now,
    #     until it causes problems - in which case stopgap of setting this attr
    #     per-instance can be used.
    password_encoding = "utf-8"

    #XXX: provide rename() & rename_realm() ?

    def _parse_line(self, line):
        user, realm, hash = line.rstrip().split(BCOLON)
        return (user, realm), hash

    def _render_line(self, key, hash):
        return render_bytes("%s:%s:%s\n", key[0], key[1], hash)

    #TODO: would frontend to calc_digest be useful?
    ##def encrypt(self, password, user, realm):
    ##    user = self._norm_user(user)
    ##    realm = self._norm_realm(realm)
    ##    hash = self._calc_digest(user, realm, password)
    ##    if self.encoding:
    ##        #decode hash if in unicode mode
    ##        hash = hash.decode("ascii")
    ##    return hash

    def _calc_digest(self, user, realm, password):
        "helper to calculate digest"
        if isinstance(password, unicode):
            password = password.encode(self.password_encoding)
        #NOTE: encode('ascii') is noop under py2, required under py3
        return md5(render_bytes("%s:%s:%s", user, realm, password)).hexdigest().encode("ascii")

    def realms(self):
        "return all realms listed in file"
        return map(self._decode_ident,
                      set(key[1] for key in self._entry_order))

    def users(self, realm):
        "return list of all users within specified realm"
        realm = self._norm_realm(realm)
        return map(self._decode_ident,
                      (key[0] for key in self._entry_order if key[1] == realm))

    def update(self, user, realm, password):
        """update password for user under specified realm; adding user if needed

        :returns: ``True`` if existing user was updated, ``False`` if user added.
        """
        user = self._norm_user(user)
        realm = self._norm_realm(realm)
        key = (user,realm)
        hash = self._calc_digest(user, realm, password)
        return self._update_key(key, hash)

    def delete(self, user, realm):
        """delete user's entry for specified realm.

        :returns: ``True`` if user deleted, ``False`` if user not found in realm.
        """
        user = self._norm_user(user)
        realm = self._norm_realm(realm)
        return self._delete_key((user,realm))

    def delete_realm(self, realm):
        """delete all users for specified realm

        :returns: number of users deleted
        """
        realm = self._norm_realm(realm)
        keys = [
            key for key in self._entry_map
            if key[1] == realm
        ]
        for key in keys:
            self._delete_key(key)
        return len(keys)

    def find(self, user, realm):
        """return digest hash for specified user+realm; returns ``None`` if not found

        :returns: htdigest hash or None
        :rtype: bytes or None
        """
        user = self._norm_user(user)
        realm = self._norm_realm(realm)
        hash = self._entry_map.get((user,realm))
        if hash is not None and self.encoding:
            #decode hash if in unicode mode
            hash = hash.decode("ascii")
        return hash

    def verify(self, user, realm, password):
        """verify password for specified user + realm.

        :returns:
            * ``None`` if user not found
            * ``False`` if password does not match
            * ``True`` if password matches.
        """
        user = self._norm_user(user)
        realm = self._norm_realm(realm)
        hash = self._entry_map.get((user,realm))
        if hash is None:
            return None
        return hash == self._calc_digest(user, realm, password)

#=========================================================
# eof
#=========================================================
