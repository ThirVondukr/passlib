"""Apache password support"""

# XXX: relocate this to passlib.ext.apache?
from __future__ import annotations

import os
from io import BytesIO
from os import PathLike
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, Union, cast
from warnings import warn

from passlib._logging import logger

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from typing_extensions import Self

from passlib import exc, registry
from passlib.context import CryptContext
from passlib.exc import ExpectedStringError
from passlib.hash import htdigest
from passlib.utils import is_ascii_codec, render_bytes, to_bytes
from passlib.utils.compat import join_bytes

# local
__all__ = [
    "HtpasswdFile",
    "HtdigestFile",
]

_UNSET = object()

_BCOLON = b":"
_BHASH = b"#"

# byte values that aren't allowed in fields.
_INVALID_FIELD_CHARS = b":\n\r\t\x00"

#: _CommonFile._source token types
_SKIPPED: Literal["skipped"] = "skipped"
_RECORD: Literal["record"] = "record"
_TRecordKey = TypeVar("_TRecordKey")

if TYPE_CHECKING:
    _SourceTypes = Union[
        tuple[Literal["skipped"], bytes],
        tuple[Literal["record"], _TRecordKey],
    ]
else:
    _SourceTypes = None


class _CommonFile(Generic[_TRecordKey]):
    """Common framework for HtpasswdFile & HtdigestFile"""

    def __init__(
        self,
        path: PathLike | None = None,
        new: bool = False,
        autosave: bool = False,
        encoding: str = "utf-8",
        return_unicode: bool = True,
    ) -> None:
        # set encoding
        if not encoding:
            raise TypeError("'encoding' is required")
        if not is_ascii_codec(encoding):
            # htpasswd/htdigest files assumes 1-byte chars, and use ":" separator,
            # so only ascii-compatible encodings are allowed.
            raise ValueError("encoding must be 7-bit ascii compatible")

        # charset encoding used by file (defaults to utf-8)
        self.encoding = encoding
        # whether users() and other public methods should return str or bytes?
        self.return_unicode = return_unicode
        # if true, automatically save to local file after changes are made.
        self.autosave = autosave
        self._path = path  # local file path
        self._mtime: float = 0  # mtime when last loaded, or 0

        # dict mapping key -> value for all records in database.
        # (e.g. user => hash for Htpasswd)
        self._records: dict[_TRecordKey, str] = {}
        #: list of tokens for recreating original file contents when saving. if present,
        #: will be sequence of (_SKIPPED, b"whitespace/comments") and (_RECORD, <record key>) tuples.
        self._source: list[_SourceTypes] = []

        # init db
        if path and not new:
            self.load()

    @classmethod
    def from_string(cls, data: str | bytes, **kwargs: Any) -> Self:
        """create new object from raw string.

        :type data: str or bytes
        :arg data:
            database to load, as single string.

        :param \\*\\*kwds:
            all other keywords are the same as in the class constructor
        """
        if "path" in kwargs:
            raise TypeError("'path' not accepted by from_string()")
        instance = cls(**kwargs)
        instance.load_string(data)
        return instance

    @classmethod
    def from_path(cls, path: PathLike, **kwds: Any) -> Self:
        """create new object from file, without binding object to file.

        :type path: str
        :arg path:
            local filepath to load from

        :param \\*\\*kwds:
            all other keywords are the same as in the class constructor
        """
        self = cls(**kwds)
        self.load(path)
        return self

    # XXX: add a new() classmethod, ala TOTP.new()?

    def __repr__(self) -> str:
        tail = ""
        if self.autosave:
            tail += " autosave=True"
        if self._path:
            tail += f" path={self._path!r}"
        if self.encoding != "utf-8":
            tail += f" encoding={self.encoding!r}"
        return f"<{self.__class__.__name__} 0x{id(self):0x}{tail}>"

    # NOTE: ``path`` is a property so that ``_mtime`` is wiped when it's set.

    @property
    def path(self) -> PathLike | None:
        return self._path

    @path.setter
    def path(self, value: PathLike | None) -> None:
        if value != self._path:
            self._mtime = 0
        self._path = value

    @property
    def mtime(self) -> float:
        """modify time when last loaded (if bound to a local file)"""
        return self._mtime

    def load_if_changed(self) -> bool:
        """Reload from ``self.path`` only if file has changed since last load"""
        if not self._path:
            raise RuntimeError(f"{self!r} is not bound to a local file")
        if self._mtime and self._mtime == os.path.getmtime(self._path):
            return False
        self.load()
        return True

    def load(self, path: PathLike | None = None) -> bool:
        """Load state from local file.
        If no path is specified, attempts to load from ``self.path``.

        :type path: str
        :arg path: local file to load from
        """
        if path is not None:
            with open(path, "rb") as fh:
                self._mtime = 0
                self._load_lines(fh)
        elif self._path:
            with open(self._path, "rb") as fh:
                self._mtime = os.path.getmtime(self._path)
                self._load_lines(fh)
        else:
            raise RuntimeError(
                f"{self.__class__.__name__}().path is not set, an explicit path is required"
            )
        return True

    def load_string(self, data: str | bytes) -> None:
        """Load state from unicode or bytes string, replacing current state"""
        self._mtime = 0
        self._load_lines(BytesIO(to_bytes(data, self.encoding, "data")))

    def _load_lines(self, lines: Iterable[bytes]) -> None:
        """load from sequence of lists"""
        records = {}
        source: list[_SourceTypes] = []
        skipped = b""
        for idx, line in enumerate(lines):
            # NOTE: per htpasswd source (https://github.com/apache/httpd/blob/trunk/support/htpasswd.c),
            #       lines with only whitespace, or with "#" as first non-whitespace char,
            #       are left alone / ignored.
            tmp = line.lstrip()
            if not tmp or tmp.startswith(_BHASH):
                skipped += line
                continue

            # parse valid line
            key, value = self._parse_record(line, idx + 1)

            # NOTE: if multiple entries for a key, we use the first one,
            #       which seems to match htpasswd source
            if key in records:
                logger.warning(
                    "username occurs multiple times in source file: %r",
                    key,
                )
                skipped += line
                continue

            # flush buffer of skipped whitespace lines
            if skipped:
                source.append((_SKIPPED, skipped))
                skipped = b""

            # store new user line
            records[key] = value
            source.append((_RECORD, key))

        # don't bother preserving trailing whitespace, but do preserve trailing comments
        if skipped.rstrip():
            source.append((_SKIPPED, skipped))

        # NOTE: not replacing ._records until parsing succeeds, so loading is atomic.
        self._records = records
        self._source = source

    def _parse_record(
        self, record: bytes, lineno: int
    ) -> tuple[_TRecordKey, Any]:  # pragma: no cover - abstract method
        """parse line of file into (key, value) pair"""
        raise NotImplementedError("should be implemented in subclass")

    def _set_record(self, key: _TRecordKey, value: Any) -> bool:
        """
        helper for setting record which takes care of inserting source line if needed;

        :returns:
            bool if key already present
        """
        existing = key in self._records
        self._records[key] = value
        if not existing:
            self._source.append((_RECORD, key))
        return existing

    def _autosave(self) -> None:
        """subclass helper to call save() after any changes"""
        if self.autosave and self._path:
            self.save()

    def save(self, path: PathLike | None = None) -> None:
        """Save current state to file.
        If no path is specified, attempts to save to ``self.path``.
        """
        if path is not None:
            with open(path, "wb") as fh:
                fh.writelines(self._iter_lines())
        elif self._path:
            self.save(self._path)
            self._mtime = os.path.getmtime(self._path)
        else:
            raise RuntimeError(
                f"{self.__class__.__name__}().path is not set, cannot autosave"
            )

    def to_string(self) -> bytes:
        """Export current state as a string of bytes"""
        return join_bytes(self._iter_lines())

    # def clean(self):
    #     """
    #     discard any comments or whitespace that were being preserved from the source file,
    #     and re-sort keys in alphabetical order
    #     """
    #     self._source = [(_RECORD, key) for key in sorted(self._records)]
    #     self._autosave()

    def _iter_lines(self) -> Iterator[Any]:
        """iterator yielding lines of database"""
        # NOTE: this relies on <records> being an OrderedDict so that it outputs
        #       records in a deterministic order.
        records = self._records
        if __debug__:
            pending = set(records)
        for action, content in self._source:
            if action == _SKIPPED:
                # 'content' is whitespace/comments to write
                yield content
            else:
                assert action == _RECORD
                content = cast(
                    "_TRecordKey", content
                )  # Should be _TRecordKey at this point

                # 'content' is record key
                if content not in records:
                    # record was deleted
                    # NOTE: doing it lazily like this so deleting & re-adding user
                    #       preserves their original location in the file.
                    continue
                yield self._render_record(content, records[content])
                if __debug__:
                    pending.remove(content)
        if __debug__:
            # sanity check that we actually wrote all the records
            # (otherwise _source & _records are somehow out of sync)
            assert not pending, f"failed to write all records: missing={pending!r}"

    def _render_record(self, key, value):  # pragma: no cover - abstract method
        """given key/value pair, encode as line of file"""
        raise NotImplementedError("should be implemented in subclass")

    def _encode_user(self, user: str | bytes) -> bytes:
        """user-specific wrapper for _encode_field()"""
        return self._encode_field(user, "user")

    def _encode_realm(
        self, realm: str | bytes
    ) -> bytes:  # pragma: no cover - abstract method
        """realm-specific wrapper for _encode_field()"""
        return self._encode_field(realm, "realm")

    def _encode_field(self, value: str | bytes, param="field") -> bytes:
        """convert field to internal representation.

        internal representation is always bytes. byte strings are left as-is,
        unicode strings encoding using file's default encoding (or ``utf-8``
        if no encoding has been specified).

        :raises UnicodeEncodeError:
            if unicode value cannot be encoded using default encoding.

        :raises ValueError:
            if resulting byte string contains a forbidden character,
            or is too long (>255 bytes).

        :returns:
            encoded identifer as bytes
        """
        if isinstance(value, str):
            value = value.encode(self.encoding)
        elif not isinstance(value, bytes):
            raise ExpectedStringError(value, param)

        if len(value) > 255:
            raise ValueError(f"{param} must be at most 255 characters: {value!r}")
        if any(c in _INVALID_FIELD_CHARS for c in value):
            raise ValueError(f"{param} contains invalid characters: {value!r}")
        return value

    def _decode_field(self, value: bytes) -> bytes | str:
        """decode field from internal representation to format
        returns by users() method, etc.

        :raises UnicodeDecodeError:
            if unicode value cannot be decoded using default encoding.
            (usually indicates wrong encoding set for file).

        :returns:
            field as str or bytes, as appropriate.
        """
        assert isinstance(value, bytes), "expected value to be bytes"
        if self.return_unicode:
            return value.decode(self.encoding)
        return value

    # FIXME: htpasswd doc says passwords limited to 255 chars under Windows & MPE,
    # and that longer ones are truncated. this may be side-effect of those
    # platforms supporting the 'plaintext' scheme. these classes don't currently
    # check for this.


# =============================================================================
# htpasswd context
#
# This section sets up a CryptContexts to mimic what schemes Apache
# (and the htpasswd tool) should support on the current system.
#
# Apache has long-time supported some basic builtin schemes (listed below),
# as well as the host's crypt() method -- though it's limited to being able
# to *verify* any scheme using that method, but can only generate "des_crypt" hashes.
#
# Apache 2.4 added builtin bcrypt support (even for platforms w/o native support).
# c.f. http://httpd.apache.org/docs/2.4/programs/htpasswd.html vs the 2.2 docs.
# =============================================================================

#: set of default schemes that (if chosen) should be using bcrypt,
#: but can't due to lack of bcrypt.
_warn_no_bcrypt: set[str] = set()


def _init_default_schemes():
    #: pick strongest one for host
    host_best = None
    for name in ["bcrypt", "sha256_crypt"]:
        if registry.has_os_crypt_support(name):
            host_best = name
            break

    # check if we have a bcrypt backend -- otherwise issue warning
    # XXX: would like to not spam this unless the user *requests* apache 24
    bcrypt = "bcrypt" if registry.has_backend("bcrypt") else None
    _warn_no_bcrypt.clear()
    if not bcrypt:
        _warn_no_bcrypt.update(
            [
                "portable_apache_24",
                "host_apache_24",
                "linux_apache_24",
                "portable",
                "host",
            ]
        )

    defaults = dict(
        # strongest hash builtin to specific apache version
        portable_apache_24=bcrypt or "apr_md5_crypt",
        portable_apache_22="apr_md5_crypt",
        # strongest hash across current host & specific apache version
        host_apache_24=bcrypt or host_best or "apr_md5_crypt",
        host_apache_22=host_best or "apr_md5_crypt",
        # strongest hash on a linux host
        linux_apache_24=bcrypt or "sha256_crypt",
        linux_apache_22="sha256_crypt",
    )

    # set latest-apache version aliases
    # XXX: could check for apache install, and pick correct host 22/24 default?
    #      could reuse _detect_htpasswd() helper in UTs
    defaults.update(
        portable=defaults["portable_apache_24"],
        host=defaults["host_apache_24"],
    )
    return defaults


#: dict mapping default alias -> appropriate scheme
htpasswd_defaults = _init_default_schemes()


def _init_htpasswd_context():
    # start with schemes built into apache
    schemes = [
        # builtin support added in apache 2.4
        # (https://bz.apache.org/bugzilla/show_bug.cgi?id=49288)
        "bcrypt",
        # support not "builtin" to apache, instead it requires support through host's crypt().
        # adding them here to allow editing htpasswd under windows and then deploying under unix.
        "sha256_crypt",
        "sha512_crypt",
        "des_crypt",
        # apache default as of 2.2.18, and still default in 2.4
        "apr_md5_crypt",
        # NOTE: apache says ONLY intended for transitioning htpasswd <-> ldap
        "ldap_sha1",
        # NOTE: apache says ONLY supported on Windows, Netware, TPF
        "plaintext",
    ]

    # apache can verify anything supported by the native crypt(),
    # though htpasswd tool can only generate a limited set of hashes.
    # (this list may overlap w/ builtin apache schemes)
    schemes.extend(registry.get_supported_os_crypt_schemes())

    # hack to remove dups and sort into preferred order
    preferred = schemes[:3] + ["apr_md5_crypt"] + schemes
    schemes = sorted(set(schemes), key=preferred.index)

    # create context object
    return CryptContext(
        schemes=schemes,
        # NOTE: default will change to "portable" in passlib 2.0
        default=htpasswd_defaults["portable_apache_22"],
        # NOTE: bcrypt "2y" is required, "2b" isn't recognized by libapr (issue 95)
        bcrypt__ident="2y",
    )


#: CryptContext configured to match htpasswd
htpasswd_context = _init_htpasswd_context()


class HtpasswdFile(_CommonFile[bytes]):
    """class for reading & writing Htpasswd files.

    The class constructor accepts the following arguments:

    :type path: filepath
    :param path:

        Specifies path to htpasswd file, use to implicitly load from and save to.

        This class has two modes of operation:

        1. It can be "bound" to a local file by passing a ``path`` to the class
           constructor. In this case it will load the contents of the file when
           created, and the :meth:`load` and :meth:`save` methods will automatically
           load from and save to that file if they are called without arguments.

        2. Alternately, it can exist as an independant object, in which case
           :meth:`load` and :meth:`save` will require an explicit path to be
           provided whenever they are called. As well, ``autosave`` behavior
           will not be available.

           This feature is new in Passlib 1.6, and is the default if no
           ``path`` value is provided to the constructor.

        This is also exposed as a readonly instance attribute.

    :type new: bool
    :param new:

        Normally, if *path* is specified, :class:`HtpasswdFile` will
        immediately load the contents of the file. However, when creating
        a new htpasswd file, applications can set ``new=True`` so that
        the existing file (if any) will not be loaded.

        .. versionadded:: 1.6
            This feature was previously enabled by setting ``autoload=False``.
            That alias was removed in Passlib 1.8

    :type autosave: bool
    :param autosave:

        Normally, any changes made to an :class:`HtpasswdFile` instance
        will not be saved until :meth:`save` is explicitly called. However,
        if ``autosave=True`` is specified, any changes made will be
        saved to disk immediately (assuming *path* has been set).

        This is also exposed as a writeable instance attribute.

    :type encoding: str
    :param encoding:

        Optionally specify character encoding used to read/write file
        and hash passwords. Defaults to ``utf-8``, though ``latin-1``
        is the only other commonly encountered encoding.

        This is also exposed as a readonly instance attribute.

    :type default_scheme: str
    :param default_scheme:
        Optionally specify default scheme to use when encoding new passwords.

        This can be any of the schemes with builtin Apache support,
        OR natively supported by the host OS's :func:`crypt.crypt` function.

        * Builtin schemes include ``"bcrypt"`` (apache 2.4+), ``"apr_md5_crypt"`,
          and ``"des_crypt"``.

        * Schemes commonly supported by Unix hosts
          include ``"bcrypt"``, ``"sha256_crypt"``, and ``"des_crypt"``.

        In order to not have to sort out what you should use,
        passlib offers a number of aliases, that will resolve
        to the most appropriate scheme based on your needs:

        * ``"portable"``, ``"portable_apache_24"`` -- pick scheme that's portable across hosts
          running apache >= 2.4. **This will be the default as of Passlib 2.0**.

        * ``"portable_apache_22"`` -- pick scheme that's portable across hosts
          running apache >= 2.4. **This is the default up to Passlib 1.9**.

        * ``"host"``, ``"host_apache_24"`` -- pick strongest scheme supported by
           apache >= 2.4 and/or host OS.

        * ``"host_apache_22"`` -- pick strongest scheme supported by
           apache >= 2.2 and/or host OS.

        .. versionadded:: 1.6
            This keyword was previously named ``default``. That alias
            was removed in Passlib 1.8.

        .. versionchanged:: 1.6.3

            Added support for ``"bcrypt"``, ``"sha256_crypt"``, and ``"portable"`` alias.

        .. versionchanged:: 1.7

            Added apache 2.4 semantics, and additional aliases.

    :type context: :class:`~passlib.context.CryptContext`
    :param context:
        :class:`!CryptContext` instance used to create
        and verify the hashes found in the htpasswd file.
        The default value is a pre-built context which supports all
        of the hashes officially allowed in an htpasswd file.

        This is also exposed as a readonly instance attribute.

        .. warning::

            This option may be used to add support for non-standard hash
            formats to an htpasswd file. However, the resulting file
            will probably not be usable by another application,
            and particularly not by Apache.

    Loading & Saving
    ================
    .. automethod:: load
    .. automethod:: load_if_changed
    .. automethod:: load_string
    .. automethod:: save
    .. automethod:: to_string

    Inspection
    ================
    .. automethod:: users
    .. automethod:: check_password
    .. automethod:: get_hash

    Modification
    ================
    .. automethod:: set_password
    .. automethod:: delete

    Alternate Constructors
    ======================
    .. automethod:: from_string

    Attributes
    ==========
    .. attribute:: path

        Path to local file that will be used as the default
        for all :meth:`load` and :meth:`save` operations.
        May be written to, initialized by the *path* constructor keyword.

    .. attribute:: autosave

        Writeable flag indicating whether changes will be automatically
        written to *path*.

    Errors
    ======
    :raises ValueError:
        All of the methods in this class will raise a :exc:`ValueError` if
        any user name contains a forbidden character (one of ``:\\r\\n\\t\\x00``),
        or is longer than 255 characters.
    """

    # NOTE: _records map stores <user> for the key, and <hash> for the value,
    #       both in bytes which use self.encoding
    def __init__(
        self, path=None, default_scheme=None, context=htpasswd_context, **kwds
    ):
        if default_scheme:
            if default_scheme in _warn_no_bcrypt:
                warn(
                    "HtpasswdFile: no bcrypt backends available, "
                    f"using fallback for default scheme {default_scheme!r}",
                    exc.PasslibSecurityWarning,
                )
            default_scheme = htpasswd_defaults.get(default_scheme, default_scheme)
            context = context.copy(default=default_scheme)
        self.context = context
        super().__init__(path, **kwds)

    def _parse_record(self, record, lineno):
        # NOTE: should return (user, hash) tuple
        result = record.rstrip().split(_BCOLON)
        if len(result) != 2:
            raise ValueError("malformed htpasswd file (error reading line %d)" % lineno)
        return result

    def _render_record(self, user, hash):
        return render_bytes("%s:%s\n", user, hash)

    def users(self) -> list[bytes | str]:
        """
        Return list of all users in database
        """
        return [self._decode_field(user) for user in self._records]

    ##def has_user(self, user):
    ##    "check whether entry is present for user"
    ##    return self._encode_user(user) in self._records

    ##def rename(self, old, new):
    ##    """rename user account"""
    ##    old = self._encode_user(old)
    ##    new = self._encode_user(new)
    ##    hash = self._records.pop(old)
    ##    self._records[new] = hash
    ##    self._autosave()

    def set_password(self, user, password):
        """Set password for user; adds user if needed.

        :returns:
            * ``True`` if existing user was updated.
            * ``False`` if user account was added.

        .. versionchanged:: 1.6
            This method was previously called ``update``, it was renamed
            to prevent ambiguity with the dictionary method.
            The old alias was removed in Passlib 1.8.
        """
        hash = self.context.hash(password)
        return self.set_hash(user, hash)

    def get_hash(self, user):
        """Return hash stored for user, or ``None`` if user not found.

        .. versionchanged:: 1.6
            This method was previously named ``find``, it was renamed
            for clarity. The old name was removed in Passlib 1.8.
        """
        try:
            return self._records[self._encode_user(user)]
        except KeyError:
            return None

    def set_hash(self, user, hash):
        """
        semi-private helper which allows writing a hash directly;
        adds user if needed.

        .. warning::
            does not (currently) do any validation of the hash string

        .. versionadded:: 1.7
        """
        # assert self.context.identify(hash), "unrecognized hash format"
        if isinstance(hash, str):
            hash = hash.encode(self.encoding)
        user = self._encode_user(user)
        existing = self._set_record(user, hash)
        self._autosave()
        return existing

    # XXX: rename to something more explicit, like delete_user()?
    def delete(self, user):
        """Delete user's entry.

        :returns:
            * ``True`` if user deleted.
            * ``False`` if user not found.
        """
        try:
            del self._records[self._encode_user(user)]
        except KeyError:
            return False
        self._autosave()
        return True

    def check_password(self, user, password):
        """
        Verify password for specified user.
        If algorithm marked as deprecated by CryptContext, will automatically be re-hashed.

        :returns:
            * ``None`` if user not found.
            * ``False`` if user found, but password does not match.
            * ``True`` if user found and password matches.

        .. versionchanged:: 1.6
            This method was previously called ``verify``, it was renamed
            to prevent ambiguity with the :class:`!CryptContext` method.
            The old alias was removed in Passlib 1.8.
        """
        user = self._encode_user(user)
        hash = self._records.get(user)
        if hash is None:
            return None
        if isinstance(password, str):
            # NOTE: encoding password to match file, making the assumption
            # that server will use same encoding to hash the password.
            password = password.encode(self.encoding)
        ok, new_hash = self.context.verify_and_update(password, hash)
        if ok and new_hash is not None:
            # rehash user's password if old hash was deprecated
            assert user in self._records  # otherwise would have to use ._set_record()
            self._records[user] = new_hash
            self._autosave()
        return ok


class HtdigestFile(_CommonFile[tuple[bytes, bytes]]):
    """class for reading & writing Htdigest files.

    The class constructor accepts the following arguments:

    :type path: filepath
    :param path:

        Specifies path to htdigest file, use to implicitly load from and save to.

        This class has two modes of operation:

        1. It can be "bound" to a local file by passing a ``path`` to the class
           constructor. In this case it will load the contents of the file when
           created, and the :meth:`load` and :meth:`save` methods will automatically
           load from and save to that file if they are called without arguments.

        2. Alternately, it can exist as an independant object, in which case
           :meth:`load` and :meth:`save` will require an explicit path to be
           provided whenever they are called. As well, ``autosave`` behavior
           will not be available.

           This feature is new in Passlib 1.6, and is the default if no
           ``path`` value is provided to the constructor.

        This is also exposed as a readonly instance attribute.

    :type default_realm: str
    :param default_realm:

        If ``default_realm`` is set, all the :class:`HtdigestFile`
        methods that require a realm will use this value if one is not
        provided explicitly. If unset, they will raise an error stating
        that an explicit realm is required.

        This is also exposed as a writeable instance attribute.

        .. versionadded:: 1.6

    :type new: bool
    :param new:

        Normally, if *path* is specified, :class:`HtdigestFile` will
        immediately load the contents of the file. However, when creating
        a new htpasswd file, applications can set ``new=True`` so that
        the existing file (if any) will not be loaded.

        .. versionadded:: 1.6
            This feature was previously enabled by setting ``autoload=False``.
            That alias was removed in Passlib 1.8

    :type autosave: bool
    :param autosave:

        Normally, any changes made to an :class:`HtdigestFile` instance
        will not be saved until :meth:`save` is explicitly called. However,
        if ``autosave=True`` is specified, any changes made will be
        saved to disk immediately (assuming *path* has been set).

        This is also exposed as a writeable instance attribute.

    :type encoding: str
    :param encoding:

        Optionally specify character encoding used to read/write file
        and hash passwords. Defaults to ``utf-8``, though ``latin-1``
        is the only other commonly encountered encoding.

        This is also exposed as a readonly instance attribute.

    Loading & Saving
    ================
    .. automethod:: load
    .. automethod:: load_if_changed
    .. automethod:: load_string
    .. automethod:: save
    .. automethod:: to_string

    Inspection
    ==========
    .. automethod:: realms
    .. automethod:: users
    .. automethod:: check_password(user[, realm], password)
    .. automethod:: get_hash

    Modification
    ============
    .. automethod:: set_password(user[, realm], password)
    .. automethod:: delete
    .. automethod:: delete_realm

    Alternate Constructors
    ======================
    .. automethod:: from_string

    Attributes
    ==========
    .. attribute:: default_realm

        The default realm that will be used if one is not provided
        to methods that require it. By default this is ``None``,
        in which case an explicit realm must be provided for every
        method call. Can be written to.

    .. attribute:: path

        Path to local file that will be used as the default
        for all :meth:`load` and :meth:`save` operations.
        May be written to, initialized by the *path* constructor keyword.

    .. attribute:: autosave

        Writeable flag indicating whether changes will be automatically
        written to *path*.

    Errors
    ======
    :raises ValueError:
        All of the methods in this class will raise a :exc:`ValueError` if
        any user name or realm contains a forbidden character (one of ``:\\r\\n\\t\\x00``),
        or is longer than 255 characters.
    """

    # NOTE: _records map stores (<user>,<realm>) for the key,
    # and <hash> as the value, all as <self.encoding> bytes.

    # NOTE: unlike htpasswd, this class doesn't use a CryptContext,
    # as only one hash format is supported: htdigest.

    # optionally specify default realm that will be used if none
    # is provided to a method call. otherwise realm is always required.
    default_realm = None

    def __init__(self, path=None, default_realm=None, **kwds):
        self.default_realm = default_realm
        super().__init__(path, **kwds)

    def _parse_record(self, record, lineno):
        result = record.rstrip().split(_BCOLON)
        if len(result) != 3:
            raise ValueError("malformed htdigest file (error reading line %d)" % lineno)
        user, realm, hash = result
        return (user, realm), hash

    def _render_record(self, key, hash):
        user, realm = key
        return render_bytes("%s:%s:%s\n", user, realm, hash)

    def _require_realm(self, realm):
        if realm is None:
            realm = self.default_realm
            if realm is None:
                raise TypeError(
                    "you must specify a realm explicitly, "
                    "or set the default_realm attribute"
                )
        return realm

    def _encode_realm(self, realm):
        realm = self._require_realm(realm)
        return self._encode_field(realm, "realm")

    def _encode_key(self, user, realm):
        return self._encode_user(user), self._encode_realm(realm)

    def realms(self):
        """Return list of all realms in database"""
        realms = set(key[1] for key in self._records)
        return [self._decode_field(realm) for realm in realms]

    def users(self, realm=None):
        """Return list of all users in specified realm.

        * uses ``self.default_realm`` if no realm explicitly provided.
        * returns empty list if realm not found.
        """
        realm = self._encode_realm(realm)
        return [self._decode_field(key[0]) for key in self._records if key[1] == realm]

    ##def has_user(self, user, realm=None):
    ##    "check if user+realm combination exists"
    ##    return self._encode_key(user,realm) in self._records

    ##def rename_realm(self, old, new):
    ##    """rename all accounts in realm"""
    ##    old = self._encode_realm(old)
    ##    new = self._encode_realm(new)
    ##    keys = [key for key in self._records if key[1] == old]
    ##    for key in keys:
    ##        hash = self._records.pop(key)
    ##        self._set_record((key[0], new), hash)
    ##    self._autosave()
    ##    return len(keys)

    ##def rename(self, old, new, realm=None):
    ##    """rename user account"""
    ##    old = self._encode_user(old)
    ##    new = self._encode_user(new)
    ##    realm = self._encode_realm(realm)
    ##    hash = self._records.pop((old,realm))
    ##    self._set_record((new, realm), hash)
    ##    self._autosave()

    def set_password(self, user, realm=None, password=_UNSET):
        """Set password for user; adds user & realm if needed.

        If ``self.default_realm`` has been set, this may be called
        with the syntax ``set_password(user, password)``,
        otherwise it must be called with all three arguments:
        ``set_password(user, realm, password)``.

        :returns:
            * ``True`` if existing user was updated
            * ``False`` if user account added.
        """
        if password is _UNSET:
            # called w/ two args - (user, password), use default realm
            realm, password = None, realm
        realm = self._require_realm(realm)
        hash = htdigest.hash(password, user, realm, encoding=self.encoding)
        return self.set_hash(user, realm, hash)

    def get_hash(self, user, realm=None):
        """Return :class:`~passlib.hash.htdigest` hash stored for user.

        * uses ``self.default_realm`` if no realm explicitly provided.
        * returns ``None`` if user or realm not found.

        .. versionchanged:: 1.6
            This method was previously named ``find``, it was renamed
            for clarity. The old name is was removed Passlib 1.8.
        """
        key = self._encode_key(user, realm)
        hash = self._records.get(key)
        if hash is None:
            return None
        return hash.decode(self.encoding)

    def set_hash(self, user, realm=None, hash=_UNSET):
        """
        semi-private helper which allows writing a hash directly;
        adds user & realm if needed.

        If ``self.default_realm`` has been set, this may be called
        with the syntax ``set_hash(user, hash)``,
        otherwise it must be called with all three arguments:
        ``set_hash(user, realm, hash)``.

        .. warning::
            does not (currently) do any validation of the hash string

        .. versionadded:: 1.7
        """
        if hash is _UNSET:
            # called w/ two args - (user, hash), use default realm
            realm, hash = None, realm
        # assert htdigest.identify(hash), "unrecognized hash format"
        if isinstance(hash, str):
            hash = hash.encode(self.encoding)
        key = self._encode_key(user, realm)
        existing = self._set_record(key, hash)
        self._autosave()
        return existing

    # XXX: rename to something more explicit, like delete_user()?
    def delete(self, user, realm=None):
        """Delete user's entry for specified realm.

        if realm is not specified, uses ``self.default_realm``.

        :returns:
            * ``True`` if user deleted,
            * ``False`` if user not found in realm.
        """
        key = self._encode_key(user, realm)
        try:
            del self._records[key]
        except KeyError:
            return False
        self._autosave()
        return True

    def delete_realm(self, realm):
        """Delete all users for specified realm.

        if realm is not specified, uses ``self.default_realm``.

        :returns: number of users deleted (0 if realm not found)
        """
        realm = self._encode_realm(realm)
        records = self._records
        keys = [key for key in records if key[1] == realm]
        for key in keys:
            del records[key]
        self._autosave()
        return len(keys)

    def check_password(self, user, realm=None, password=_UNSET):
        """Verify password for specified user + realm.

        If ``self.default_realm`` has been set, this may be called
        with the syntax ``check_password(user, password)``,
        otherwise it must be called with all three arguments:
        ``check_password(user, realm, password)``.

        :returns:
            * ``None`` if user or realm not found.
            * ``False`` if user found, but password does not match.
            * ``True`` if user found and password matches.

        .. versionchanged:: 1.6
            This method was previously called ``verify``, it was renamed
            to prevent ambiguity with the :class:`!CryptContext` method.
            The old alias was removed in Passlib 1.8.
        """
        if password is _UNSET:
            # called w/ two args - (user, password), use default realm
            realm, password = None, realm
        user = self._encode_user(user)
        realm = self._encode_realm(realm)
        hash = self._records.get((user, realm))
        if hash is None:
            return None
        return htdigest.verify(password, hash, user, realm, encoding=self.encoding)
