import sys

import passlib.utils.handlers as uh
from passlib.utils import consteq, to_native_str
from passlib.utils.compat import unicode_or_bytes

__all__ = [
    "unix_disabled",
    "plaintext",
]

_MARKER_CHARS = "*!"
_MARKER_BYTES = b"*!"


class unix_disabled(uh.ifc.DisabledHash, uh.MinimalHandler):
    """This class provides disabled password behavior for unix shadow files,
    and follows the :ref:`password-hash-api`.

    This class does not implement a hash, but instead matches the "disabled account"
    strings found in ``/etc/shadow`` on most Unix variants. "encrypting" a password
    will simply return the disabled account marker. It will reject all passwords,
    no matter the hash string. The :meth:`~passlib.ifc.PasswordHash.hash`
    method supports one optional keyword:

    :type marker: str
    :param marker:
        Optional marker string which overrides the platform default
        used to indicate a disabled account.

        If not specified, this will default to ``"*"`` on BSD systems,
        and use the Linux default ``"!"`` for all other platforms.
        (:attr:`!unix_disabled.default_marker` will contain the default value)

    .. versionadded:: 1.6
        This class was added as a replacement for the now-removed
        :class:`!unix_fallback` class.
    """

    name = "unix_disabled"
    setting_kwds = ("marker",)
    context_kwds = ()

    _disable_prefixes = tuple(str(_MARKER_CHARS))

    # TODO: rename attr to 'marker'...
    if "bsd" in sys.platform:  # pragma: no cover -- runtime detection
        default_marker = "*"
    else:
        # use the linux default for other systems
        # (glibc also supports adding old hash after the marker
        # so it can be restored later).
        default_marker = "!"

    @classmethod
    def using(cls, marker=None, **kwds):
        subcls = super().using(**kwds)
        if marker is not None:
            if not cls.identify(marker):
                raise ValueError(f"invalid marker: {marker!r}")
            subcls.default_marker = marker
        return subcls

    @classmethod
    def identify(cls, hash):
        # NOTE: technically, anything in the /etc/shadow password field
        #       which isn't valid crypt() output counts as "disabled".
        #       but that's rather ambiguous, and it's hard to predict what
        #       valid output is for unknown crypt() implementations.
        #       so to be on the safe side, we only match things *known*
        #       to be disabled field indicators, and will add others
        #       as they are found. things beginning w/ "$" should *never* match.
        #
        # things currently matched:
        #       * linux uses "!"
        #       * bsd uses "*"
        #       * linux may use "!" + hash to disable but preserve original hash
        #       * linux counts empty string as "any password";
        #         this code recognizes it, but treats it the same as "!"
        if isinstance(hash, str):
            start = _MARKER_CHARS
        elif isinstance(hash, bytes):
            start = _MARKER_BYTES
        else:
            raise uh.exc.ExpectedStringError(hash, "hash")
        return not hash or hash[0] in start

    @classmethod
    def verify(cls, secret, hash):
        uh.validate_secret(secret)
        if not cls.identify(hash):  # handles typecheck
            raise uh.exc.InvalidHashError(cls)
        return False

    @classmethod
    def hash(cls, secret, **kwds):
        if kwds:
            uh.warn_hash_settings_deprecation(cls, kwds)
            return cls.using(**kwds).hash(secret)
        uh.validate_secret(secret)
        marker = cls.default_marker
        assert marker
        assert cls.identify(marker)
        return to_native_str(marker, param="marker")

    @uh.deprecated_method(deprecated="1.7", removed="2.0")
    @classmethod
    def genhash(cls, secret, config, marker=None):
        if not cls.identify(config):
            raise uh.exc.InvalidHashError(cls)

        if config:
            # preserve the existing str,since it might contain a disabled password hash ("!" + hash)
            uh.validate_secret(secret)
            return to_native_str(config, param="config")
        if marker is not None:
            cls = cls.using(marker=marker)  # noqa: PLW0642
        return cls.hash(secret)

    @classmethod
    def disable(cls, hash=None):
        out = cls.hash("")
        if hash is not None:
            hash = to_native_str(hash, param="hash")
            if cls.identify(hash):
                # extract original hash, so that we normalize marker
                hash = cls.enable(hash)
            if hash:
                out += hash
        return out

    @classmethod
    def enable(cls, hash):
        hash = to_native_str(hash, param="hash")
        for prefix in cls._disable_prefixes:
            if hash.startswith(prefix):
                orig = hash[len(prefix) :]
                if orig:
                    return orig
                raise ValueError("cannot restore original hash")
        raise uh.exc.InvalidHashError(cls)


class plaintext(uh.MinimalHandler):
    """This class stores passwords in plaintext, and follows the :ref:`password-hash-api`.

    The :meth:`~passlib.ifc.PasswordHash.hash`, :meth:`~passlib.ifc.PasswordHash.genhash`, and :meth:`~passlib.ifc.PasswordHash.verify` methods all require the
    following additional contextual keyword:

    :type encoding: str
    :param encoding:
        This controls the character encoding to use (defaults to ``utf-8``).

        This encoding will be used to encode :class:`!str` passwords
        under Python 2, and decode :class:`!bytes` hashes under Python 3.

    .. versionchanged:: 1.6
        The ``encoding`` keyword was added.
    """

    # NOTE: this is subclassed by ldap_plaintext

    name = "plaintext"
    setting_kwds = ()
    context_kwds = ("encoding",)
    default_encoding = "utf-8"

    @classmethod
    def identify(cls, hash):
        if isinstance(hash, unicode_or_bytes):
            return True
        raise uh.exc.ExpectedStringError(hash, "hash")

    @classmethod
    def hash(cls, secret, encoding=None):
        uh.validate_secret(secret)
        if not encoding:
            encoding = cls.default_encoding
        return to_native_str(secret, encoding, "secret")

    @classmethod
    def verify(cls, secret, hash, encoding=None):
        if not encoding:
            encoding = cls.default_encoding
        hash = to_native_str(hash, encoding, "hash")
        if not cls.identify(hash):
            raise uh.exc.InvalidHashError(cls)
        return consteq(cls.hash(secret, encoding), hash)

    @uh.deprecated_method(deprecated="1.7", removed="2.0")
    @classmethod
    def genconfig(cls):
        return cls.hash("")

    @uh.deprecated_method(deprecated="1.7", removed="2.0")
    @classmethod
    def genhash(cls, secret, config, encoding=None):
        # NOTE: 'config' is ignored, as this hash has no salting / etc
        if not cls.identify(config):
            raise uh.exc.InvalidHashError(cls)
        return cls.hash(secret, encoding=encoding)
