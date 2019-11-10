"""passlib.totp -- TOTP / RFC6238 / Google Authenticator utilities."""
#=============================================================================
# imports
#=============================================================================
from __future__ import absolute_import, division, print_function
from passlib.utils.compat import PY3
# core
import base64
import calendar
import json
import logging; log = logging.getLogger(__name__)
import math
import struct
import sys
import time as _time
import re
if PY3:
    from urllib.parse import urlparse, parse_qsl, quote, unquote
else:
    from urllib import quote, unquote
    from urlparse import urlparse, parse_qsl
from warnings import warn
# site
try:
    # TOTP encrypted keys only supported if cryptography (https://cryptography.io) is installed
    from cryptography.hazmat.backends import default_backend as _cg_default_backend
    import cryptography.hazmat.primitives.ciphers.algorithms
    import cryptography.hazmat.primitives.ciphers.modes
    from cryptography.hazmat.primitives import ciphers as _cg_ciphers
    del cryptography
except ImportError:
    log.debug("can't import 'cryptography' package, totp encryption disabled")
    _cg_ciphers = _cg_default_backend = None
# pkg
from passlib import exc
from passlib.exc import TokenError, MalformedTokenError, InvalidTokenError, UsedTokenError
from passlib.utils import (to_unicode, to_bytes, consteq,
                           getrandbytes, rng, SequenceMixin, xor_bytes, getrandstr)
from passlib.utils.binary import BASE64_CHARS, b32encode, b32decode
from passlib.utils.compat import (u, unicode, native_string_types, bascii_to_str, int_types, num_types,
                                  irange, byte_elem_value, UnicodeIO, suppress_cause)
from passlib.utils.decor import hybrid_method, memoized_property
from passlib.crypto.digest import lookup_hash, compile_hmac, pbkdf2_hmac
from passlib.hash import pbkdf2_sha256
# local
__all__ = [
    # frontend classes
    "AppWallet",
    "TOTP",

    # errors (defined in passlib.exc, but exposed here for convenience)
    "TokenError",
        "MalformedTokenError",
        "InvalidTokenError",
        "UsedTokenError",

    # internal helper classes
    "TotpToken",
    "TotpMatch",
]

#=============================================================================
# HACK: python < 2.7.4's urlparse() won't parse query strings unless the url scheme
#       is one of the schemes in the urlparse.uses_query list. 2.7 abandoned
#       this, and parses query if present, regardless of the scheme.
#       as a workaround for older versions, we add "otpauth" to the known list.
#       this was fixed by https://bugs.python.org/issue9374, in 2.7.4 release.
#=============================================================================
if sys.version_info < (2,7,4):
    from urlparse import uses_query
    if "otpauth" not in uses_query:
        uses_query.append("otpauth")
        log.debug("registered 'otpauth' scheme with urlparse.uses_query")
    del uses_query

#=============================================================================
# internal helpers
#=============================================================================

#-----------------------------------------------------------------------------
# token parsing / rendering helpers
#-----------------------------------------------------------------------------

#: regex used to clean whitespace from tokens & keys
_clean_re = re.compile(u(r"\s|[-=]"), re.U)

_chunk_sizes = [4,6,5]

def _get_group_size(klen):
    """
    helper for group_string() --
    calculates optimal size of group for given string size.
    """
    # look for exact divisor
    for size in _chunk_sizes:
        if not klen % size:
            return size
    # fallback to divisor with largest remainder
    # (so chunks are as close to even as possible)
    best = _chunk_sizes[0]
    rem = 0
    for size in _chunk_sizes:
        if klen % size > rem:
            best = size
            rem = klen % size
    return best

def group_string(value, sep="-"):
    """
    reformat string into (roughly) evenly-sized groups, separated by **sep**.
    useful for making tokens & keys easier to read by humans.
    """
    klen = len(value)
    size = _get_group_size(klen)
    return sep.join(value[o:o+size] for o in irange(0, klen, size))

#-----------------------------------------------------------------------------
# encoding helpers
#-----------------------------------------------------------------------------

def _decode_bytes(key, format):
    """
    internal TOTP() helper --
    decodes key according to specified format.
    """
    if format == "raw":
        if not isinstance(key, bytes):
            raise exc.ExpectedTypeError(key, "bytes", "key")
        return key
    # for encoded data, key must be either unicode or ascii-encoded bytes,
    # and must contain a hex or base32 string.
    key = to_unicode(key, param="key")
    key = _clean_re.sub("", key).encode("utf-8") # strip whitespace & hypens
    if format == "hex" or format == "base16":
        return base64.b16decode(key.upper())
    elif format == "base32":
        return b32decode(key)
    # XXX: add base64 support?
    else:
        raise ValueError("unknown byte-encoding format: %r" % (format,))

#=============================================================================
# OTP management
#=============================================================================

#: flag for detecting if encrypted totp support is present
AES_SUPPORT = bool(_cg_ciphers)

#: regex for validating secret tags
_tag_re = re.compile("(?i)^[a-z0-9][a-z0-9_.-]*$")

class AppWallet(object):
    """
    This class stores application-wide secrets that can be used
    to encrypt & decrypt TOTP keys for storage.
    It's mostly an internal detail, applications usually just need
    to pass ``secrets`` or ``secrets_path`` to :meth:`TOTP.using`.

    .. seealso::

        :ref:`totp-storing-instances` for more details on this workflow.

    Arguments
    =========
    :param secrets:
        Dict of application secrets to use when encrypting/decrypting
        stored TOTP keys.  This should include a secret to use when encrypting
        new keys, but may contain additional older secrets to decrypt
        existing stored keys.

        The dict should map tags -> secrets, so that each secret is identified
        by a unique tag.  This tag will be stored along with the encrypted
        key in order to determine which secret should be used for decryption.
        Tag should be string that starts with regex range ``[a-z0-9]``,
        and the remaining characters must be in ``[a-z0-9_.-]``.

        It is recommended to use something like a incremental counter
        ("1", "2", ...), an ISO date ("2016-01-01", "2016-05-16", ...), 
        or a timestamp ("19803495", "19813495", ...) when assigning tags.

        This mapping be provided in three formats:

        * A python dict mapping tag -> secret
        * A JSON-formatted string containing the dict
        * A multiline string with the format ``"tag: value\\ntag: value\\n..."``

        (This last format is mainly useful when loading from a text file via **secrets_path**)

        .. seealso:: :func:`generate_secret` to create a secret with sufficient entropy

    :param secrets_path:
        Alternately, callers can specify a separate file where the
        application-wide secrets are stored, using either of the string
        formats described in **secrets**.

    :param default_tag:
        Specifies which tag in **secrets** should be used as the default
        for encrypting new keys. If omitted, the tags will be sorted,
        and the largest tag used as the default.

        if all tags are numeric, they will be sorted numerically;
        otherwise they will be sorted alphabetically.
        this permits tags to be assigned numerically,
        or e.g. using ``YYYY-MM-DD`` dates.

    :param encrypt_cost:
        Optional time-cost factor for key encryption.
        This value corresponds to log2() of the number of PBKDF2
        rounds used.

    .. warning::

        The application secret(s) should be stored in a secure location by
        your application, and each secret should contain a large amount
        of entropy (to prevent brute-force attacks if the encrypted keys
        are leaked).

        :func:`generate_secret` is provided as a convenience helper
        to generate a new application secret of suitable size.

        Best practice is to load these values from a file via **secrets_path**,
        and then have your application give up permission to read this file
        once it's running.

    Public Methods
    ==============
    .. autoattribute:: has_secrets
    .. autoattribute:: default_tag

    Semi-Private Methods
    ====================
    The following methods are used internally by the :class:`TOTP`
    class in order to encrypt & decrypt keys using the provided application
    secrets.  They will generally not be publically useful, and may have their
    API changed periodically.

    .. automethod:: get_secret
    .. automethod:: encrypt_key
    .. automethod:: decrypt_key
    """
    #========================================================================
    # instance attrs
    #========================================================================

    #: default salt size for encrypt_key() output
    salt_size = 12

    #: default cost (log2 of pbkdf2 rounds) for encrypt_key() output
    #: NOTE: this is relatively low, since the majority of the security
    #: relies on a high entropy secret to pass to AES.
    encrypt_cost = 14

    #: map of secret tag -> secret bytes
    _secrets = None

    #: tag for default secret
    default_tag = None

    #========================================================================
    # init
    #========================================================================
    def __init__(self, secrets=None, default_tag=None, encrypt_cost=None,
                 secrets_path=None):

        # TODO: allow a lot more things to be customized from here,
        #       e.g. setting default TOTP constructor options.

        #
        # init cost
        #
        if encrypt_cost is not None:
            if isinstance(encrypt_cost, native_string_types):
                encrypt_cost = int(encrypt_cost)
            assert encrypt_cost >= 0
            self.encrypt_cost = encrypt_cost

        #
        # init secrets map
        #

        # load secrets from file (if needed)
        if secrets_path is not None:
            if secrets is not None:
                raise TypeError("'secrets' and 'secrets_path' are mutually exclusive")
            secrets = open(secrets_path, "rt").read()

        # parse & store secrets
        secrets = self._secrets = self._parse_secrets(secrets)

        #
        # init default tag/secret
        #
        if secrets:
            if default_tag is not None:
                # verify that tag is present in map
                self.get_secret(default_tag)
            elif all(tag.isdigit() for tag in secrets):
                default_tag = max(secrets, key=int)
            else:
                default_tag = max(secrets)
            self.default_tag = default_tag

    def _parse_secrets(self, source):
        """
        parse 'secrets' parameter

        :returns:
            Dict[tag:str, secret:bytes]
        """
        # parse string formats
        # to make this easy to pass in configuration from a separate file,
        # 'secrets' can be string using two formats -- json & "tag:value\n"
        check_type = True
        if isinstance(source, native_string_types):
            if source.lstrip().startswith(("[", "{")):
                # json list / dict
                source = json.loads(source)
            elif "\n" in source and ":" in source:
                # multiline string containing series of "tag: value\n" rows;
                # empty and "#\n" rows are ignored
                def iter_pairs(source):
                    for line in source.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            tag, secret = line.split(":", 1)
                            yield tag.strip(), secret.strip()
                source = iter_pairs(source)
                check_type = False
            else:
                raise ValueError("unrecognized secrets string format")

        # ensure we have iterable of (tag, value) pairs
        if source is None:
            return {}
        elif isinstance(source, dict):
            source = source.items()
        # XXX: could support iterable of (tag,value) pairs, but not yet needed...
        # elif check_type and (isinstance(source, str) or not isinstance(source, Iterable)):
        elif check_type:
            raise TypeError("'secrets' must be mapping, or list of items")

        # parse into final dict, normalizing contents
        return dict(self._parse_secret_pair(tag, value)
                    for tag, value in source)

    def _parse_secret_pair(self, tag, value):
        if isinstance(tag, native_string_types):
            pass
        elif isinstance(tag, int):
            tag = str(tag)
        else:
            raise TypeError("tag must be unicode/string: %r" % (tag,))
        if not _tag_re.match(tag):
            raise ValueError("tag contains invalid characters: %r" % (tag,))
        if not isinstance(value, bytes):
            value = to_bytes(value, param="secret %r" % (tag,))
        if not value:
            raise ValueError("tag contains empty secret: %r" % (tag,))
        return tag, value

    #========================================================================
    # accessing secrets
    #========================================================================

    @property
    def has_secrets(self):
        """whether at least one application secret is present"""
        return self.default_tag is not None

    def get_secret(self, tag):
        """
        resolve a secret tag to the secret (as bytes).
        throws a KeyError if not found.
        """
        secrets = self._secrets
        if not secrets:
            raise KeyError("no application secrets configured")
        try:
            return secrets[tag]
        except KeyError:
            raise suppress_cause(KeyError("unknown secret tag: %r" % (tag,)))

    #========================================================================
    # encrypted key helpers -- used internally by TOTP
    #========================================================================

    @staticmethod
    def _cipher_aes_key(value, secret, salt, cost, decrypt=False):
        """
        Internal helper for :meth:`encrypt_key` --
        handles lowlevel encryption/decryption.

        Algorithm details:

        This function uses PBKDF2-HMAC-SHA256 to generate a 32-byte AES key
        and a 16-byte IV from the application secret & random salt.
        It then uses AES-256-CTR to encrypt/decrypt the TOTP key.

        CTR mode was chosen over CBC because the main attack scenario here
        is that the attacker has stolen the database, and is trying to decrypt a TOTP key
        (the plaintext value here).  To make it hard for them, we want every password
        to decrypt to a potentially valid key -- thus need to avoid any authentication
        or padding oracle attacks.  While some random padding construction could be devised
        to make this work for CBC mode, a stream cipher mode is just plain simpler.
        OFB/CFB modes would also work here, but seeing as they have malleability
        and cyclic issues (though remote and barely relevant here),
        CTR was picked as the best overall choice.
        """
        # make sure backend AES support is available
        if _cg_ciphers is None:
            raise RuntimeError("TOTP encryption requires 'cryptography' package "
                               "(https://cryptography.io)")

        # use pbkdf2 to derive both key (32 bytes) & iv (16 bytes)
        # NOTE: this requires 2 sha256 blocks to be calculated.
        keyiv = pbkdf2_hmac("sha256", secret, salt=salt, rounds=(1 << cost), keylen=48)

        # use AES-256-CTR to encrypt/decrypt input value
        cipher = _cg_ciphers.Cipher(_cg_ciphers.algorithms.AES(keyiv[:32]),
                                    _cg_ciphers.modes.CTR(keyiv[32:]),
                                    _cg_default_backend())
        ctx = cipher.decryptor() if decrypt else cipher.encryptor()
        return ctx.update(value) + ctx.finalize()

    def encrypt_key(self, key):
        """
        Helper used to encrypt TOTP keys for storage.

        :param key:
            TOTP key to encrypt, as raw bytes.

        :returns:
            dict containing encrypted TOTP key & configuration parameters.
            this format should be treated as opaque, and potentially subject
            to change, though it is designed to be easily serialized/deserialized
            (e.g. via JSON).

        .. note::

            This function requires installation of the external
            `cryptography <https://cryptography.io>`_ package.

        To give some algorithm details:  This function uses AES-256-CTR to encrypt
        the provided data.  It takes the application secret and randomly generated salt,
        and uses PBKDF2-HMAC-SHA256 to combine them and generate the AES key & IV.
        """
        if not key:
            raise ValueError("no key provided")
        salt = getrandbytes(rng, self.salt_size)
        cost = self.encrypt_cost
        tag = self.default_tag
        if not tag:
            raise TypeError("no application secrets configured, can't encrypt OTP key")
        ckey = self._cipher_aes_key(key, self.get_secret(tag), salt, cost)
        # XXX: switch to base64?
        return dict(v=1, c=cost, t=tag, s=b32encode(salt), k=b32encode(ckey))

    def decrypt_key(self, enckey):
        """
        Helper used to decrypt TOTP keys from storage format.
        Consults configured secrets to decrypt key.

        :param source:
            source object, as returned by :meth:`encrypt_key`.

        :returns:
            ``(key, needs_recrypt)`` --

            **key** will be the decrypted key, as bytes.

            **needs_recrypt** will be a boolean flag indicating
            whether encryption cost or default tag is too old,
            and henace that key needs re-encrypting before storing.

        .. note::

            This function requires installation of the external
            `cryptography <https://cryptography.io>`_ package.
        """
        if not isinstance(enckey, dict):
            raise TypeError("'enckey' must be dictionary")
        version = enckey.get("v", None)
        needs_recrypt = False
        if version == 1:
            _cipher_key = self._cipher_aes_key
        else:
            raise ValueError("missing / unrecognized 'enckey' version: %r" % (version,))
        tag = enckey['t']
        cost = enckey['c']
        key = _cipher_key(
            value=b32decode(enckey['k']),
            secret=self.get_secret(tag),
            salt=b32decode(enckey['s']),
            cost=cost,
        )
        if cost != self.encrypt_cost or tag != self.default_tag:
            needs_recrypt = True
        return key, needs_recrypt

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# TOTP class
#=============================================================================

#: helper to convert HOTP counter to bytes
_pack_uint64 = struct.Struct(">Q").pack

#: helper to extract value from HOTP digest
_unpack_uint32 = struct.Struct(">I").unpack

#: dummy bytes used as temp key for .using() method
_DUMMY_KEY = b"\x00" * 16

class TOTP(object):
    """
    Helper for generating and verifying TOTP codes.

    Given a secret key and set of configuration options, this object
    offers methods for token generation, token validation, and serialization.
    It can also be used to track important persistent TOTP state,
    such as the last counter used.

    This class accepts the following options
    (only **key** and **format** may be specified as positional arguments).

    :arg str key:
        The secret key to use. By default, should be encoded as
        a base32 string (see **format** for other encodings).

        Exactly one of **key** or ``new=True`` must be specified.

    :arg str format:
        The encoding used by the **key** parameter. May be one of:
        ``"base32"`` (base32-encoded string),
        ``"hex"`` (hexadecimal string), or ``"raw"`` (raw bytes).
        Defaults to ``"base32"``.

    :param bool new:
        If ``True``, a new key will be generated using :class:`random.SystemRandom`.

        Exactly one ``new=True`` or **key** must be specified.

    :param str label:
        Label to associate with this token when generating a URI.
        Displayed to user by most OTP client applications (e.g. Google Authenticator),
        and typically has format such as ``"John Smith"`` or ``"jsmith@webservice.example.org"``.
        Defaults to ``None``.
        See :meth:`to_uri` for details.

    :param str issuer:
        String identifying the token issuer (e.g. the domain name of your service).
        Used internally by some OTP client applications (e.g. Google Authenticator) to distinguish entries
        which otherwise have the same label.
        Optional but strongly recommended if you're rendering to a URI.
        Defaults to ``None``.
        See :meth:`to_uri` for details.

    :param int size:
        Number of bytes when generating new keys. Defaults to size of hash algorithm (e.g. 20 for SHA1).

        .. warning::

            Overriding the default values for ``digits``, ``period``, or ``alg`` may
            cause problems with some OTP client programs (such as Google Authenticator),
            which may have these defaults hardcoded.

    :param int digits:
        The number of digits in the generated / accepted tokens. Defaults to ``6``.
        Must be in range [6 .. 10].

        .. rst-class:: inline-title
        .. caution::
           Due to a limitation of the HOTP algorithm, the 10th digit can only take on values 0 .. 2,
           and thus offers very little extra security.

    :param str alg:
        Name of hash algorithm to use. Defaults to ``"sha1"``.
        ``"sha256"`` and ``"sha512"`` are also accepted, per :rfc:`6238`.

    :param int period:
        The time-step period to use, in integer seconds. Defaults to ``30``.

    ..
        See the passlib documentation for a full list of attributes & methods.
    """
    #=============================================================================
    # class attrs
    #=============================================================================

    #: minimum number of bytes to allow in key, enforced by passlib.
    # XXX: see if spec says anything relevant to this.
    _min_key_size = 10

    #: minimum & current serialization version (may be set independently by subclasses)
    min_json_version = json_version = 1

    #: AppWallet that this class will use for encrypting/decrypting keys.
    #: (can be overwritten via the :meth:`TOTP.using()` constructor)
    wallet = None

    #: function to get system time in seconds, as needed by :meth:`generate` and :meth:`verify`.
    #: defaults to :func:`time.time`, but can be overridden on a per-instance basis.
    now = _time.time

    #=============================================================================
    # instance attrs
    #=============================================================================

    #---------------------------------------------------------------------------
    # configuration attrs
    #---------------------------------------------------------------------------

    #: [private] secret key as raw :class:`!bytes`
    #: see .key property for public access.
    _key = None

    #: [private] cached copy of encrypted secret,
    #: so .to_json() doesn't have to re-encrypt on each call.
    _encrypted_key = None

    #: [private] cached copy of keyed HMAC function,
    #: so ._generate() doesn't have to rebuild this each time
    #: ._find_match() invokes it.
    _keyed_hmac = None

    #: number of digits in the generated tokens.
    digits = 6

    #: name of hash algorithm in use (e.g. ``"sha1"``)
    alg = "sha1"

    #: default label for :meth:`to_uri`
    label = None

    #: default issuer for :meth:`to_uri`
    issuer = None

    #: number of seconds per counter step.
    #: *(TOTP uses an internal time-derived counter which
    #: increments by 1 every* :attr:`!period` *seconds)*.
    period = 30

    #---------------------------------------------------------------------------
    # state attrs
    #---------------------------------------------------------------------------

    #: Flag set by deserialization methods to indicate the object needs to be re-serialized.
    #: This can be for a number of reasons -- encoded using deprecated format,
    #: or encrypted using a deprecated key or too few rounds.
    changed = False

    #=============================================================================
    # prototype construction
    #=============================================================================
    @classmethod
    def using(cls, digits=None, alg=None, period=None,
              issuer=None, wallet=None, now=None, **kwds):
        """
        Dynamically create subtype of :class:`!TOTP` class
        which has the specified defaults set.

        :parameters: **digits, alg, period, issuer**:

            All these options are the same as in the :class:`TOTP` constructor,
            and the resulting class will use any values you specify here
            as the default for all TOTP instances it creates.

        :param wallet:
            Optional :class:`AppWallet` that will be used for encrypting/decrypting keys.

        :param secrets, secrets_path, encrypt_cost:

            If specified, these options will be passed to the :class:`AppWallet` constructor,
            allowing you to directly specify the secret keys that should be used
            to encrypt & decrypt stored keys.

        :returns:
            subclass of :class:`!TOTP`.

        This method is useful for creating a TOTP class configured
        to use your application's secrets for encrypting & decrypting
        keys, as well as create new keys using it's desired configuration defaults.

        As an example::

            >>> # your application can create a custom class when it initializes
            >>> from passlib.totp import TOTP, generate_secret
            >>> TotpFactory = TOTP.using(secrets={"1": generate_secret()})

            >>> # subsequent TOTP objects created from this factory
            >>> # will use the specified secrets to encrypt their keys...
            >>> totp = TotpFactory.new()
            >>> totp.to_dict()
            {'enckey': {'c': 14,
              'k': 'H77SYXWORDPGVOQTFRR2HFUB3C45XXI7',
              's': 'G5DOQPIHIBUM2OOHHADQ',
              't': '1',
              'v': 1},
             'type': 'totp',
             'v': 1}

        .. seealso:: :ref:`totp-creation` and :ref:`totp-storing-instances` tutorials for a usage example
        """
        # XXX: could add support for setting default match 'window' and 'reuse' policy

        # :param now:
        #     Optional callable that should return current time for generator to use.
        #     Default to :func:`time.time`. This optional is generally not needed,
        #     and is mainly present for examples & unit-testing.

        subcls = type("TOTP", (cls,), {})

        def norm_param(attr, value):
            """
            helper which uses constructor to validate parameter value.
            it returns corresponding attribute, so we use normalized value.
            """
            # NOTE: this creates *subclass* instance,
            #       so normalization takes into account any custom params
            #       already stored.
            kwds = dict(key=_DUMMY_KEY, format="raw")
            kwds[attr] = value
            obj = subcls(**kwds)
            return getattr(obj, attr)

        if digits is not None:
            subcls.digits = norm_param("digits", digits)

        if alg is not None:
            subcls.alg = norm_param("alg", alg)

        if period is not None:
            subcls.period = norm_param("period", period)

        # XXX: add default size as configurable parameter?

        if issuer is not None:
            subcls.issuer = norm_param("issuer", issuer)

        if kwds:
            subcls.wallet = AppWallet(**kwds)
            if wallet:
                raise TypeError("'wallet' and 'secrets' keywords are mutually exclusive")
        elif wallet is not None:
            if not isinstance(wallet, AppWallet):
                raise exc.ExpectedTypeError(wallet, AppWallet, "wallet")
            subcls.wallet = wallet

        if now is not None:
            assert isinstance(now(), num_types) and now() >= 0, \
                "now() function must return non-negative int/float"
            subcls.now = staticmethod(now)

        return subcls

    #=============================================================================
    # init
    #=============================================================================

    @classmethod
    def new(cls, **kwds):
        """
        convenience alias for creating new TOTP key, same as ``TOTP(new=True)``
        """
        return cls(new=True, **kwds)

    def __init__(self, key=None, format="base32",
                 # keyword only...
                 new=False, digits=None, alg=None, size=None, period=None,
                 label=None, issuer=None, changed=False,
                 **kwds):
        super(TOTP, self).__init__(**kwds)
        if changed:
            self.changed = changed

        # validate & normalize alg
        info = lookup_hash(alg or self.alg)
        self.alg = info.name
        digest_size = info.digest_size
        if digest_size < 4:
            raise RuntimeError("%r hash digest too small" % alg)

        # parse or generate new key
        if new:
            # generate new key
            if key:
                raise TypeError("'key' and 'new=True' are mutually exclusive")
            if size is None:
                # default to digest size, per RFC 6238 Section 5.1
                size = digest_size
            elif size > digest_size:
                # not forbidden by spec, but would just be wasted bytes.
                # maybe just warn about this?
                raise ValueError("'size' should be less than digest size "
                                 "(%d)" % digest_size)
            self.key = getrandbytes(rng, size)
        elif not key:
            raise TypeError("must specify either an existing 'key', or 'new=True'")
        elif format == "encrypted":
            # NOTE: this handles decrypting & setting '.key'
            self.encrypted_key = key
        elif key:
            # use existing key, encoded using specified <format>
            self.key = _decode_bytes(key, format)

        # enforce min key size
        if len(self.key) < self._min_key_size:
            # only making this fatal for new=True,
            # so that existing (but ridiculously small) keys can still be used.
            msg = "for security purposes, secret key must be >= %d bytes" % self._min_key_size
            if new:
                raise ValueError(msg)
            else:
                warn(msg, exc.PasslibSecurityWarning, stacklevel=1)

        # validate digits
        if digits is None:
            digits = self.digits
        if not isinstance(digits, int_types):
            raise TypeError("digits must be an integer, not a %r" % type(digits))
        if digits < 6 or digits > 10:
            raise ValueError("digits must in range(6,11)")
        self.digits = digits

        # validate label
        if label:
            self._check_label(label)
            self.label = label

        # validate issuer
        if issuer:
            self._check_issuer(issuer)
            self.issuer = issuer

        # init period
        if period is not None:
            self._check_serial(period, "period", minval=1)
            self.period = period

    #=============================================================================
    # helpers to verify value types & ranges
    #=============================================================================

    @staticmethod
    def _check_serial(value, param, minval=0):
        """
        check that serial value (e.g. 'counter') is non-negative integer
        """
        if not isinstance(value, int_types):
            raise exc.ExpectedTypeError(value, "int", param)
        if value < minval:
            raise ValueError("%s must be >= %d" % (param, minval))

    @staticmethod
    def _check_label(label):
        """
        check that label doesn't contain chars forbidden by KeyURI spec
        """
        if label and ":" in label:
            raise ValueError("label may not contain ':'")

    @staticmethod
    def _check_issuer(issuer):
        """
        check that issuer doesn't contain chars forbidden by KeyURI spec
        """
        if issuer and ":" in issuer:
            raise ValueError("issuer may not contain ':'")

    #=============================================================================
    # key attributes
    #=============================================================================

    #------------------------------------------------------------------
    # raw key
    #------------------------------------------------------------------
    @property
    def key(self):
        """
        secret key as raw bytes
        """
        return self._key

    @key.setter
    def key(self, value):
        # set key
        if not isinstance(value, bytes):
            raise exc.ExpectedTypeError(value, bytes, "key")
        self._key = value

        # clear cached properties derived from key
        self._encrypted_key = self._keyed_hmac = None

    #------------------------------------------------------------------
    # encrypted key
    #------------------------------------------------------------------
    @property
    def encrypted_key(self):
        """
        secret key, encrypted using application secret.
        this match the output of :meth:`AppWallet.encrypt_key`,
        and should be treated as an opaque json serializable object.
        """
        enckey = self._encrypted_key
        if enckey is None:
            wallet = self.wallet
            if not wallet:
                raise TypeError("no application secrets present, can't encrypt TOTP key")
            enckey = self._encrypted_key = wallet.encrypt_key(self.key)
        return enckey

    @encrypted_key.setter
    def encrypted_key(self, value):
        wallet = self.wallet
        if not wallet:
            raise TypeError("no application secrets present, can't decrypt TOTP key")
        self.key, needs_recrypt = wallet.decrypt_key(value)
        if needs_recrypt:
            # mark as changed so it gets re-encrypted & written to db
            self.changed = True
        else:
            # cache encrypted key for re-use
            self._encrypted_key = value

    #------------------------------------------------------------------
    # pretty-printed / encoded key helpers
    #------------------------------------------------------------------

    @property
    def hex_key(self):
        """
        secret key encoded as hexadecimal string
        """
        return bascii_to_str(base64.b16encode(self.key)).lower()

    @property
    def base32_key(self):
        """
        secret key encoded as base32 string
        """
        return b32encode(self.key)

    def pretty_key(self, format="base32", sep="-"):
        """
        pretty-print the secret key.

        This is mainly useful for situations where the user cannot get the qrcode to work,
        and must enter the key manually into their TOTP client. It tries to format
        the key in a manner that is easier for humans to read.

        :param format:
            format to output secret key. ``"hex"`` and ``"base32"`` are both accepted.

        :param sep:
            separator to insert to break up key visually.
            can be any of ``"-"`` (the default), ``" "``, or ``False`` (no separator).

        :return:
            key as native string.

        Usage example::

            >>> t = TOTP('s3jdvb7qd2r7jpxx')
            >>> t.pretty_key()
            'S3JD-VB7Q-D2R7-JPXX'
        """
        if format == "hex" or format == "base16":
            key = self.hex_key
        elif format == "base32":
            key = self.base32_key
        else:
            raise ValueError("unknown byte-encoding format: %r" % (format,))
        if sep:
            key = group_string(key, sep)
        return key

    #=============================================================================
    # time & token parsing
    #=============================================================================

    @classmethod
    def normalize_time(cls, time):
        """
        Normalize time value to unix epoch seconds.

        :arg time:
            Can be ``None``, :class:`!datetime`,
            or unix epoch timestamp as :class:`!float` or :class:`!int`.
            If ``None``, uses current system time.
            Naive datetimes are treated as UTC.

        :returns:
            unix epoch timestamp as :class:`int`.
        """
        if isinstance(time, int_types):
            return time
        elif isinstance(time, float):
            return int(time)
        elif time is None:
            return int(cls.now())
        elif hasattr(time, "utctimetuple"):
            # coerce datetime to UTC timestamp
            # NOTE: utctimetuple() assumes naive datetimes are in UTC
            # NOTE: we explicitly *don't* want microseconds.
            return calendar.timegm(time.utctimetuple())
        else:
            raise exc.ExpectedTypeError(time, "int, float, or datetime", "time")

    def _time_to_counter(self, time):
        """
        convert timestamp to HOTP counter using :attr:`period`.
        """
        return time // self.period

    def _counter_to_time(self, counter):
        """
        convert HOTP counter to timestamp using :attr:`period`.
        """
        return counter * self.period

    @hybrid_method
    def normalize_token(self_or_cls, token):
        """
        Normalize OTP token representation:
        strips whitespace, converts integers to a zero-padded string,
        validates token content & number of digits.

        This is a hybrid method -- it can be called at the class level,
        as ``TOTP.normalize_token()``, or the instance level as ``TOTP().normalize_token()``.
        It will normalize to the instance-specific number of :attr:`~TOTP.digits`,
        or use the class default.

        :arg token:
            token as ascii bytes, unicode, or an integer.

        :raises ValueError:
            if token has wrong number of digits, or contains non-numeric characters.

        :returns:
            token as :class:`!unicode` string, containing only digits 0-9.
        """
        digits = self_or_cls.digits
        if isinstance(token, int_types):
            token = u"%0*d" % (digits, token)
        else:
            token = to_unicode(token, param="token")
            token = _clean_re.sub(u"", token)
            if not token.isdigit():
                raise MalformedTokenError("Token must contain only the digits 0-9")
        if len(token) != digits:
            raise MalformedTokenError("Token must have exactly %d digits" % digits)
        return token

    #=============================================================================
    # token generation
    #=============================================================================

# # debug helper
#    def generate_range(self, size, time=None):
#        counter = self._time_to_counter(time) - (size + 1) // 2
#        end = counter + size
#        while counter <= end:
#            token = self._generate(counter)
#            yield TotpToken(self, token, counter)
#            counter += 1

    def generate(self, time=None):
        """
        Generate token for specified time
        (uses current time if none specified).

        :arg time:
            Can be ``None``, a :class:`!datetime`,
            or class:`!float` / :class:`!int` unix epoch timestamp.
            If ``None`` (the default), uses current system time.
            Naive datetimes are treated as UTC.

        :returns:

            A :class:`TotpToken` instance, which can be treated
            as a sequence of ``(token, expire_time)`` -- see that class
            for more details.

        Usage example::

            >>> # generate a new token, wrapped in a TotpToken instance...
            >>> otp = TOTP('s3jdvb7qd2r7jpxx')
            >>> otp.generate(1419622739)
            <TotpToken token='897212' expire_time=1419622740>

            >>> # when you just need the token...
            >>> otp.generate(1419622739).token
            '897212'
        """
        time = self.normalize_time(time)
        counter = self._time_to_counter(time)
        if counter < 0:
            raise ValueError("timestamp must be >= 0")
        token = self._generate(counter)
        return TotpToken(self, token, counter)

    def _generate(self, counter):
        """
        base implementation of HOTP token generation algorithm.

        :arg counter: HOTP counter, as non-negative integer
        :returns: token as unicode string
        """
        # generate digest
        assert isinstance(counter, int_types), "counter must be integer"
        assert counter >= 0, "counter must be non-negative"
        keyed_hmac = self._keyed_hmac
        if keyed_hmac is None:
            keyed_hmac = self._keyed_hmac = compile_hmac(self.alg, self.key)
        digest = keyed_hmac(_pack_uint64(counter))
        digest_size = keyed_hmac.digest_info.digest_size
        assert len(digest) == digest_size, "digest_size: sanity check failed"

        # derive 31-bit token value
        assert digest_size >= 20, "digest_size: sanity check 2 failed" # otherwise 0xF+4 will run off end of hash.
        offset = byte_elem_value(digest[-1]) & 0xF
        value = _unpack_uint32(digest[offset:offset+4])[0] & 0x7fffffff

        # render to decimal string, return last <digits> chars
        # NOTE: the 10'th digit is not as secure, as it can only take on values 0-2, not 0-9,
        #       due to 31-bit mask on int ">I". But some servers / clients use it :|
        #       if 31-bit mask removed (which breaks spec), would only get values 0-4.
        digits = self.digits
        assert 0 < digits < 11, "digits: sanity check failed"
        return (u"%0*d" % (digits, value))[-digits:]

    #=============================================================================
    # token verification
    #=============================================================================

    @classmethod
    def verify(cls, token, source, **kwds):
        r"""
        Convenience wrapper around :meth:`TOTP.from_source` and :meth:`TOTP.match`.

        This parses a TOTP key & configuration from the specified source,
        and tries and match the token.
        It's designed to parallel the :meth:`passlib.ifc.PasswordHash.verify` method.

        :param token:
            Token string to match.

        :param source:
            Serialized TOTP key.
            Can be anything accepted by :meth:`TOTP.from_source`.

        :param \*\*kwds:
            All additional keywords passed to :meth:`TOTP.match`.

        :return:
            A :class:`TotpMatch` instance, or raises a :exc:`TokenError`.
        """
        return cls.from_source(source).match(token, **kwds)

    def match(self, token, time=None, window=30, skew=0, last_counter=None):
        """
        Match TOTP token against specified timestamp.
        Searches within a window before & after the provided time,
        in order to account for transmission delay and small amounts of skew in the client's clock.

        :arg token:
            Token to validate.
            may be integer or string (whitespace and hyphens are ignored).

        :param time:
            Unix epoch timestamp, can be any of :class:`!float`, :class:`!int`, or :class:`!datetime`.
            if ``None`` (the default), uses current system time.
            *this should correspond to the time the token was received from the client*.

        :param int window:
            How far backward and forward in time to search for a match.
            Measured in seconds. Defaults to ``30``.  Typically only useful if set
            to multiples of :attr:`period`.

        :param int skew:
            Adjust timestamp by specified value, to account for excessive
            client clock skew. Measured in seconds. Defaults to ``0``.

            Negative skew (the common case) indicates transmission delay,
            and/or that the client clock is running behind the server.

            Positive skew indicates the client clock is running ahead of the server
            (and by enough that it cancels out any negative skew added by
            the transmission delay).

            You should ensure the server clock uses a reliable time source such as NTP,
            so that only the client clock's inaccuracy needs to be accounted for.

            This is an advanced parameter that should usually be left at ``0``;
            The **window** parameter is usually enough to account
            for any observed transmission delay.

        :param last_counter:
            Optional value of last counter value that was successfully used.
            If specified, verify will never search earlier counters,
            no matter how large the window is.

            Useful when client has previously authenticated,
            and thus should never provide a token older than previously
            verified value.

        :raises ~passlib.exc.TokenError:

            If the token is malformed, fails to match, or has already been used.

        :returns TotpMatch:

            Returns a :class:`TotpMatch` instance on successful match.
            Can be treated as tuple of ``(counter, time)``.
            Raises error if token is malformed / can't be verified.

        Usage example::

            >>> totp = TOTP('s3jdvb7qd2r7jpxx')

            >>> # valid token for this time period
            >>> totp.match('897212', 1419622729)
            <TotpMatch counter=47320757 time=1419622729 cache_seconds=60>

            >>> # token from counter step 30 sec ago (within allowed window)
            >>> totp.match('000492', 1419622729)
            <TotpMatch counter=47320756 time=1419622729 cache_seconds=60>

            >>> # invalid token -- token from 60 sec ago (outside of window)
            >>> totp.match('760389', 1419622729)
            Traceback:
                ...
            InvalidTokenError: Token did not match
        """
        time = self.normalize_time(time)
        self._check_serial(window, "window")

        client_time = time + skew
        if last_counter is None:
            last_counter = -1
        start = max(last_counter, self._time_to_counter(client_time - window))
        end = self._time_to_counter(client_time + window) + 1
        # XXX: could pass 'expected = _time_to_counter(client_time + TRANSMISSION_DELAY)'
        #      to the _find_match() method, would help if window set to very large value.

        counter = self._find_match(token, start, end)
        assert counter >= last_counter, "sanity check failed: counter went backward"

        if counter == last_counter:
            raise UsedTokenError(expire_time=(last_counter + 1) * self.period)

        # NOTE: By returning match tied to <time>, not <client_time>, we're
        #       causing .skipped to reflect the observed skew, independent of
        #       the 'skew' param.  This is deliberately done so that caller
        #       can use historical .skipped values to estimate future skew.
        return TotpMatch(self, counter, time, window)

    def _find_match(self, token, start, end, expected=None):
        """
        helper for verify() --
        returns counter value within specified range that matches token.

        :arg token:
            token value to match (will be normalized internally)

        :arg start:
            starting counter value to check

        :arg end:
            check up to (but not including) this counter value

        :arg expected:
            optional expected value where search should start,
            to help speed up searches.

        :raises ~passlib.exc.TokenError:
            If the token is malformed, or fails to verify.

        :returns:
            counter value that matched
        """
        token = self.normalize_token(token)
        if start < 0:
            start = 0
        if end <= start:
            raise InvalidTokenError()
        generate = self._generate
        if not (expected is None or expected < start) and consteq(token, generate(expected)):
            return expected
        # XXX: if (end - start) is very large (e.g. for resync purposes),
        #      could start with expected value, and work outward from there,
        #      alternately checking before & after it until match is found.
        # XXX: can't use irange(start, end) here since py2x/win32
        #      throws error on values >= (1<<31), which 'end' can be.
        counter = start
        while counter < end:
            if consteq(token, generate(counter)):
                return counter
            counter += 1
        raise InvalidTokenError()

    #-------------------------------------------------------------------------
    # TODO: resync(self, tokens, time=None, min_tokens=10, window=100)
    #       helper to re-synchronize using series of sequential tokens,
    #       all of which must validate; per RFC recommendation.
    # NOTE: need to make sure this function is constant time
    #       (i.e. scans ALL tokens, and doesn't short-circuit after first mismatch)
    #-------------------------------------------------------------------------

    #=============================================================================
    # generic parsing
    #=============================================================================

    @classmethod
    def from_source(cls, source):
        """
        Load / create a TOTP object from a serialized source.
        This acts as a wrapper for the various deserialization methods:

        * TOTP URIs are handed off to :meth:`from_uri`
        * Any other strings are handed off to :meth:`from_json`
        * Dicts are handed off to :meth:`from_dict`

        :param source:
            Serialized TOTP object.

        :raises ValueError:
            If the key has been encrypted, but the application secret isn't available;
            or if the string cannot be recognized, parsed, or decoded.

            See :meth:`TOTP.using()` for how to configure application secrets.

        :returns:
            a :class:`TOTP` instance.
        """
        if isinstance(source, TOTP):
            # return object unchanged if they share same wallet.
            # otherwise make a new one that's bound to expected wallet.
            if cls.wallet == source.wallet:
                return source
            source = source.to_dict(encrypt=False)
        if isinstance(source, dict):
            return cls.from_dict(source)
        # NOTE: letting to_unicode() raise TypeError in this case
        source = to_unicode(source, param="totp source")
        if source.startswith("otpauth://"):
            return cls.from_uri(source)
        else:
            return cls.from_json(source)

    #=============================================================================
    # uri parsing
    #=============================================================================
    @classmethod
    def from_uri(cls, uri):
        """
        create an OTP instance from a URI (such as returned by :meth:`to_uri`).

        :returns:
            :class:`TOTP` instance.

        :raises ValueError:
            if the uri cannot be parsed or contains errors.

        .. seealso:: :ref:`totp-configuring-clients` tutorial for a usage example
        """
        # check for valid uri
        uri = to_unicode(uri, param="uri").strip()
        result = urlparse(uri)
        if result.scheme != "otpauth":
            raise cls._uri_parse_error("wrong uri scheme")

        # validate netloc, and hand off to helper
        cls._check_otp_type(result.netloc)
        return cls._from_parsed_uri(result)

    @classmethod
    def _check_otp_type(cls, type):
        """
        validate otp URI type is supported.
        returns True or raises appropriate error.
        """
        if type == "totp":
            return True
        if type == "hotp":
            raise NotImplementedError("HOTP not supported")
        raise ValueError("unknown otp type: %r" % type)

    @classmethod
    def _from_parsed_uri(cls, result):
        """
        internal from_uri() helper --
        handles parsing a validated TOTP URI

        :param result:
            a urlparse() instance

        :returns:
            cls instance
        """

        # decode label from uri path
        label = result.path
        if label.startswith("/") and len(label) > 1:
            label = unquote(label[1:])
        else:
            raise cls._uri_parse_error("missing label")

        # extract old-style issuer prefix
        if ":" in label:
            try:
                issuer, label = label.split(":")
            except ValueError:  # too many ":"
                raise cls._uri_parse_error("malformed label")
        else:
            issuer = None
        if label:
            # NOTE: KeyURI spec says there may be leading spaces
            label = label.strip() or None

        # parse query params
        params = dict(label=label)
        for k, v in parse_qsl(result.query):
            if k in params:
                raise cls._uri_parse_error("duplicate parameter (%r)" % k)
            params[k] = v

        # synchronize issuer prefix w/ issuer param
        if issuer:
            if "issuer" not in params:
                params['issuer'] = issuer
            elif params['issuer'] != issuer:
                raise cls._uri_parse_error("conflicting issuer identifiers")

        # convert query params to constructor kwds, and call constructor
        return cls(**cls._adapt_uri_params(**params))

    @classmethod
    def _adapt_uri_params(cls, label=None, secret=None, issuer=None,
                          digits=None, algorithm=None, period=None,
                          **extra):
        """
        from_uri() helper --
        converts uri params into constructor args.
        """
        assert label, "from_uri() failed to provide label"
        if not secret:
            raise cls._uri_parse_error("missing 'secret' parameter")
        kwds = dict(label=label, issuer=issuer, key=secret, format="base32")
        if digits:
            kwds['digits'] = cls._uri_parse_int(digits, "digits")
        if algorithm:
            kwds['alg'] = algorithm
        if period:
            kwds['period'] = cls._uri_parse_int(period, "period")
        if extra:
            # malicious uri, deviation from spec, or newer revision of spec?
            # in either case, we issue warning and ignore extra params.
            warn("%s: unexpected parameters encountered in otp uri: %r" %
                 (cls, extra), exc.PasslibRuntimeWarning)
        return kwds

    @staticmethod
    def _uri_parse_error(reason):
        """uri parsing helper -- creates preformatted error message"""
        return ValueError("Invalid otpauth uri: %s" % (reason,))

    @classmethod
    def _uri_parse_int(cls, source, param):
        """uri parsing helper -- int() wrapper"""
        try:
            return int(source)
        except ValueError:
            raise cls._uri_parse_error("Malformed %r parameter" % param)

    #=============================================================================
    # uri rendering
    #=============================================================================
    def to_uri(self, label=None, issuer=None):
        """
        Serialize key and configuration into a URI, per
        Google Auth's `KeyUriFormat <http://code.google.com/p/google-authenticator/wiki/KeyUriFormat>`_.

        :param str label:
            Label to associate with this token when generating a URI.
            Displayed to user by most OTP client applications (e.g. Google Authenticator),
            and typically has format such as ``"John Smith"`` or ``"jsmith@webservice.example.org"``.

            Defaults to **label** constructor argument. Must be provided in one or the other location.
            May not contain ``:``.

        :param str issuer:
            String identifying the token issuer (e.g. the domain or canonical name of your service).
            Optional but strongly recommended if you're rendering to a URI.
            Used internally by some OTP client applications (e.g. Google Authenticator) to distinguish entries
            which otherwise have the same label.

            Defaults to **issuer** constructor argument, or ``None``.
            May not contain ``:``.

        :raises ValueError:
            * if a label was not provided either as an argument, or in the constructor.
            * if the label or issuer contains invalid characters.

        :returns:
            all the configuration information for this OTP token generator,
            encoded into a URI.

        These URIs are frequently converted to a QRCode for transferring
        to a TOTP client application such as Google Auth.
        Usage example::

            >>> from passlib.totp import TOTP
            >>> tp = TOTP('s3jdvb7qd2r7jpxx')
            >>> uri = tp.to_uri("user@example.org", "myservice.another-example.org")
            >>> uri
            'otpauth://totp/user@example.org?secret=S3JDVB7QD2R7JPXX&issuer=myservice.another-example.org'

        .. versionchanged:: 1.7.2

            This method now prepends the issuer URI label.  This is recommended by the KeyURI
            specification, for compatibility with older clients.
        """
        # encode label
        if label is None:
            label = self.label
        if not label:
            raise ValueError("a label must be specified as argument, or in the constructor")
        self._check_label(label)
        # NOTE: reference examples in spec seem to indicate the '@' in a label
        #       shouldn't be escaped, though spec doesn't explicitly address this.
        # XXX: is '/' ok to leave unencoded?
        label = quote(label, '@')

        # encode query parameters
        params = self._to_uri_params()
        if issuer is None:
            issuer = self.issuer
        if issuer:
            self._check_issuer(issuer)
            # NOTE: per KeyURI spec, including issuer as part of label is deprecated,
            #       in favor of adding it to query params.  however, some QRCode clients
            #       don't recognize the 'issuer' query parameter, so spec recommends (as of 2018-7)
            #       to include both.
            label = "%s:%s" % (quote(issuer, '@'), label)
            params.append(("issuer", issuer))
        # NOTE: not using urllib.urlencode() because it encodes ' ' as '+';
        #       but spec says to use '%20', and not sure how fragile
        #       the various totp clients' parsers are.
        param_str = u"&".join(u"%s=%s" % (key, quote(value, '')) for key, value in params)
        assert param_str, "param_str should never be empty"

        # render uri
        return u"otpauth://totp/%s?%s" % (label, param_str)

    def _to_uri_params(self):
        """return list of (key, param) entries for URI"""
        args = [("secret", self.base32_key)]
        if self.alg != "sha1":
            args.append(("algorithm", self.alg.upper()))
        if self.digits != 6:
            args.append(("digits", str(self.digits)))
        if self.period != 30:
            args.append(("period", str(self.period)))
        return args

    #=============================================================================
    # json rendering / parsing
    #=============================================================================

    @classmethod
    def from_json(cls, source):
        """
        Load / create an OTP object from a serialized json string
        (as generated by :meth:`to_json`).

        :arg json:
            Serialized output from :meth:`to_json`, as unicode or ascii bytes.

        :raises ValueError:
            If the key has been encrypted, but the application secret isn't available;
            or if the string cannot be recognized, parsed, or decoded.

            See :meth:`TOTP.using()` for how to configure application secrets.

        :returns:
            a :class:`TOTP` instance.

        .. seealso:: :ref:`totp-storing-instances` tutorial for a usage example
        """
        source = to_unicode(source, param="json source")
        return cls.from_dict(json.loads(source))

    def to_json(self, encrypt=None):
        """
        Serialize configuration & internal state to a json string,
        mainly useful for persisting client-specific state in a database.
        All keywords passed to :meth:`to_dict`.

        :returns:
            json string containing serializes configuration & state.
        """
        state = self.to_dict(encrypt=encrypt)
        return json.dumps(state, sort_keys=True, separators=(",", ":"))

    #=============================================================================
    # dict rendering / parsing
    #=============================================================================

    @classmethod
    def from_dict(cls, source):
        """
        Load / create a TOTP object from a dictionary
        (as generated by :meth:`to_dict`)

        :param source:
            dict containing serialized TOTP key & configuration.

        :raises ValueError:
            If the key has been encrypted, but the application secret isn't available;
            or if the dict cannot be recognized, parsed, or decoded.

            See :meth:`TOTP.using()` for how to configure application secrets.

        :returns:
            A :class:`TOTP` instance.

        .. seealso:: :ref:`totp-storing-instances` tutorial for a usage example
        """
        if not isinstance(source, dict) or "type" not in source:
            raise cls._dict_parse_error("unrecognized format")
        return cls(**cls._adapt_dict_kwds(**source))

    @classmethod
    def _adapt_dict_kwds(cls, type, **kwds):
        """
        Internal helper for .from_json() --
        Adapts serialized json dict into constructor keywords.
        """
        # default json format is just serialization of constructor kwds.
        # XXX: just pass all this through to _from_json / constructor?
        # go ahead and mark as changed (needs re-saving) if the version is too old
        assert cls._check_otp_type(type)
        ver = kwds.pop("v", None)
        if not ver or ver < cls.min_json_version or ver > cls.json_version:
            raise cls._dict_parse_error("missing/unsupported version (%r)" % (ver,))
        elif ver != cls.json_version:
            # mark older version as needing re-serializing
            kwds['changed'] = True
        if 'enckey' in kwds:
            # handing encrypted key off to constructor, which handles the
            # decryption. this lets it get ahold of (and store) the original
            # encrypted key, so if to_json() is called again, the encrypted
            # key can be re-used.
            # XXX: wallet is known at this point, could decrypt key here.
            assert 'key' not in kwds  # shouldn't be present w/ enckey
            kwds.update(key=kwds.pop("enckey"), format="encrypted")
        elif 'key' not in kwds:
            raise cls._dict_parse_error("missing 'enckey' / 'key'")
        # XXX: could should set changed=True if active wallet is available,
        #      and source wasn't encrypted.
        kwds.pop("last_counter", None) # extract legacy counter parameter
        return kwds

    @staticmethod
    def _dict_parse_error(reason):
        """dict parsing helper -- creates preformatted error message"""
        return ValueError("Invalid totp data: %s" % (reason,))

    def to_dict(self, encrypt=None):
        """
        Serialize configuration & internal state to a dict,
        mainly useful for persisting client-specific state in a database.

        :param encrypt:
            Whether to output should be encrypted.

            * ``None`` (the default) -- uses encrypted key if application
              secrets are available, otherwise uses plaintext key.
            * ``True`` -- uses encrypted key, or raises TypeError
              if application secret wasn't provided to OTP constructor.
            * ``False`` -- uses raw key.

        :returns:
            dictionary, containing basic (json serializable) datatypes.
        """
        # NOTE: 'type' may seem redundant, but using it so code can try to
        #       detect that this *is* a TOTP json string / dict.
        state = dict(v=self.json_version, type="totp")
        if self.alg != "sha1":
            state['alg'] = self.alg
        if self.digits != 6:
            state['digits'] = self.digits
        if self.period != 30:
            state['period'] = self.period
        # XXX: should we include label as part of json format?
        if self.label:
            state['label'] = self.label
        issuer = self.issuer
        if issuer and issuer != type(self).issuer:
            # (omit issuer if it matches class default)
            state['issuer'] = issuer
        if encrypt is None:
            wallet = self.wallet
            encrypt = wallet and wallet.has_secrets
        if encrypt:
            state['enckey'] = self.encrypted_key
        else:
            state['key'] = self.base32_key
        # NOTE: in the future, may add a "history" parameter
        #       containing a list of (time, skipped) pairs, encoding
        #       the last X successful verifications, to allow persisting
        #       & estimating client clock skew over time.
        return state

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# TOTP helpers
#=============================================================================
class TotpToken(SequenceMixin):
    """
    Object returned by :meth:`TOTP.generate`.
    It can be treated as a sequence of ``(token, expire_time)``,
    or accessed via the following attributes:

    .. autoattribute:: token
    .. autoattribute:: expire_time
    .. autoattribute:: counter
    .. autoattribute:: remaining
    .. autoattribute:: valid
    """
    #: TOTP object that generated this token
    totp = None

    #: Token as decimal-encoded ascii string.
    token = None

    #: HOTP counter value used to generate token (derived from time)
    counter = None

    def __init__(self, totp, token, counter):
        """
        .. warning::
            the constructor signature is an internal detail, and is subject to change.
        """
        self.totp = totp
        self.token = token
        self.counter = counter

    @memoized_property
    def start_time(self):
        """Timestamp marking beginning of period when token is valid"""
        return self.totp._counter_to_time(self.counter)

    @memoized_property
    def expire_time(self):
        """Timestamp marking end of period when token is valid"""
        return self.totp._counter_to_time(self.counter + 1)

    @property
    def remaining(self):
        """number of (float) seconds before token expires"""
        return max(0, self.expire_time - self.totp.now())

    @property
    def valid(self):
        """whether token is still valid"""
        return bool(self.remaining)

    def _as_tuple(self):
        return self.token, self.expire_time

    def __repr__(self):
        expired = "" if self.remaining else " expired"
        return "<TotpToken token='%s' expire_time=%d%s>" % \
               (self.token, self.expire_time, expired)


class TotpMatch(SequenceMixin):
    """
    Object returned by :meth:`TOTP.match` and :meth:`TOTP.verify` on a successful match.

    It can be treated as a sequence of ``(counter, time)``,
    or accessed via the following attributes:

    .. autoattribute:: counter
        :annotation: = 0

    .. autoattribute:: time
        :annotation: = 0

    .. autoattribute:: expected_counter
        :annotation: = 0

    .. autoattribute:: skipped
        :annotation: = 0

    .. autoattribute:: expire_time
        :annotation: = 0

    .. autoattribute:: cache_seconds
        :annotation: = 60

    .. autoattribute:: cache_time
        :annotation: = 0

    This object will always have a ``True`` boolean value.
    """

    #: TOTP object that generated this token
    totp = None

    #: TOTP counter value which matched token.
    #: (Best practice is to subsequently ignore tokens matching this counter
    #: or earlier)
    counter = 0

    #: Timestamp when verification was performed.
    time = 0

    #: Search window used by verify() (affects cache_time)
    window = 30

    def __init__(self, totp, counter, time, window=30):
        """
        .. warning::
            the constructor signature is an internal detail, and is subject to change.
        """
        self.totp = totp
        self.counter = counter
        self.time = time
        self.window = window

    @memoized_property
    def expected_counter(self):
        """
        Counter value expected for timestamp.
        """
        return self.totp._time_to_counter(self.time)

    @memoized_property
    def skipped(self):
        """
        How many steps were skipped between expected and actual matched counter
        value (may be positive, zero, or negative).
        """
        return self.counter - self.expected_counter

    # @memoized_property
    # def start_time(self):
    #     """Timestamp marking start of period when token is valid"""
    #     return self.totp._counter_to_time(self.counter + 1)

    @memoized_property
    def expire_time(self):
        """Timestamp marking end of period when token is valid"""
        return self.totp._counter_to_time(self.counter + 1)

    @memoized_property
    def cache_seconds(self):
        """
        Number of seconds counter should be cached
        before it's guaranteed to have passed outside of verification window.
        """
        # XXX: real value is 'cache_time - now()',
        #      but this is a cheaper upper bound.
        return self.totp.period + self.window

    @memoized_property
    def cache_time(self):
        """
        Timestamp marking when counter has passed outside of verification window.
        """
        return self.expire_time + self.window

    def _as_tuple(self):
        return self.counter, self.time

    def __repr__(self):
        args = (self.counter, self.time, self.cache_seconds)
        return "<TotpMatch counter=%d time=%d cache_seconds=%d>" % args

#=============================================================================
# convenience helpers
#=============================================================================

def generate_secret(entropy=256, charset=BASE64_CHARS[:-2]):
    """
    generate a random string suitable for use as an
    :class:`AppWallet` application secret.

    :param entropy:
        number of bits of entropy (controls size/complexity of password).
    """
    assert entropy > 0
    assert len(charset) > 1
    count = int(math.ceil(entropy * math.log(2, len(charset))))
    return getrandstr(rng, charset, count)

#=============================================================================
# eof
#=============================================================================
