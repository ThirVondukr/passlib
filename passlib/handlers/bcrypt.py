"""implementation of OpenBSD's BCrypt algorithm.

TODO:

* support 2x and altered-2a hashes?
  http://www.openwall.com/lists/oss-security/2011/06/27/9

* deal with lack of PY3-compatibile c-ext implementation
"""

from __future__ import annotations

import re
from base64 import b64encode
from hashlib import sha256
from importlib import metadata
from importlib.util import find_spec
from warnings import warn

import passlib.utils.handlers as uh
from passlib._logging import logger
from passlib.crypto.digest import compile_hmac
from passlib.exc import PasslibHashWarning, PasslibSecurityError
from passlib.utils import (
    repeat_string,
    to_unicode,
    utf8_repeat_string,
    utf8_truncate,
)
from passlib.utils.binary import bcrypt64

_bcrypt = None  # dynamically imported by _load_backend_bcrypt()

__all__ = [
    "bcrypt",
]

IDENT_2 = "$2$"
IDENT_2A = "$2a$"
IDENT_2X = "$2x$"
IDENT_2Y = "$2y$"
IDENT_2B = "$2b$"
_BNULL = b"\x00"

# reference hash of "test", used in various self-checks
TEST_HASH_2A = "$2a$04$5BJqKfqMQvV7nS.yUguNcueVirQqDBGaLXSqj.rs.pZPlNR0UX/HK"


def _detect_pybcrypt():
    """
    internal helper which tries to distinguish pybcrypt vs bcrypt.

    :returns:
        True if cext-based py-bcrypt,
        False if ffi-based bcrypt,
        None if 'bcrypt' module not found.

    .. versionchanged:: 1.6.3

        Now assuming bcrypt installed, unless py-bcrypt explicitly detected.
        Previous releases assumed py-bcrypt by default.

        Making this change since py-bcrypt is (apparently) unmaintained and static,
        whereas bcrypt is being actively maintained, and it's internal structure may shift.
    """
    # NOTE: this is also used by the unittests.

    # check for module.
    if find_spec("bcrypt") is None:
        return False

    # py-bcrypt has a "._bcrypt.__version__" attribute (confirmed for v0.1 - 0.4),
    # which bcrypt lacks (confirmed for v1.0 - 2.0)
    # "._bcrypt" alone isn't sufficient, since bcrypt 2.0 now has that attribute.
    try:
        from bcrypt._bcrypt import (  # type: ignore[import-not-found]  #  noqa: F401
            __version__,
        )
    except ImportError:
        return False
    return True


class _BcryptCommon(  # type: ignore[misc]
    uh.SubclassBackendMixin,
    uh.TruncateMixin,
    uh.HasManyIdents,
    uh.HasRounds,
    uh.HasSalt,
    uh.GenericHandler,
):
    """
    Base class which implements brunt of BCrypt code.
    This is then subclassed by the various backends,
    to override w/ backend-specific methods.

    When a backend is loaded, the bases of the 'bcrypt' class proper
    are modified to prepend the correct backend-specific subclass.
    """

    # --------------------
    # PasswordHash
    # --------------------
    name = "bcrypt"
    setting_kwds: tuple[str, ...] = ("salt", "rounds", "ident", "truncate_error")

    # --------------------
    # GenericHandler
    # --------------------
    checksum_size = 31
    checksum_chars = bcrypt64.charmap

    # --------------------
    # HasManyIdents
    # --------------------
    default_ident = IDENT_2B
    ident_values: tuple[str, ...] = (IDENT_2, IDENT_2A, IDENT_2X, IDENT_2Y, IDENT_2B)
    ident_aliases = {"2": IDENT_2, "2a": IDENT_2A, "2y": IDENT_2Y, "2b": IDENT_2B}

    # --------------------
    # HasSalt
    # --------------------
    min_salt_size = max_salt_size = 22
    salt_chars = bcrypt64.charmap

    # NOTE: 22nd salt char must be in restricted set of ``final_salt_chars``, not full set above.
    final_salt_chars = ".Oeu"  # bcrypt64._padinfo2[1]

    # --------------------
    # HasRounds
    # --------------------
    default_rounds = 12  # current passlib default
    min_rounds = 4  # minimum from bcrypt specification
    max_rounds = 31  # 32-bit integer limit (since real_rounds=1<<rounds)
    rounds_cost = "log2"

    # --------------------
    # TruncateMixin
    # --------------------
    truncate_size: int | None = 72

    # --------------------
    # custom
    # --------------------

    # backend workaround detection flags
    # NOTE: these are only set on the backend mixin classes
    _workrounds_initialized = False
    _has_2a_wraparound_bug = False
    _lacks_20_support = False
    _lacks_2y_support = False
    _lacks_2b_support = False
    _fallback_ident = IDENT_2A
    _require_valid_utf8_bytes = False

    @classmethod
    def from_string(cls, hash):
        ident, tail = cls._parse_ident(hash)
        if ident == IDENT_2X:
            raise ValueError(
                "crypt_blowfish's buggy '2x' hashes are not currently supported"
            )
        rounds_str, data = tail.split("$")
        rounds = int(rounds_str)
        if rounds_str != "%02d" % (rounds,):
            raise uh.exc.MalformedHashError(cls, "malformed cost field")
        salt, chk = data[:22], data[22:]
        return cls(
            rounds=rounds,
            salt=salt,
            checksum=chk or None,
            ident=ident,
        )

    def to_string(self):
        return "%s%02d$%s%s" % (self.ident, self.rounds, self.salt, self.checksum)

    # NOTE: this should be kept separate from to_string()
    #       so that bcrypt_sha256() can still use it, while overriding to_string()
    def _get_config(self, ident):
        """internal helper to prepare config string for backends"""
        return "%s%02d$%s" % (ident, self.rounds, self.salt)

    @classmethod
    def needs_update(cls, hash, **kwds):
        # NOTE: can't convert this to use _calc_needs_update() helper,
        #       since _norm_hash() will correct salt padding before we can read it here.
        # check for incorrect padding bits (passlib issue 25)
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        if hash.startswith(IDENT_2A) and hash[28] not in cls.final_salt_chars:
            return True

        # TODO: try to detect incorrect 8bit/wraparound hashes using kwds.get("secret")

        # hand off to base implementation, so HasRounds can check rounds value.
        return super().needs_update(hash, **kwds)

    @classmethod
    def normhash(cls, hash):
        """helper to normalize hash, correcting any bcrypt padding bits"""
        if cls.identify(hash):
            return cls.from_string(hash).to_string()
        return hash

    @classmethod
    def _generate_salt(cls):
        # generate random salt as normal,
        # but repair last char so the padding bits always decode to zero.
        salt = super()._generate_salt()
        return bcrypt64.repair_unused(salt)

    @classmethod
    def _norm_salt(cls, salt, **kwds):
        salt = super()._norm_salt(salt, **kwds)
        assert salt is not None, "HasSalt didn't generate new salt!"
        changed, salt = bcrypt64.check_repair_unused(salt)
        if changed:
            # FIXME: if salt was provided by user, this message won't be
            # correct. not sure if we want to throw error, or use different warning.
            warn(
                "encountered a bcrypt salt with incorrectly set padding bits; "
                "you may want to use bcrypt.normhash() "
                "to fix this; this will be an error under Passlib 2.0",
                PasslibHashWarning,
            )
        return salt

    def _norm_checksum(self, checksum, relaxed=False):
        checksum = super()._norm_checksum(checksum, relaxed=relaxed)
        changed, checksum = bcrypt64.check_repair_unused(checksum)
        if changed:
            warn(
                "encountered a bcrypt hash with incorrectly set padding bits; "
                "you may want to use bcrypt.normhash() "
                "to fix this; this will be an error under Passlib 2.0",
                PasslibHashWarning,
            )
        return checksum

    # ===================================================================
    # backend configuration
    # NOTE: backends are defined in terms of mixin classes,
    #       which are dynamically inserted into the bases of the 'bcrypt' class
    #       via the machinery in 'SubclassBackendMixin'.
    #       this lets us load in a backend-specific implementation
    #       of _calc_checksum() and similar methods.
    # ===================================================================

    # NOTE: backend config is located down in <bcrypt> class

    # NOTE: set_backend() will execute the ._load_backend_mixin()
    #       of the matching mixin class, which will handle backend detection

    # appended to HasManyBackends' "no backends available" error message
    _no_backend_suggestion = " -- recommend you install one (e.g. 'pip install bcrypt')"

    @classmethod
    def _finalize_backend_mixin(mixin_cls, backend, dryrun):
        """
        helper called by from backend mixin classes' _load_backend_mixin() --
        invoked after backend imports have been loaded, and performs
        feature detection & testing common to all backends.
        """
        # ----------------------------------------------------------------
        # setup helpers
        # ----------------------------------------------------------------
        assert mixin_cls is bcrypt._backend_mixin_map[backend], (
            "_configure_workarounds() invoked from wrong class"
        )

        if mixin_cls._workrounds_initialized:
            return True

        verify = mixin_cls.verify

        err_types = (ValueError, uh.exc.MissingBackendError)

        def safe_verify(secret, hash):
            """verify() wrapper which traps 'unknown identifier' errors"""
            try:
                return verify(secret, hash)
            except err_types:
                # backends without support for given ident will throw various
                # errors about unrecognized version:
                #   os_crypt -- internal code below throws
                #       - PasswordValueError if there's encoding issue w/ password.
                #       - InternalBackendError if crypt fails for unknown reason
                #         (trapped below so we can debug it)
                #   pybcrypt, bcrypt -- raises ValueError
                return NotImplemented
            except uh.exc.InternalBackendError:
                # _calc_checksum() code may also throw CryptBackendError
                # if correct hash isn't returned (e.g. 2y hash converted to 2b,
                # such as happens with bcrypt 3.0.0)
                logger.debug(
                    "trapped unexpected response from %r backend: verify(%r, %r):",
                    backend,
                    secret,
                    hash,
                    exc_info=True,
                )
                return NotImplemented

        def assert_lacks_8bit_bug(ident):
            """
            helper to check for cryptblowfish 8bit bug (fixed in 2y/2b);
            even though it's not known to be present in any of passlib's backends.
            this is treated as FATAL, because it can easily result in seriously malformed hashes,
            and we can't correct for it ourselves.

            test cases from <http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/glibc/crypt_blowfish/wrapper.c.diff?r1=1.9;r2=1.10>
            reference hash is the incorrectly generated $2x$ hash taken from above url
            """
            # NOTE: passlib 1.7.2 and earlier used the commented-out LATIN-1 test vector to detect
            #       this bug; but python3's crypt.crypt() only supports unicode inputs (and
            #       always encodes them as UTF8 before passing to crypt); so passlib 1.7.3
            #       switched to the UTF8-compatible test vector below.  This one's bug_hash value
            #       ("$2x$...rcAS") was drawn from the same openwall source (above); and the correct
            #       hash ("$2a$...X6eu") was generated by passing the raw bytes to python2's
            #       crypt.crypt() using OpenBSD 6.7 (hash confirmed as same for $2a$ & $2b$).

            # LATIN-1 test vector
            # secret = b"\xA3"
            # bug_hash = ident.encode("ascii") + b"05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"
            # correct_hash = ident.encode("ascii") + b"05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"

            # UTF-8 test vector
            secret = b"\xd1\x91"  # aka "\u0451"
            bug_hash = (
                ident.encode("ascii")
                + b"05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS"
            )
            correct_hash = (
                ident.encode("ascii")
                + b"05$6bNw2HLQYeqHYyBfLMsv/OUcZd0LKP39b87nBw3.S2tVZSqiQX6eu"
            )

            if verify(secret, bug_hash):
                # NOTE: this only EVER be observed in (broken) 2a and (backward-compat) 2x hashes
                #       generated by crypt_blowfish library. 2y/2b hashes should not have the bug
                #       (but we check w/ them anyways).
                raise PasslibSecurityError(
                    f"passlib.hash.bcrypt: Your installation of the {backend!r} backend is vulnerable to "
                    f"the crypt_blowfish 8-bit bug (CVE-2011-2483) under {ident!r} hashes, "
                    "and should be upgraded or replaced with another backend"
                )

            # it doesn't have wraparound bug, but make sure it *does* verify against the correct
            # hash, or we're in some weird third case!
            if not verify(secret, correct_hash):
                raise RuntimeError(
                    f"{backend} backend failed to verify {ident} 8bit hash"
                )

        def detect_wrap_bug(ident):
            """
            check for bsd wraparound bug (fixed in 2b)
            this is treated as a warning, because it's rare in the field,
            and pybcrypt (as of 2015-7-21) is unpatched, but some people may be stuck with it.

            test cases from <http://www.openwall.com/lists/oss-security/2012/01/02/4>

            NOTE: reference hash is of password "0"*72

            NOTE: if in future we need to deliberately create hashes which have this bug,
                  can use something like 'hashpw(repeat_string(secret[:((1+secret) % 256) or 1]), 72)'
            """
            # check if it exhibits wraparound bug
            secret = (b"0123456789" * 26)[:255]
            bug_hash = (
                ident.encode("ascii")
                + b"04$R1lJ2gkNaoPGdafE.H.16.nVyh2niHsGJhayOHLMiXlI45o8/DU.6"
            )
            if verify(secret, bug_hash):
                return True

            # if it doesn't have wraparound bug, make sure it *does* handle things
            # correctly -- or we're in some weird third case.
            correct_hash = (
                ident.encode("ascii")
                + b"04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi"
            )
            if not verify(secret, correct_hash):
                raise RuntimeError(
                    f"{backend} backend failed to verify {ident} wraparound hash"
                )

            return False

        def assert_lacks_wrap_bug(ident):
            if not detect_wrap_bug(ident):
                return
            # should only see in 2a, later idents should NEVER exhibit this bug:
            # * 2y implementations should have been free of it
            # * 2b was what (supposedly) fixed it
            raise RuntimeError(
                f"{backend} backend unexpectedly has wraparound bug for {ident}"
            )

        # ----------------------------------------------------------------
        # check for old 20 support
        # ----------------------------------------------------------------
        test_hash_20 = b"$2$04$5BJqKfqMQvV7nS.yUguNcuRfMMOXK0xPWavM7pOzjEi5ze5T1k8/S"
        result = safe_verify("test", test_hash_20)
        if result is NotImplemented:
            mixin_cls._lacks_20_support = True
            logger.debug("%r backend lacks $2$ support, enabling workaround", backend)
        elif not result:
            raise RuntimeError(f"{backend} incorrectly rejected $2$ hash")

        # ----------------------------------------------------------------
        # check for 2a support
        # ----------------------------------------------------------------
        result = safe_verify("test", TEST_HASH_2A)
        if result is NotImplemented:
            # 2a support is required, and should always be present
            raise RuntimeError(f"{backend} lacks support for $2a$ hashes")
        if not result:
            raise RuntimeError(f"{backend} incorrectly rejected $2a$ hash")
        assert_lacks_8bit_bug(IDENT_2A)
        if detect_wrap_bug(IDENT_2A):
            if backend == "os_crypt":
                # don't make this a warning for os crypt (e.g. openbsd);
                # they'll have proper 2b implementation which will be used for new hashes.
                # so even if we didn't have a workaround, this bug wouldn't be a concern.
                logger.debug(
                    "%r backend has $2a$ bsd wraparound bug, enabling workaround",
                    backend,
                )
            else:
                # installed library has the bug -- want to let users know,
                # so they can upgrade it to something better (e.g. bcrypt cffi library)
                warn(
                    f"passlib.hash.bcrypt: Your installation of the {backend!r} backend is vulnerable to "
                    "the bsd wraparound bug, "
                    "and should be upgraded or replaced with another backend "
                    "(enabling workaround for now).",
                    uh.exc.PasslibSecurityWarning,
                )
            mixin_cls._has_2a_wraparound_bug = True

        # ----------------------------------------------------------------
        # check for 2y support
        # ----------------------------------------------------------------
        test_hash_2y = TEST_HASH_2A.replace("2a", "2y")
        result = safe_verify("test", test_hash_2y)
        if result is NotImplemented:
            mixin_cls._lacks_2y_support = True
            logger.debug("%r backend lacks $2y$ support, enabling workaround", backend)
        elif not result:
            raise RuntimeError(f"{backend} incorrectly rejected $2y$ hash")
        else:
            # NOTE: Not using this as fallback candidate,
            #       lacks wide enough support across implementations.
            assert_lacks_8bit_bug(IDENT_2Y)
            assert_lacks_wrap_bug(IDENT_2Y)

        # ----------------------------------------------------------------
        # TODO: check for 2x support
        # ----------------------------------------------------------------

        # ----------------------------------------------------------------
        # check for 2b support
        # ----------------------------------------------------------------
        test_hash_2b = TEST_HASH_2A.replace("2a", "2b")
        result = safe_verify("test", test_hash_2b)
        if result is NotImplemented:
            mixin_cls._lacks_2b_support = True
            logger.debug("%r backend lacks $2b$ support, enabling workaround", backend)
        elif not result:
            raise RuntimeError(f"{backend} incorrectly rejected $2b$ hash")
        else:
            mixin_cls._fallback_ident = IDENT_2B
            assert_lacks_8bit_bug(IDENT_2B)
            assert_lacks_wrap_bug(IDENT_2B)

        # set flag so we don't have to run this again
        mixin_cls._workrounds_initialized = True
        return True

    # _calc_checksum() defined by backends

    def _prepare_digest_args(self, secret):
        """
        common helper for backends to implement _calc_checksum().
        takes in secret, returns (secret, ident) pair,
        """
        return self._norm_digest_args(secret, self.ident, new=self.use_defaults)

    @classmethod
    def _norm_digest_args(cls, secret, ident, new=False):
        # make sure secret is unicode
        require_valid_utf8_bytes = cls._require_valid_utf8_bytes
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        elif require_valid_utf8_bytes:
            # if backend requires utf8 bytes (os_crypt);
            # make sure input actually is utf8, or don't bother enabling utf-8 specific helpers.
            try:
                secret.decode("utf-8")
            except UnicodeDecodeError:
                # XXX: could just throw PasswordValueError here, backend will just do that
                #      when _calc_digest() is actually called.
                require_valid_utf8_bytes = False

        # check max secret size
        uh.validate_secret(secret)

        # check for truncation (during .hash() calls only)
        if new:
            cls._check_truncate_policy(secret)

        # NOTE: especially important to forbid NULLs for bcrypt, since many
        # backends (bcrypt) happily accept them, and then
        # silently truncate the password at first NULL they encounter!
        if _BNULL in secret:
            raise uh.exc.NullPasswordError(cls)

        # TODO: figure out way to skip these tests when not needed...

        # protect from wraparound bug by truncating secret before handing it to the backend.
        # bcrypt only uses first 72 bytes anyways.
        # NOTE: not needed for 2y/2b, but might use 2a as fallback for them.
        if cls._has_2a_wraparound_bug and len(secret) >= 255:
            if require_valid_utf8_bytes:
                # backend requires valid utf8 bytes, so truncate secret to nearest valid segment.
                # want to do this in constant time to not give away info about secret.
                # NOTE: this only works because bcrypt will ignore everything past
                #       secret[71], so padding to include a full utf8 sequence
                #       won't break anything about the final output.
                secret = utf8_truncate(secret, 72)
            else:
                secret = secret[:72]

        # special case handling for variants (ordered most common first)
        if ident == IDENT_2A:
            # nothing needs to be done.
            pass

        elif ident == IDENT_2B:
            if cls._lacks_2b_support:
                # handle $2b$ hash format even if backend is too old.
                # have it generate a 2A/2Y digest, then return it as a 2B hash.
                # 2a-only backend could potentially exhibit wraparound bug --
                # but we work around that issue above.
                ident = cls._fallback_ident

        elif ident == IDENT_2Y:
            if cls._lacks_2y_support:
                # handle $2y$ hash format (not supported by BSDs, being phased out on others)
                # have it generate a 2A/2B digest, then return it as a 2Y hash.
                ident = cls._fallback_ident

        elif ident == IDENT_2:
            if cls._lacks_20_support:
                # handle legacy $2$ format (not supported by most backends except BSD os_crypt)
                # we can fake $2$ behavior using the 2A/2Y/2B algorithm
                # by repeating the password until it's at least 72 chars in length.
                if secret:
                    if require_valid_utf8_bytes:
                        # NOTE: this only works because bcrypt will ignore everything past
                        #       secret[71], so padding to include a full utf8 sequence
                        #       won't break anything about the final output.
                        secret = utf8_repeat_string(secret, 72)
                    else:
                        secret = repeat_string(secret, 72)
                ident = cls._fallback_ident

        elif ident == IDENT_2X:
            # NOTE: shouldn't get here.
            # XXX: could check if backend does actually offer 'support'
            raise RuntimeError("$2x$ hashes not currently supported by passlib")

        else:
            raise AssertionError(f"unexpected ident value: {ident!r}")

        return secret, ident


class _NoBackend(_BcryptCommon):
    """
    mixin used before any backend has been loaded.
    contains stubs that force loading of one of the available backends.
    """

    def _calc_checksum(self, secret):
        self._stub_requires_backend()
        # NOTE: have to use super() here so that we don't recursively
        #       call subclass's wrapped _calc_checksum, e.g. bcrypt_sha256._calc_checksum
        return self._calc_checksum(secret)


class _BcryptBackend(_BcryptCommon):
    """
    backend which uses 'bcrypt' package
    """

    @classmethod
    def _load_backend_mixin(mixin_cls, name, dryrun):
        # try to import bcrypt
        global _bcrypt  # noqa: PLW0603
        if _detect_pybcrypt():
            # pybcrypt was installed instead
            return False
        try:
            import bcrypt as _bcrypt
        except ImportError:  # pragma: no cover
            return False
        try:
            version = metadata.version("bcrypt")
        except Exception:
            logger.warning("(trapped) error reading bcrypt version", exc_info=True)
            version = "<unknown>"

        logger.debug("detected 'bcrypt' backend, version %r", version)
        return mixin_cls._finalize_backend_mixin(name, dryrun)

    # # TODO: would like to implementing verify() directly,
    # #       to skip need for parsing hash strings.
    # #       below method has a few edge cases where it chokes though.
    # @classmethod
    # def verify(cls, secret, hash):
    #     if isinstance(hash, str):
    #         hash = hash.encode("ascii")
    #     ident = hash[:hash.index(b"$", 1)+1].decode("ascii")
    #     if ident not in cls.ident_values:
    #         raise uh.exc.InvalidHashError(cls)
    #     secret, eff_ident = cls._norm_digest_args(secret, ident)
    #     if eff_ident != ident:
    #         # lacks support for original ident, replace w/ new one.
    #         hash = eff_ident.encode("ascii") + hash[len(ident):]
    #     result = _bcrypt.hashpw(secret, hash)
    #     assert result.startswith(eff_ident)
    #     return consteq(result, hash)

    def _calc_checksum(self, secret):
        # bcrypt behavior:
        #   secret must be bytes
        #   config must be ascii bytes
        #   returns ascii bytes
        secret, ident = self._prepare_digest_args(secret)
        config = self._get_config(ident)
        if isinstance(config, str):
            config = config.encode("ascii")
        hash = _bcrypt.hashpw(secret, config)
        assert isinstance(hash, bytes)
        if not hash.startswith(config) or len(hash) != len(config) + 31:
            raise uh.exc.CryptBackendError(
                self, config, hash, source="`bcrypt` package"
            )
        return hash[-31:].decode("ascii")


class bcrypt(_NoBackend, _BcryptCommon):  # type: ignore[misc]
    """This class implements the BCrypt password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 22 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :type rounds: int
    :param rounds:
        Optional number of rounds to use.
        Defaults to 12, must be between 4 and 31, inclusive.
        This value is logarithmic, the actual number of iterations used will be :samp:`2**{rounds}`
        -- increasing the rounds by +1 will double the amount of time taken.

    :type ident: str
    :param ident:
        Specifies which version of the BCrypt algorithm will be used when creating a new hash.
        Typically this option is not needed, as the default (``"2b"``) is usually the correct choice.
        If specified, it must be one of the following:

        * ``"2"`` - the first revision of BCrypt, which suffers from a minor security flaw and is generally not used anymore.
        * ``"2a"`` - some implementations suffered from rare security flaws, replaced by 2b.
        * ``"2y"`` - format specific to the *crypt_blowfish* BCrypt implementation,
          identical to ``"2b"`` in all but name.
        * ``"2b"`` - latest revision of the official BCrypt algorithm, current default.

    :param bool truncate_error:
        By default, BCrypt will silently truncate passwords larger than 72 bytes.
        Setting ``truncate_error=True`` will cause :meth:`~passlib.ifc.PasswordHash.hash`
        to raise a :exc:`~passlib.exc.PasswordTruncateError` instead.

        .. versionadded:: 1.7

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

        .. versionadded:: 1.6

    .. versionchanged:: 1.6
        This class now supports ``"2y"`` hashes, and recognizes
        (but does not support) the broken ``"2x"`` hashes.
        (see the :ref:`crypt_blowfish bug <crypt-blowfish-bug>`
        for details).

    .. versionchanged:: 1.6
        Added a pure-python backend.

    .. versionchanged:: 1.6.3

        Added support for ``"2b"`` variant.

    .. versionchanged:: 1.7

        Now defaults to ``"2b"`` variant.
    """

    # NOTE: the brunt of the bcrypt class is implemented in _BcryptCommon.
    #       there are then subclass for each backend (e.g. _PyBcryptBackend),
    #       these are dynamically prepended to this class's bases
    #       in order to load the appropriate backend.

    #: list of potential backends
    backends = ("bcrypt",)

    #: flag that this class's bases should be modified by SubclassBackendMixin
    _backend_mixin_target = True

    #: map of backend -> mixin class, used by _get_backend_loader()
    _backend_mixin_map = {
        None: _NoBackend,
        "bcrypt": _BcryptBackend,
    }


_UDOLLAR = "$"


# XXX: it might be better to have all the bcrypt variants share a common base class,
#      and have the (django_)bcrypt_sha256 wrappers just proxy bcrypt instead of subclassing it.
class _wrapped_bcrypt(bcrypt):
    """
    abstracts out some bits bcrypt_sha256 & django_bcrypt_sha256 share.
    - bypass backend-loading wrappers for hash() etc
    - disable truncation support, sha256 wrappers don't need it.
    """

    setting_kwds = tuple(
        elem for elem in bcrypt.setting_kwds if elem not in ["truncate_error"]
    )
    truncate_size: int | None = None

    # XXX: these will be needed if any bcrypt backends directly implement this...
    # @classmethod
    # def hash(cls, secret, **kwds):
    #     # bypass bcrypt backend overriding this method
    #     # XXX: would wrapping bcrypt make this easier than subclassing it?
    #     return super().hash(secret, **kwds)
    #
    # @classmethod
    # def verify(cls, secret, hash):
    #     # bypass bcrypt backend overriding this method
    #     return super().verify(secret, hash)
    #
    # @classmethod
    # def genhash(cls, secret, hash):
    #     # bypass bcrypt backend overriding this method
    #     return super().genhash(secret, hash)

    @classmethod
    def _check_truncate_policy(cls, secret):
        # disable check performed by bcrypt(), since this doesn't truncate passwords.
        pass


class bcrypt_sha256(_wrapped_bcrypt):
    """
    This class implements a composition of BCrypt + HMAC_SHA256,
    and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.hash` and :meth:`~passlib.ifc.PasswordHash.genconfig` methods accept
    all the same optional keywords as the base :class:`bcrypt` hash.

    .. versionadded:: 1.6.2

    .. versionchanged:: 1.7

        Now defaults to ``"2b"`` bcrypt variant; though supports older hashes
        generated using the ``"2a"`` bcrypt variant.

    .. versionchanged:: 1.7.3

        For increased security, updated to use HMAC-SHA256 instead of plain SHA256.
        Now only supports the ``"2b"`` bcrypt variant.  Hash format updated to "v=2".
    """

    # --------------------
    # PasswordHash
    # --------------------
    name = "bcrypt_sha256"

    # --------------------
    # GenericHandler
    # --------------------
    # this is locked at 2b for now (with 2a allowed only for legacy v1 format)
    ident_values = (IDENT_2A, IDENT_2B)

    # clone bcrypt's ident aliases so they can be used here as well...
    ident_aliases = (  # noqa: PLC3002
        lambda ident_values: dict(
            item for item in bcrypt.ident_aliases.items() if item[1] in ident_values
        )
    )(ident_values)
    default_ident = IDENT_2B

    # --------------------
    # class specific
    # --------------------

    _supported_versions = {1, 2}

    #: wrapper version.
    #: v1 -- used prior to passlib 1.7.3; performs ``bcrypt(sha256(secret), salt, cost)``
    #: v2 -- new in passlib 1.7.3; performs `bcrypt(sha256_hmac(salt, secret), salt, cost)``
    version = 2

    @classmethod
    def using(cls, version=None, **kwds):
        subcls = super().using(**kwds)
        if version is not None:
            subcls.version = subcls._norm_version(version)
        ident = subcls.default_ident
        if subcls.version > 1 and ident != IDENT_2B:
            raise ValueError(
                f"bcrypt {ident!r} hashes not allowed for version {subcls.version!r}"
            )
        return subcls

    # sample hash:
    # $bcrypt-sha256$2a,6$/3OeRpbOf8/l6nPPRdZPp.$nRiyYqPobEZGdNRBWihQhiFDh1ws1tu
    # $bcrypt-sha256$           -- prefix/identifier
    # 2a                        -- bcrypt variant
    # ,                         -- field separator
    # 6                         -- bcrypt work factor
    # $                         -- section separator
    # /3OeRpbOf8/l6nPPRdZPp.    -- salt
    # $                         -- section separator
    # nRiyYqPobEZGdNRBWihQhiFDh1ws1tu  -- digest

    # XXX: we can't use .ident attr due to bcrypt code using it.
    #      working around that via prefix.
    prefix = "$bcrypt-sha256$"

    #: current version 2 hash format
    _v2_hash_re = re.compile(r"""(?x)
        ^
        [$]bcrypt-sha256[$]
        v=(?P<version>\d+),
        t=(?P<type>2b),
        r=(?P<rounds>\d{1,2})
        [$](?P<salt>[^$]{22})
        (?:[$](?P<digest>[^$]{31}))?
        $
        """)

    #: old version 1 hash format
    _v1_hash_re = re.compile(r"""(?x)
        ^
        [$]bcrypt-sha256[$]
        (?P<type>2[ab]),
        (?P<rounds>\d{1,2})
        [$](?P<salt>[^$]{22})
        (?:[$](?P<digest>[^$]{31}))?
        $
        """)

    @classmethod
    def identify(cls, hash):
        hash = uh.to_unicode_for_identify(hash)
        if not hash:
            return False
        return hash.startswith(cls.prefix)

    @classmethod
    def from_string(cls, hash):
        hash = to_unicode(hash, "ascii", "hash")
        if not hash.startswith(cls.prefix):
            raise uh.exc.InvalidHashError(cls)
        m = cls._v2_hash_re.match(hash)
        if m:
            version = int(m.group("version"))
            if version < 2:
                raise uh.exc.MalformedHashError(cls)
        else:
            m = cls._v1_hash_re.match(hash)
            if m:
                version = 1
            else:
                raise uh.exc.MalformedHashError(cls)
        rounds = m.group("rounds")
        if rounds.startswith(uh._UZERO) and rounds != uh._UZERO:
            raise uh.exc.ZeroPaddedRoundsError(cls)
        return cls(
            version=version,
            ident=m.group("type"),
            rounds=int(rounds),
            salt=m.group("salt"),
            checksum=m.group("digest"),
        )

    _v2_template = "$bcrypt-sha256$v=2,t=%s,r=%d$%s$%s"
    _v1_template = "$bcrypt-sha256$%s,%d$%s$%s"

    def to_string(self):
        if self.version == 1:  # noqa: SIM108
            template = self._v1_template
        else:
            template = self._v2_template
        return template % (
            self.ident.strip(_UDOLLAR),
            self.rounds,
            self.salt,
            self.checksum,
        )

    def __init__(self, version=None, **kwds):
        if version is not None:
            self.version = self._norm_version(version)
        super().__init__(**kwds)

    @classmethod
    def _norm_version(cls, version):
        if version not in cls._supported_versions:
            raise ValueError(f"{cls.name}: unknown or unsupported version: {version!r}")
        return version

    def _calc_checksum(self, secret):
        # NOTE: can't use digest directly, since bcrypt stops at first NULL.
        # NOTE: bcrypt doesn't fully mix entropy for bytes 55-72 of password
        #       (XXX: citation needed), so we don't want key to be > 55 bytes.
        #       thus, have to use base64 (44 bytes) rather than hex (64 bytes).
        # XXX: it's later come out that 55-72 may be ok, so later revision of bcrypt_sha256
        #      may switch to hex encoding, since it's simpler to implement elsewhere.
        if isinstance(secret, str):
            secret = secret.encode("utf-8")

        if self.version == 1:
            # version 1 -- old version just ran secret through sha256(),
            # though this could be vulnerable to a breach attach
            # (c.f. issue 114); which is why v2 switched to hmac wrapper.
            digest = sha256(secret).digest()
        else:
            # version 2 -- running secret through HMAC keyed off salt.
            # this prevents known secret -> sha256 password tables from being
            # used to test against a bcrypt_sha256 hash.
            # keying off salt (instead of constant string) should minimize chances of this
            # colliding with existing table of hmac digest lookups as well.
            # NOTE: salt in this case is the "bcrypt64"-encoded value, not the raw salt bytes,
            #       to make things easier for parallel implementations of this hash --
            #       saving them the trouble of implementing a "bcrypt64" decoder.
            salt = self.salt
            if salt[-1] not in self.final_salt_chars:
                # forbidding salts with padding bits set, because bcrypt implementations
                # won't consistently hash them the same.  since we control this format,
                # just prevent these from even getting used.
                raise ValueError("invalid salt string")
            digest = compile_hmac("sha256", salt.encode("ascii"))(secret)

        # NOTE: output of b64encode() uses "+/" altchars, "=" padding chars,
        #       and no leading/trailing whitespace.
        key = b64encode(digest)

        # hand result off to normal bcrypt algorithm
        return super()._calc_checksum(key)

    def _calc_needs_update(self, **kwds):
        if self.version < type(self).version:
            return True
        return super()._calc_needs_update(**kwds)
