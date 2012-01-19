"""passlib.exc -- exceptions & warnings raised by passlib"""
#==========================================================================
# exceptions
#==========================================================================
class MissingBackendError(RuntimeError):
    """Error raised if multi-backend handler has no available backends;
    or if specifically requested backend is not available.

    :exc:`!MissingBackendError` derives
    from :exc:`RuntimeError`, since this usually indicates
    lack of an external library or OS feature.

    This is primarily used by handlers which derive
    from :class:`~passlib.utils.handlers.HasManyBackends`.
    """

#==========================================================================
# warnings
#==========================================================================
class PasslibWarning(UserWarning):
    """base class for Passlib's user warnings"""

class PasslibContextWarning(PasslibWarning):
    """Warning issued when non-fatal issue is found related to the configuration
    of a :class:`~passlib.context.CryptContext` instance.

    This occurs primarily in one of two cases:

    * the policy contains rounds limits which exceed the hard limits
      imposed by the underlying algorithm.
    * an explicit rounds value was provided which exceeds the limits
      imposed by the policy.

    In both of these cases, the code will perform correctly & securely;
    but the warning is issued as a sign the configuration may need updating.
    """

class PasslibHandlerWarning(PasslibWarning):
    """Warning issued when non-fatal issue is found with parameters
    or hash string passed to a passlib hash class.

    This occurs primarily in one of two cases:

    * a rounds value or other setting was explicitly provided which
      exceeded the handler's limits (and has been clamped).

    * a hash malformed hash string was encountered, which while parsable,
      should be re-encoded.
    """

class PasslibRuntimeWarning(PasslibWarning):
    """Warning issued when something strange but correctable happens during
    runtime. These are generally ok, but the developers would love to hear
    the conditions under which it occurred."""

#==========================================================================
# eof
#==========================================================================
