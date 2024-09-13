"""passlib.ext.django.models -- monkeypatch django hashing framework"""

from passlib.ext.django.utils import DjangoContextAdapter

# local
__all__ = ["password_context"]


#: adapter instance used to drive most of this
adapter = DjangoContextAdapter()

# the context object which this patches contrib.auth to use for password hashing.
# configuration controlled by ``settings.PASSLIB_CONFIG``.
password_context = adapter.context

#: hook callers should use if context is changed
context_changed = adapter.reset_hashers


# load config & install monkeypatch
adapter.load_model()
