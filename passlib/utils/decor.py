"""
passlib.utils.decor -- helper decorators & properties
"""
#=============================================================================
# imports
#=============================================================================
# core
from __future__ import absolute_import, division, print_function
from functools import wraps
# site
# pkg
# local
__all__ = [
    "memoize_single_value"
]

#=============================================================================
# memoization
#=============================================================================

def memoize_single_value(func):
    """
    decorator for function which takes no args,
    and memoizes result.  exposes a ``.clear_cache`` method
    to clear the cached value.
    """
    cache = {}

    @wraps(func)
    def wrapper():
        try:
            return cache[True]
        except KeyError:
            pass
        value = cache[True] = func()
        return value

    def clear_cache():
        cache.pop(True, None)
    wrapper.clear_cache = clear_cache

    return wrapper

#=============================================================================
# eof
#=============================================================================
