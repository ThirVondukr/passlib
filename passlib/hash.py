"""passlib.hash stub

NOTE:
  this module does not actually contain any hashes.
  this file is a stub which is replaced by a proxy object,
  which lazy-loads hashes as requested.

  the actually implementations of hashes (at least, those built into passlib)
  are stored in the passlib.handlers subpackage.
"""

#NOTE: could support 'non-lazy' version which just imports
# all schemes known to list_crypt_handlers()

#=========================================================
#import special proxy object as 'passlib.hash' module
#=========================================================

#import proxy object, and replace this module with it.
#this should cause any import commands to return that object,
#not this module
from passlib.registry import _proxy
import sys
sys.modules['passlib.hash'] = _proxy
del sys, _proxy

#=========================================================
#eoc
#=========================================================
