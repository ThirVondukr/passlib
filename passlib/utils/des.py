"""
passlib.utils.des - DEPRECATED LOCATION, WILL BE REMOVED IN 2.0

This has been moved to :mod:`passlib.crypto.des`.
"""
#=============================================================================
# import from new location
#=============================================================================
from warnings import warn
warn("the 'passlib.utils.des' module has been relocated to 'passlib.crypto.des' "
     "as of passlib 1.7, and the old location will be removed in passlib 2.0",
     DeprecationWarning)

#=============================================================================
# relocated functions
#=============================================================================
from passlib.utils.decor import deprecated_function
from passlib.crypto.des import expand_des_key, des_encrypt_block, des_encrypt_int_block

expand_des_key = deprecated_function(deprecated="1.7", removed="2.0",
    replacement="passlib.crypto.des.expand_des_key")(expand_des_key)

des_encrypt_block = deprecated_function(deprecated="1.7", removed="2.0",
    replacement="passlib.crypto.des.des_encrypt_block")(des_encrypt_block)

des_encrypt_int_block = deprecated_function(deprecated="1.7", removed="2.0",
    replacement="passlib.crypto.des.des_encrypt_int_block")(des_encrypt_int_block)

#=============================================================================
# eof
#=============================================================================
