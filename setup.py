"""passlib setup script"""
#=========================================================
#init script env
#=========================================================
import os
root_dir = os.path.abspath(os.path.join(__file__,".."))
os.chdir(root_dir)

#=========================================================
#imports
#=========================================================
import re
import sys
py3k = (sys.version_info >= (3,0))
from setuptools import setup, find_packages

#=========================================================
#monkeypatch & enable 2to3 
#=========================================================
opts = {}
if py3k:
    from passlib.setup.cond2to3 import patch2to3
    patch2to3()
    opts['use_2to3'] = True

#=========================================================
#version string
#=========================================================
vh = open(os.path.join(root_dir, "passlib", "__init__.py"))
VERSION = re.search(r'^__version__\s*=\s*"(.*?)"\s*$', vh.read(), re.M).group(1)
vh.close()

#=========================================================
#setup
#=========================================================
DESCRIPTION = "comprehensive password hashing framework supporting over 20 schemes"

LONG_DESCRIPTION = """\
PassLib is a password hash library, which provides cross-platform
implementations of over 20 password hashing algorithms; as well as a framework for managing
and migrating existing password hashes. It's designed to be useful
for any task from quickly verifying a hash found in /etc/shadow,
to providing full-strength password hashing for multi-user applications.

* See the `online documentation <http://packages.python.org/passlib>`_ for details and examples.

* See the `passlib homepage <http://passlib.googlecode.com>`_ for the latest news, more information, and additional downloads. 

* See the `changelog <http://packages.python.org/passlib/history.html>`_ for list of what's new in passlib.

All releases are signed with the gpg key `4CE1ED31 <http://pgp.mit.edu:11371/pks/lookup?op=get&search=0x4D8592DF4CE1ED31>`_.
"""

KEYWORDS = "password secret hash security crypt md5-crypt sha256-crypt sha512-crypt bcrypt apache htpasswd htdigest pbkdf2 ntlm"

setup(
    #package info
    packages = find_packages(),
    package_data = { "passlib": ["*.cfg"] },
    zip_safe=True,

    # metadata
    name = "passlib",
    version = VERSION,
    author = "Eli Collins",
    author_email = "elic@assurancetechnologies.com",
    license = "BSD",

    url = "http://passlib.googlecode.com",
    download_url = "http://passlib.googlecode.com/files/passlib-" + VERSION + ".tar.gz",

    description = DESCRIPTION,
    long_description = LONG_DESCRIPTION,
    keywords = KEYWORDS,
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],

    test_suite = 'nose.collector',

    #extra opts
    **opts
)
#=========================================================
#EOF
#=========================================================
