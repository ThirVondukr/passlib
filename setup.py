"""passlib setup script"""
#=========================================================
#init script env -- ensure cwd = root of source dir
#=========================================================
import os
root_dir = os.path.abspath(os.path.join(__file__,".."))
os.chdir(root_dir)

#=========================================================
#imports
#=========================================================
import re
import sys
py3k = (sys.version_info[0] >= 3)

try:
    from setuptools import setup
    has_distribute = True
except ImportError:
    from distutils import setup
    has_distribute = False

#=========================================================
#enable various 2to3 options
#=========================================================
opts = { "cmdclass": {} }

if py3k:
    #monkeypatch preprocessor into lib2to3
    from passlib.setup.cond2to3 import patch2to3
    patch2to3()

    #enable 2to3 translation in build_py
    if has_distribute:
        opts['use_2to3'] = True
    else:
        #if we can't use distribute's "use_2to3" flag,
        #have to override build_py command
        from distutils.command.build_py import build_py_2to3 as build_py
        opts['cmdclass']['build_py'] = build_py

#=========================================================
#version string
#=========================================================
from passlib import __version__ as VERSION

#=========================================================
#static text
#=========================================================
SUMMARY = "comprehensive password hashing framework supporting over 20 schemes"

DESCRIPTION = """\
Passlib is a password hashing library for Python 2 & 3,
which provides cross-platform implementations of over 20
password hashing algorithms, as well as a framework for
managing existing password hashes. It's designed to be useful
for a wide range of tasks, from verifying a hash found in /etc/shadow,
to providing full-strength password hashing for multi-user application.

* See the `online documentation <http://packages.python.org/passlib>`_
  for details, installation instructions, and examples.

* See the `passlib homepage <http://passlib.googlecode.com>`_
  for the latest news, more information, and additional downloads.

* See the `changelog <http://packages.python.org/passlib/history.html>`_
  for description of what's new in Passlib.

All releases are signed with the gpg key
`4CE1ED31 <http://pgp.mit.edu:11371/pks/lookup?op=get&search=0x4D8592DF4CE1ED31>`_.
"""

KEYWORDS = "password secret hash security crypt md5-crypt \
sha256-crypt sha512-crypt bcrypt apache htpasswd htdigest pbkdf2 ntlm"

#=========================================================
#run setup
#=========================================================
setup(
    #package info
    packages = [
        "passlib",
            "passlib.handlers",
            "passlib.setup",
            "passlib.tests",
            "passlib.utils",
        ],
    package_data = { "passlib": ["*.cfg"] },
    zip_safe=True,

    #metadata
    name = "passlib",
    version = VERSION,
    author = "Eli Collins",
    author_email = "elic@assurancetechnologies.com",
    license = "BSD",

    url = "http://passlib.googlecode.com",
    download_url = "http://passlib.googlecode.com/files/passlib-" + VERSION + ".tar.gz",

    description = SUMMARY,
    long_description = DESCRIPTION,
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

    tests_require = 'nose >= 1.0',
    test_suite = 'nose.collector',

    #extra opts
    **opts
)
#=========================================================
#EOF
#=========================================================
