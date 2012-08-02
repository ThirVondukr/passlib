"""passlib setup script"""
#=============================================================================
# init script env -- ensure cwd = root of source dir
#=============================================================================
import os
root_dir = os.path.abspath(os.path.join(__file__,".."))
os.chdir(root_dir)

#=============================================================================
# imports
#=============================================================================
import re
import sys
import time

py3k = (sys.version_info[0] >= 3)

try:
    from setuptools import setup
    has_distribute = True
except ImportError:
    from distutils.core import setup
    has_distribute = False

#=============================================================================
# init setup options
#=============================================================================
opts = { "cmdclass": { } }
args = sys.argv[1:]

#=============================================================================
# register docdist command (not required)
#=============================================================================
try:
    from passlib._setup.docdist import docdist
    opts['cmdclass']['docdist'] = docdist
except ImportError:
    pass

#=============================================================================
# version string / datestamps
#=============================================================================
from passlib import __version__ as VERSION

# if this is an hg checkout of passlib, add datestamp to version string.
# XXX: could check for *absence* of PKG-INFO instead
if os.path.exists(os.path.join(root_dir, "passlib.komodoproject")):

    # check for --for-release flag indicating this isn't a snapshot
    for_release = False
    i = 0
    while i < len(args):
        v = args[i]
        if v == '--for-release':
            for_release = True
            del args[i]
            break
        elif not v.startswith("-"):
            break
        i += 1

    if for_release:
        assert '.dev' not in VERSION and '.post' not in VERSION
    else:
        # add datestamp if doing a snapshot
        dstr = time.strftime("%Y%m%d")
        if VERSION.endswith(".dev0") or VERSION.endswith(".post0"):
            VERSION = VERSION[:-1] + dstr
        else:
            assert '.dev' not in VERSION and '.post' not in VERSION
            VERSION += ".post" + dstr

        # subclass build_py & sdist so they rewrite passlib/__init__.py
        # to have the correct version string
        from passlib._setup.stamp import stamp_distutils_output
        stamp_distutils_output(opts, VERSION)

#=============================================================================
# static text
#=============================================================================
SUMMARY = "comprehensive password hashing framework supporting over 30 schemes"

DESCRIPTION = """\
Passlib is a password hashing library for Python 2 & 3, which provides
cross-platform implementations of over 30 password hashing algorithms, as well
as a framework for managing existing password hashes. It's designed to be useful
for a wide range of tasks, from verifying a hash found in /etc/shadow, to
providing full-strength password hashing for multi-user application.

* See the `online documentation <http://packages.python.org/passlib>`_
  for details, installation instructions, and examples.

* See the `Passlib homepage <http://passlib.googlecode.com>`_
  for the latest news, more information, and additional downloads.

* See the `changelog <http://packages.python.org/passlib/history.html>`_
  for a description of what's new in Passlib.

All releases are signed with the gpg key
`4CE1ED31 <http://pgp.mit.edu:11371/pks/lookup?op=get&search=0x4D8592DF4CE1ED31>`_.
"""

KEYWORDS = "password secret hash security crypt md5-crypt \
sha256-crypt sha512-crypt bcrypt apache htpasswd htdigest pbkdf2"

CLASSIFIERS = """\
Intended Audience :: Developers
License :: OSI Approved :: BSD License
Natural Language :: English
Operating System :: OS Independent
Programming Language :: Python :: 2.5
Programming Language :: Python :: 2.6
Programming Language :: Python :: 2.7
Programming Language :: Python :: 3
Programming Language :: Python :: Implementation :: CPython
Programming Language :: Python :: Implementation :: Jython
Programming Language :: Python :: Implementation :: PyPy
Topic :: Security :: Cryptography
Topic :: Software Development :: Libraries
""".splitlines()

# TODO: "Programming Language :: Python :: Implementation :: IronPython" -- issue 34

is_release = False
if '.dev' in VERSION:
    CLASSIFIERS.append("Development Status :: 3 - Alpha")
elif '.post' in VERSION:
    CLASSIFIERS.append("Development Status :: 4 - Beta")
else:
    is_release = True
    CLASSIFIERS.append("Development Status :: 5 - Production/Stable")

#=============================================================================
# run setup
#=============================================================================
# XXX: could omit 'passlib._setup' from eggs, but not sdist
setup(
    # package info
    packages = [
        "passlib",
            "passlib.ext",
                "passlib.ext.django",
            "passlib.handlers",
            "passlib.tests",
            "passlib.utils",
                "passlib.utils._blowfish",
            "passlib._setup",
        ],
    package_data = { "passlib.tests": ["*.cfg"] },
    zip_safe=True,

    # metadata
    name = "passlib",
    version = VERSION,
    author = "Eli Collins",
    author_email = "elic@assurancetechnologies.com",
    license = "BSD",

    url = "http://passlib.googlecode.com",
    download_url =
        ("http://passlib.googlecode.com/files/passlib-" + VERSION + ".tar.gz")
        if is_release else None,

    description = SUMMARY,
    long_description = DESCRIPTION,
    keywords = KEYWORDS,
    classifiers = CLASSIFIERS,

    tests_require = 'nose >= 1.1',
    test_suite = 'nose.collector',

    # extra opts
    script_args=args,
    **opts
)
#=============================================================================
# eof
#=============================================================================
