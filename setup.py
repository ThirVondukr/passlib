"""
passlib setup script

This script honors one environmental variable:
SETUP_TAG_RELEASE
    if "yes" (the default), revision tag is appended to version.
    for release, this is explicitly set to "no".
"""
#=============================================================================
# init script env -- ensure cwd = root of source dir
#=============================================================================
import os
root_dir = os.path.abspath(os.path.join(__file__, ".."))
os.chdir(root_dir)

#=============================================================================
# imports
#=============================================================================
from setuptools import setup, find_packages
import sys

#=============================================================================
# init setup options
#=============================================================================
opts = {"cmdclass": {}}
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

# pull version string from passlib
from passlib import __version__ as version

# append hg revision to builds
stamp_build = True  # NOTE: modified by stamp_distutils_output()
if stamp_build:
    from passlib._setup.stamp import (
        as_bool, append_hg_revision, stamp_distutils_output
    )

    # add HG revision to end of version
    if as_bool(os.environ.get("SETUP_TAG_RELEASE", "yes")):
        version = append_hg_revision(version)

    # subclass build_py & sdist to rewrite source version string,
    # and clears stamp_build flag so this doesn't run again.
    stamp_distutils_output(opts, version)

#=============================================================================
# static text
#=============================================================================
SUMMARY = "comprehensive password hashing framework supporting over 30 schemes"

DESCRIPTION = """\
Passlib is a password hashing library for Python 2 & 3, which provides
cross-platform implementations of over 30 password hashing algorithms, as well
as a framework for managing existing password hashes. It's designed to be useful
for a wide range of tasks, from verifying a hash found in /etc/shadow, to
providing full-strength password hashing for multi-user applications.

* See the `documentation <https://passlib.readthedocs.io>`_
  for details, installation instructions, and examples.

* See the `homepage <https://bitbucket.org/ecollins/passlib>`_
  for the latest news and more information.

* See the `changelog <https://passlib.readthedocs.io/en/stable/history>`_
  for a description of what's new in Passlib.

All releases are signed with the gpg key
`4D8592DF4CE1ED31 <http://pgp.mit.edu:11371/pks/lookup?op=get&search=0x4D8592DF4CE1ED31>`_.
"""

KEYWORDS = """\
password secret hash security
crypt md5-crypt
sha256-crypt sha512-crypt pbkdf2 argon2 scrypt bcrypt
apache htpasswd htdigest
totp 2fa
"""

CLASSIFIERS = """\
Intended Audience :: Developers
License :: OSI Approved :: BSD License
Natural Language :: English
Operating System :: OS Independent
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
if '.dev' in version:
    CLASSIFIERS.append("Development Status :: 3 - Alpha")
elif '.post' in version:
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
    # XXX: could omit 'passlib._setup' for bdist_wheel
    packages=find_packages(root_dir),
    package_data={
        "passlib.tests": ["*.cfg"],
        "passlib": ["_data/wordsets/*.txt"],
    },
    zip_safe=True,

    # metadata
    name="passlib",
    version=version,
    author="Eli Collins",
    author_email="elic@assurancetechnologies.com",
    license="BSD",

    url="https://bitbucket.org/ecollins/passlib",
    download_url=
        ("https://pypi.python.org/packages/source/p/passlib/passlib-" + version + ".tar.gz")
        if is_release else None,

    description=SUMMARY,
    long_description=DESCRIPTION,
    keywords=KEYWORDS,
    classifiers=CLASSIFIERS,

    tests_require='nose >= 1.1',
    test_suite='nose.collector',

    extras_require={
        "argon2": "argon2_cffi>=16.2",
        "bcrypt": "bcrypt>=3.1.0",
        "totp": "cryptography",
    },

    # extra opts
    script_args=args,
    **opts
)

#=============================================================================
# eof
#=============================================================================
