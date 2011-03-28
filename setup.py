"""passlib setup script"""
#=========================================================
#init script env
#=========================================================
import os
os.chdir(os.path.abspath(os.path.join(__file__,"..")))
#=========================================================
#imports
#=========================================================
from setuptools import setup, find_packages
from passlib import __version__ as version
#=========================================================
#setup
#=========================================================
setup(
    #package info
    packages = find_packages(),
    package_data = { "passlib": ["*.cfg"] },

    # metadata
    name = "passlib",
    version = version,
    author = "Eli Collins",
    author_email = "elic@assurancetechnologies.com",
    license = "BSD",

    url = "http://code.google.com/p/passlib/",
    download_url = "http://code.google.com/p/passlib/downloads/list",

    description = "comprehensive password hashing framework supporting over 20 schemes",
    long_description = """\
PassLib is a password hash library, which provides cross-platform
implementations of over 20 password hashing algorithms; as well as a framework for managing
and migrating existing password hashes. It's designed to be useful
for any task from quickly verifying a hash found in /etc/shadow,
to providing full-strength password hashing for multi-user application.
""",

    keywords = "password secret hash security crypt md5-crypt sha256-crypt sha512-crypt bcrypt htpasswd htdigest pbkdf2",
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],
    zip_safe=True,

    test_suite = 'nose.collector',
)
#=========================================================
#EOF
#=========================================================
