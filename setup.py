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

    url = "http://www.assurancetechnologies.com/software/passlib",
    #download_url

    description = "password hash library",
    long_description = """\
PassLib provides cross-platform implementations of most of the major
password hashing algorithms; as well as a framework for managing
and migrating existing password hashes. It's designed to be useful
for anything from quickly verify a hash found in /etc/shadow,
to integrating full-strength password hashing for multi-user application.
""",

    keywords = "password secret hash security crypt md5-crypt sha256-crypt sha512-crypt bcrypt htpasswd htdigest apache",
    classifiers = [
        "Development Status :: 4 - Beta",
        "Environment :: Plugins",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
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
