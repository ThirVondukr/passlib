## 1.9.1 (2025-05-02)

### Fix

- don't use root logger

### Refactor

- **apache**: improve typing of HtpasswdFile and HtdigestFile
- enable ruff "INP" rule
- enable ruff "PLW" rule
- enable ruff "PLC" rule

## 1.9.0 (2025-02-18)

### Refactor

- remove dependency on crypt
- **libpass**: use functools.cached_property for CryptContext active schemes

## 1.8.2 (2025-02-13)

### Feat

- add django pbkdf2_sha256 and pbkdf2_sha1 hashers
- add pbkdf2 sha_256 and sha_512 hashes
- add PasswordHasher.needs_update method
- add argon2 hasher
- add CryptContext class

### Fix
- add python 3.13 compatability

### Refactor

- enable ruff "FURB" rule
- enable ruff "PERF" rule
- enable ruff "RSE" rule
- enable ruff "FA" rule
- enable ruff "ISC" rule
- enable ruff "SIM" rule
- enable ruff "PIE" rule
- enable ruff "G" rule
- enable RET ruff rule
- enable pyupgrade(UP) checks in ruff
- **tests/**: use pytest to capture warnings
- **utils**: improve typing
- remove jython and pypy compatiblity helpers, remove setup.py
- remove dependency on built-in crypt, use legacycrypt instead
- replace consteq and str_consteq implementations with hmac.compare_digest

## 1.7.5.post0 (2024-09-11)

## 1.7.5 (2024-09-11)

### Fix

- **argon2.py**: use metadata.version to retrieve package version
- **bcrypt.py**: use importlib.metadata to get bcrypt version
- **bcrypt.py**: _calc_checksum call

### Refactor

- fix some of ruff errors
- remove deprecated pkg_resources usage
- add ".git-blame-ignore-revs"
- add ruff, mypy and deptry
- cleanup
- use pdm for dependency management

## 1.7.4 (2020-10-08)

## 1.7.3 (2020-10-06)

## 1.7.2 (2019-11-22)

## 1.7.1 (2017-01-30)

## 1.7.0 (2016-11-22)

### Fix

- passlib.tests: added "test_handlers_argon2" to get_handler_case()
- handler test suite: avoid even rounds for bsdi_crypt

## 1.6.5 (2015-08-04)

## 1.6.4 (2015-07-25)

## 1.6.2 (2013-12-26)

## 1.6.1 (2012-08-02)

## 1.6 (2012-05-17)

## 1.5.3 (2011-10-08)

## 1.5.2 (2011-09-19)

## 1.5.1 (2011-08-17)

## 1.5 (2011-07-11)

## 1.4 (2011-05-04)

## 1.3.1 (2011-03-28)

## 1.3.0 (2011-03-25)

## 1.2.0 (2011-01-17)

## 1.1.0 (2011-01-07)
