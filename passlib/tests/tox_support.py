"""passlib.tests.tox_support - helper script for tox tests"""
#=============================================================================
# imports
#=============================================================================
# core
import os
import logging; log = logging.getLogger(__name__)
# site
# pkg
# local
__all__ = [
]

#=============================================================================
# main
#=============================================================================
def main(path, runtime):
    "write fake GAE ``app.yaml`` to current directory so nosegae will work"
    from passlib.tests.utils import set_file
    set_file(os.path.join(path, "app.yaml"), """\
application: fake-app
version: 2
runtime: %s
api_version: 1

handlers:
- url: /.*
  script: dummy.py
""" % runtime)

if __name__ == "__main__":
    import sys
    sys.exit(main(*sys.argv[1:]) or 0)

#=============================================================================
# eof
#=============================================================================
