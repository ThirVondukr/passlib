"""passlib.tests.tox_support - helper script for tox tests"""
#=============================================================================
# init script env
#=============================================================================
import os, sys
root_dir = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
sys.path.insert(0, root_dir)

#=============================================================================
# imports
#=============================================================================
# core
import re
import logging; log = logging.getLogger(__name__)
# site
# pkg
from passlib.utils.compat import print_
# local
__all__ = [
]

#=============================================================================
# main
#=============================================================================
def do_preset_tests(name):
    "return list of preset test names"
    if name == "django" or name == "django-hashes":
        from passlib.tests import test_handlers
        names = [
            "passlib/tests/test_handlers.py:" + name
            for name in dir(test_handlers)
            if re.match("^django_.*_test$", name)
        ] + ["hex_md5_test"]
        if name == "django":
            names.append("passlib/tests/test_ext_django.py")
        print_(" ".join(names))
    else:
        raise ValueError("unknown name: %r" % name)

def do_setup_gae(path, runtime):
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

def main(cmd, *args):
    func = globals()["do_" + cmd]
    return func(*args)

if __name__ == "__main__":
    import sys
    sys.exit(main(*sys.argv[1:]) or 0)

#=============================================================================
# eof
#=============================================================================
