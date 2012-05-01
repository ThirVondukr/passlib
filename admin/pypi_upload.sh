#!/bin/sh

#
# helper script to build release & upload to pypi
# TODO: integrate the gc_upload.sh script into here,
# add some checks for the env vars that are needed,
# and make it more failure-proof
#

#TODO: run through all builds *first*, to make sure they work.
#      re-clean, run pypi upload, gc upload

# clean dir
rm -rf build dist

# upload sdist
python setup.py --for-release sdist upload

## upload eggs
##for PYEXT in 2.5 2.6 2.7 3.1 3.2
##do
##        python${PYEXT} setup.py --for-release bdist_egg upload
##done

# upload docs to packages.python.org
PASSLIB_DOCS="for-pypi" python setup.py --for-release build_sphinx upload_docs

# build & sign docdist for googlecode
python setup.py --for-release docdist
gpg --detach-sign -a dist/passlib-docs*.zip
