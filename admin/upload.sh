#!/bin/sh
#
# helper script to build & upload passlib to pypi & google code
#

SEP1="====================================================="
SEP2="-----------------------------------------------------"

#
# init config
#

if [ -z "$GC_USER" ]; then
    echo "GC_USER not set"
    exit 1
fi

if [ -z "$GC_PASSWORD" ]; then
    echo "GC_PASSWORD not set"
    exit 1
fi

GC_CMD="googlecode_upload.py -p passlib -u $GC_USER -w $GC_PASSWORD"
if [ -z "$DRY_RUN" ]; then
    echo "DRY_RUN not set"
    exit 1
elif [ "$DRY_RUN" -eq 1 ]; then
    echo "dry run"
    UPLOAD_ARG=""
    UPLOAD_DOCS_ARG=""
    GC_CMD="echo >>> $GC_CMD"
else
    echo "real run"
    UPLOAD_ARG="upload"
    UPLOAD_DOCS_ARG="upload_docs"
fi

VSTR=`python setup.py --for-release --version`
VTAIL="Release-${VSTR}"

echo "$SEP1"
echo "DRY_RUN=$DRY_RUN"
echo "GC_USER=$GC_USER"
echo "GC_PASSWORD=$GC_PASSWORD"
echo "VERSION=$VSTR"

#
# upload to pypi
#
if [ -z "$SKIP_PYPI" ]; then

    # clean dir
    echo "\n$SEP1\ncleaning build dirs\n$SEP2"
    rm -rf build dist

    # upload source
    echo "\n$SEP1\nbuilding and uploading source to pypi\n$SEP2"
    python setup.py --for-release sdist $UPLOAD_ARG

    # upload docs
    echo "\n$SEP1\nbuilding and uploading docs to pypi\n$SEP2"
    PASSLIB_DOCS="for-pypi" python setup.py --for-release build_sphinx $UPLOAD_DOCS_ARG

fi
#
# upload to google code
#
if [ -z "$SKIP_GC" ]; then

    # build & sign docdist for google code
    echo "\n$SEP1\nbuilding and signing docs.zip\n$SEP2"
    python setup.py --for-release docdist
    gpg --detach-sign -a dist/passlib-docs*.zip

    # move into dist for google code
    cd dist

    # upload source to gc
    echo "\n$SEP1\nuploading source to google code\n$SEP2"
    SDIST="passlib-${VSTR}.tar.gz"
    DZIP="passlib-docs-${VSTR}.zip"
    if [ ! -f "$SDIST" -o ! -f "$SDIST.asc" -o ! -f "$DZIP" -o ! -f "$DZIP.asc" ]; then
        echo "error: release file(s) not found"
        exit 1
    fi
    $GC_CMD -l Featured,Type-Source,OpSys-All,$VTAIL -s "Passlib ${VSTR} source distribution" $SDIST
    $GC_CMD -l Type-Signature-Source,$VTAIL -s "Passlib ${VSTR} source distribution - PGP signature" passlib-${VSTR}.tar.gz.asc

    echo "\n$SEP1\nuploading docs to google code\n$SEP2"
    $GC_CMD -l Type-Docs,OpSys-All,$VTAIL -s "Passlib ${VSTR} standalone documentation"  passlib-docs-${VSTR}.zip
    $GC_CMD -l Type-Signature-Docs,$VTAIL -s "Passlib ${VSTR} standalone documentation - PGP signature" passlib-docs-${VSTR}.zip.asc

    # move back again
    cd ..
fi

echo "\n$SEP1\ndone."