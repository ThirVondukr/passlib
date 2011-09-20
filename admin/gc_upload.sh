#!/bin/sh
#
# helper script to upload built eggs to google code
# assumes GC_USER and GC_PASSWD are set

VSTR=`python setup.py --for-release --version`

cd dist

CMD="googlecode_upload.py -p passlib -u $GC_USER -w $GC_PASSWD"
#CMD="echo >>> "

TAIL="Release-${VSTR}"

$CMD -l Featured,Type-Source,OpSys-All,$TAIL -s "Passlib ${VSTR} source distribution" passlib-${VSTR}.tar.gz
$CMD -l Type-Signature-Source,$TAIL -s "Passlib ${VSTR} source distribution - PGP signature" passlib-${VSTR}.tar.gz.asc

for PV in 2.5 2.6 2.7 3.1 3.2
do
	$CMD -l Featured,Type-Egg,OpSys-All,$TAIL -s "Passlib ${VSTR} for python ${PV}" passlib-${VSTR}-py${PV}.egg
	$CMD -l Type-Signature,$TAIL -s "Passlib ${VSTR} for python ${PV} - PGP signature" passlib-${VSTR}-py${PV}.egg.asc
done

$CMD -l Type-Docs,OpSys-All,$TAIL -s "Passlib ${VSTR} standalone documentation"  passlib-docs-${VSTR}.zip
$CMD -l Type-Signature-Docs,$TAIL -s "Passlib ${VSTR} standalone documentation - PGP signature" passlib-docs-${VSTR}.zip.asc
