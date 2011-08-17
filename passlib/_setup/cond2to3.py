"""passlib.setup.cond2to3 - moneypatches 2to3 to provide conditional macros, ala SQLAlchemy"""
#=========================================================
#imports
#=========================================================
#core
from lib2to3.refactor import RefactoringTool
import re
#site
#local
__all__ = [
    "patch2to3",
]

#=========================================================
#macro preprocessor
#=========================================================
py3k_start_re = re.compile(r"^(\s*)# Py3K #", re.I)
py3k_stop_re = re.compile(r"^(\s*)# end Py3K #", re.I)

py2k_start_re = re.compile(r"^(\s*)# Py2K #", re.I)
py2k_stop_re = re.compile(r"^(\s*)# end Py2K #", re.I)

bare_comment_re = re.compile(r"^(\s*)#(.*)")
bare_re = re.compile(r"^(\s*)(.*)")

def preprocess(data, name):
    #TODO: add flag so this can also function in reverse, for 3to2
    changed = False

    lines = data.split("\n")
    state = 0
        #0: parsing normally, looking for start-p3k or start-py2k
        #1: in Py3K block - removing comment chars until end-py3k
        #2: in Py2K block - adding comment chars until end-py2k
    idx = 0
    indent = ''
    while idx < len(lines):
        line = lines[idx]

        #hack to detect ''"abc" strings - using this as py25-compat way to indicate bytes.
        #should really turn into a proper fixer.
        #also, this check is really weak, and might fail in some cases
        if '\'\'".*"' in line:
            line = lines[idx] = line.replace("''", "b")
            changed = True

        #check for py3k start marker
        m = py3k_start_re.match(line)
        if m:
            if state in (0,2):
                ident = m.group(1)
                state = 1
                idx += 1
                continue
            #states 1 this is an error...
            raise SyntaxError("unexpected py3k-start marker on line %d of %r: %r" % (idx, name, line))

        #check for py3k stop marker
        if py3k_stop_re.match(line):
            if state == 1:
                state = 0
                idx += 1
                continue
            #states 0,2 this is an error...
            raise SyntaxError("unexpected py3k-stop marker on line %d of %r: %r" % (idx, name, line))

        #check for py2k start marker
        m = py2k_start_re.match(line)
        if m:
            if state in (0,1):
                ident = m.group(1)
                state = 2
                idx += 1
                continue
            #states 2 this is an error...
            raise SyntaxError("unexpected py2k-start marker on line %d of %r: %r" % (idx, name, line))

        #check for py2k end marker
        if py2k_stop_re.match(line):
            if state == 2:
                state = 0
                idx += 1
                continue
            #states 0,1 this is an error...
            raise SyntaxError("unexpected py2k-stop marker on line %d of %r: %r" % (idx, name, line))

        #state 0 - leave non-marker lines alone
        if state == 0:
            idx += 1
            continue

        #state 1 - uncomment comment lines, throw error on bare lines
        if state == 1:
            m = bare_comment_re.match(line)
            if not m:
                raise SyntaxError("unexpected non-comment in py3k block on line %d of %r: %r" % (idx,name, line))
            pad, content = m.group(1,2)
            lines[idx] = pad + content
            changed = True
            idx += 1
            continue

        #state 2 - comment out all lines
        if state == 2:
            m = bare_re.match(line)
            if not m:
                raise RuntimeError("unexpected failure to parse line %d of %r: %r" % (idx, name, line))
            pad, content = m.group(1,2)
            if pad.startswith(ident): #try to put comments on same level
                content = pad[len(ident):] + content
                pad = ident
            lines[idx] = "%s#%s" % (pad,content)
            changed = True
            idx += 1
            continue

        #should never get here
        raise AssertionError("invalid state: %r" % (state,))

    if changed:
        return "\n".join(lines)
    else:
        return data

orig_rs = RefactoringTool.refactor_string

def refactor_string(self, data, name):
    "replacement for RefactoringTool.refactor_string which honors conditional includes"
    newdata = preprocess(data, name)
    tree = orig_rs(self, newdata, name)
    if tree and newdata != data:
        tree.was_changed = True
    return tree

#=========================================================
#main
#=========================================================

def patch2to3():
    "frontend to patch preprocessor into lib2to3"
    RefactoringTool.refactor_string = refactor_string

#helper for development purposes - runs 2to3 w/ patch
if __name__ == "__main__":
    import sys
    from lib2to3.main import main
    patch2to3()
    sys.exit(main("lib2to3.fixes"))

#=========================================================
#eof
#=========================================================
