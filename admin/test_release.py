"""helper script that tries to build & test passlib for various python versions.

note that this script is very Linux-specific,
and in fact contains various hardcoded assumptions
that are only true for the systems used by passlib's developers.

it also calls "rm -rf" a lot, so be wary :)
"""
#=========================================================================
# imports
#=========================================================================
import re
import sys
import os.path
import subprocess

#=========================================================================
# helpers
#=========================================================================
def absjoin(*args):
    return os.path.abspath(os.path.join(*args))

def discard_paths(*paths, **kwds):
    cmd = [ "rm", "-rf" ]
    if kwds.get("sudo"):
        cmd.insert(0, "sudo")
    paths = filter(os.path.exists, paths)
    if paths:
        subprocess.check_call(cmd + list(paths))

#=========================================================================
# main
#=========================================================================
class PlatformTestApp(object):
    "command line program that runs passlib's unittest suite for all python versions"

    #=========================================================================
    # class attrs
    #=========================================================================
    # names of vms to test
    vm_names = [
        # normal python versions
        "2.5",
        "2.6",
        "2.7",
        "3.1",
        "3.2",

        # other vms
        "y2.7-1.5",  # pypy 1.5
        "y2.7-1.6",  # pypy 1.6
        "j2.5", # jython 2.5
        "gae",
        ]

    #=========================================================================
    # instance attrs
    #=========================================================================
    root_dir = None # root dir of source
    version = None #current version string
    sdist_dir = None # unpacked sdist dir

    #=========================================================================
    # init
    #=========================================================================
    def __init__(self, args):
        self.args = args

    #=========================================================================
    # run
    #=========================================================================
    def run(self):
        # change dir root dir
        self.root_dir = absjoin(__file__, os.pardir, os.pardir)
        os.chdir(self.root_dir)

        # get version
        self.version = subprocess.check_output(
            ["python", "setup.py","--version"]).strip()

        # purge build & dist
        discard_paths(
            absjoin(self.root_dir, "dist"),
            absjoin(self.root_dir, "build"),
            )

        # create new source dist, extract it, and work from that
        subprocess.check_call(["python", "setup.py", "sdist"])
        os.chdir(absjoin(self.root_dir, "dist"))
        subprocess.check_call(["tar", "zxvf", "passlib-" + self.version + ".tar.gz"])
        self.sdist_dir = absjoin(self.root_dir, "dist", "passlib-" + self.version)

        # run test for each of the vms
        for name in self.vm_names:
            self.run_vm_test(name)

        return 0

    def run_vm_test(self, name):
        # cd to sdist dir, purge everything
        os.chdir(self.sdist_dir)
        discard_paths(
            absjoin(self.sdist_dir, "dist"),
            absjoin(self.sdist_dir, "build"),
            )
        self.uninstall_passlib(name)

        # if gae, run unittests directly in source
        if name == "gae":
            self.run_gae_test()
        else:
            self.run_vm_test_egg(name)
            if not self.parse_vm(name)[0]:
                self.uninstall_passlib(name)
                self.run_vm_test_pip(name)

        self.uninstall_passlib(name)

    def run_gae_test(self):
        # cd to preconfigured gae app
        gae_dir = absjoin(self.root_dir, os.pardir, "gae")
        os.chdir(gae_dir)

        # cleanup and init symlink for passlib
        target_dir = absjoin(gae_dir, "passlib")
        discard_paths(target_dir)
        os.symlink(absjoin(self.sdist_dir, "passlib"), target_dir)

        # run nose w/ gae integration
        subprocess.check_call([
            self.get_vm_exe("gae", "nosetests"),
            "--with-gae",
            "--exe", # later versions set exe bit on test_xxx.py files
            "--tests", "passlib/tests",
        ])

    def run_vm_test_pip(self, name):
        os.chdir(absjoin(self.root_dir, "dist"))

        # install via pip
        pkg = "passlib-" + self.version + ".tar.gz"
        if self.is_vm_sitewide(name):
            subprocess.check_call([
                "sudo",
                self.get_vm_exe(name, "pip"),
                "install",
                pkg,
            ])
        else:
            subprocess.check_call([
                self.get_vm_exe(name, "pip"),
                "install", "--user",
                pkg,
            ])

        # cd to install location and run tests
        # NOTE: just testing that pip worked, so skipping expensive tests
        os.chdir(absjoin(self.get_vm_dir(name)))
        subprocess.check_call([
            self.get_vm_exe(name, "nosetests"),
            "--exe", # later versions set exe bit on test_xxx.py files
            "--tests", "passlib/tests/test_context.py",
        ])

    def run_vm_test_egg(self, name):

        # build & install egg
        subprocess.check_call([
            self.get_vm_exe(name, "python"),
            "setup.py",
            "bdist_egg",
        ])
        egg_name = "passlib-%s-py%s.egg" %  (self.version, self.get_vm_suffix(name))
        exe = self.get_vm_exe(name, "easy_install")
        if self.is_vm_sitewide(name):
            subprocess.check_call(["sudo", exe, "dist/" + egg_name])
        else:
            subprocess.check_call([exe, "--user", "dist/" + egg_name])

        # cd to install location and run tests
        os.chdir(absjoin(self.get_vm_dir(name), egg_name))
        subprocess.check_call([
            self.get_vm_exe(name, "nosetests"),
            "--exe", # later versions set exe bit on test_xxx.py files
            "--tests", "passlib/tests",
        ])

    def uninstall_passlib(self, name):
        vm_dir = self.get_vm_dir(name)
        discard_paths(*[
            absjoin(vm_dir, fname)
            for fname in os.listdir(vm_dir)
            if fname.startswith("passlib")
            ], sudo=self.is_vm_sitewide(name))

    #=========================================================================
    # vm info
    #=========================================================================
    def parse_vm(self, name):
        "parse 'vm name' string into (vm id, py version, vm release)"
        if name == "gae":
            name = "2.5"
        m = re.match(r"^(?P<vm>[a-z]*)(?P<ver>[\d.]+)(-(?P<rel>[\d.]+))?$", name)
        if not m:
            raise ValueError("can't parse vm name: %r" % (name,))
        return m.group("vm", "ver", "rel")

    def is_vm_sitewide(self, name):
        "does vm require installing site-wide?"
        vm, ver, rel = self.parse_vm(name)
        return vm == "y" or ver == "2.5"

    def get_vm_suffix(self, name):
        "return suffix used by egg built using specified vm"
        return self.parse_vm(name)[1]

    def get_vm_dir(self, name):
        "get name of dir where eggs will be installed for specified vm"
        vm, ver, rel = self.parse_vm(name)
        if vm == "y":
            return "/opt/pypy-" + rel + "/site-packages"
        elif vm in ["j", ""] and ver == "2.5":
            prefix = "/usr/lib"
        else:
            prefix = os.path.expanduser("~/.local/lib")
        return prefix + "/python" + self.get_vm_suffix(name) + "/site-packages"

    def get_vm_exe(self, name, exe):
        "return path to appropriate exe for specified vm"
        vm, ver, rel = self.parse_vm(name)
        if vm:
            if vm == "y":
                if exe == "python":
                    exe = "pypy"
                return "/opt/pypy-" + rel + "/bin/" + exe
            elif vm == "j" and exe == "python":
                return "jython"
            else:
                return exe + "-" + name
        else:
            if exe == "python":
                return "python" + ver
            else:
                return exe + "-" + ver

    #=========================================================================
    # eoc
    #=========================================================================

if __name__ == "__main__":
    app = PlatformTestApp(sys.argv[1:])
    sys.exit(app.run())

#=========================================================================
# eof
#=========================================================================
