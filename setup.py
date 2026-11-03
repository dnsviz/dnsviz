#!/usr/bin/env python

from __future__ import unicode_literals

import codecs
import glob
import os
import stat
import subprocess
import sys

from setuptools import setup
from setuptools.command.install import install
from setuptools.command.build_py import build_py

JQUERY_UI_PATH = "'https://code.jquery.com/ui/1.11.4/jquery-ui.min.js'"
JQUERY_UI_CSS_PATH = "'https://code.jquery.com/ui/1.11.4/themes/redmond/jquery-ui.css'"
JQUERY_PATH = "'https://code.jquery.com/jquery-1.11.3.min.js'"
RAPHAEL_PATH = "'https://cdnjs.cloudflare.com/ajax/libs/raphael/2.1.4/raphael-min.js'"
RESOLV_CONF = "'/etc/resolv.conf'"

def apply_substitutions(filename, install_prefix):
    assert filename.endswith('.in'), 'Filename supplied for customization must end with \'.in\': %s' % (filename)

    filename_out = filename[:-3]

    if os.path.exists(filename_out) and os.path.getctime(filename_out) > os.path.getctime(filename):
        return

    with open(filename, 'r') as in_fh:
        s = in_fh.read()

    s = s.replace('__DNSVIZ_INSTALL_PREFIX__', install_prefix)
    s = s.replace('__JQUERY_PATH__', JQUERY_PATH)
    s = s.replace('__JQUERY_UI_PATH__', JQUERY_UI_PATH)
    s = s.replace('__JQUERY_UI_CSS_PATH__', JQUERY_UI_CSS_PATH)
    s = s.replace('__RAPHAEL_PATH__', RAPHAEL_PATH)
    s = s.replace('__RESOLV_CONF__', RESOLV_CONF)

    with open(filename_out, 'w') as out_fh:
        out_fh.write(s)

def make_documentation():
    os.chdir('doc')
    try:
        if os.system('make') != 0:
            sys.stderr.write('Warning: Some of the included documentation failed to build.  Proceeding without it.\n')
    finally:
        os.chdir('..')

def create_config(prefix):
    # Create dnsviz/config.py, so version exists for packages that don't
    # require calling install.  Even though the install prefix is the empty
    # string, the use case for this is virtual environments, which won't
    # use it.
    apply_substitutions(os.path.join('dnsviz','config.py.in'), prefix)
    # update the timestamp of config.py.in, so if/when the install command
    # is called, config.py will be rewritten, i.e., with the real install
    # prefix.
    os.utime(os.path.join('dnsviz', 'config.py.in'), None)

class MyBuildPy(build_py):
    def run(self):
        make_documentation()
        build_py.run(self)

class MyInstall(install):
    def run(self):
        # if this an alternate root is specified, then embed the install_data
        # path relative to that alternate root
        if self.root is not None:
            install_data = os.path.join(os.path.sep, os.path.relpath(self.install_data, self.root))
        else:
            install_data = self.install_data
        create_config(install_data)
        install.run(self)

DOC_FILES = [('share/doc/dnsviz', ['README.md'])]
DATA_FILES = [('share/dnsviz/icons', ['doc/images/error.png', 'doc/images/warning.png']),
        ('share/dnsviz/css', ['share/css/dnsviz.css']),
        ('share/dnsviz/js', ['share/js/dnsviz.js']),
        ('share/dnsviz/html', ['share/html/dnssec-template.html']),
        ('share/dnsviz/trusted-keys', ['share/trusted-keys/root.txt']),
        ('share/dnsviz/hints', ['share/hints/named.root'])]
MAN_FILES = [('share/man/man1', ['doc/man/dnsviz.1', 'doc/man/dnsviz-probe.1', 'doc/man/dnsviz-grok.1', 'doc/man/dnsviz-graph.1', 'doc/man/dnsviz-print.1', 'doc/man/dnsviz-query.1'])]
DOC_EXTRA_FILES = [('share/doc/dnsviz', ['doc/dnsviz-graph.html']),
        ('share/doc/dnsviz/images', glob.glob(os.path.join('doc', 'images', '*.png')))]

# third-party files are only installed if they're included in the package
if os.path.exists(os.path.join('external', 'jquery-ui')):
    JQUERY_UI_PATH = "'file://' + os.path.join(DNSVIZ_SHARE_PATH, 'js', 'jquery-ui-1.11.4.custom.min.js')"
    JQUERY_UI_CSS_PATH = "'file://' + os.path.join(DNSVIZ_SHARE_PATH, 'css', 'jquery-ui-1.11.4.custom.min.css')"
if os.path.exists(os.path.join('external', 'jquery')):
    JQUERY_FILES = [('share/dnsviz/js', ['external/jquery/jquery-1.11.3.min.js'])]
    JQUERY_PATH = "'file://' + os.path.join(DNSVIZ_SHARE_PATH, 'js', 'jquery-1.11.3.min.js')"
else:
    JQUERY_FILES = []
if os.path.exists(os.path.join('external', 'raphael')):
    RAPHAEL_FILES = [('share/dnsviz/js', ['external/raphael/raphael-min.js'])]
    RAPHAEL_PATH = "'file://' + os.path.join(DNSVIZ_SHARE_PATH, 'js', 'raphael-min.js')"
else:
    RAPHAEL_FILES = []

create_config('')
setup(name='dnsviz',
        cmdclass={ 'build_py': MyBuildPy, 'install': MyInstall },
)
