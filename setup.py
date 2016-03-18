#!/usr/bin/env python

import glob
import os
import stat
import subprocess
import sys

from distutils.core import setup
from distutils.dist import Distribution
from distutils.command.install import install
from distutils.command.build import build

JQUERY_UI_PATH = "'http://code.jquery.com/ui/1.11.4/jquery-ui.min.js'"
JQUERY_UI_CSS_PATH = "'http://code.jquery.com/ui/1.11.4/themes/redmond/jquery-ui.css'"
JQUERY_PATH = "'http://code.jquery.com/jquery-1.11.3.min.js'"
RAPHAEL_PATH = "'http://cdnjs.cloudflare.com/ajax/libs/raphael/2.1.4/raphael-min.js'"
OPENSSL_LIB_DIR = "None"

def apply_substitutions(filename, install_prefix):
    assert filename.endswith('.in'), 'Filename supplied for customization must end with \'.in\': %s' % (filename)

    filename_out = filename[:-3]

    if os.path.exists(filename_out) and os.path.getctime(filename_out) > os.path.getctime(filename):
        return

    in_fh = open(filename, 'r')
    out_fh = open(filename_out, 'w')
    s = in_fh.read()
    s = s.replace('__DNSVIZ_INSTALL_PREFIX__', install_prefix)
    s = s.replace('__JQUERY_PATH__', JQUERY_PATH)
    s = s.replace('__JQUERY_UI_PATH__', JQUERY_UI_PATH)
    s = s.replace('__JQUERY_UI_CSS_PATH__', JQUERY_UI_CSS_PATH)
    s = s.replace('__RAPHAEL_PATH__', RAPHAEL_PATH)
    s = s.replace('__OPENSSL_LIB_DIR__', OPENSSL_LIB_DIR)
    out_fh.write(s)
    in_fh.close()
    out_fh.close()

def make_documentation():
    os.chdir('doc')
    try:
        if os.system('make') != 0:
            sys.stderr.write('Warning: Some of the included documentation failed to build.  Proceeding without it.\n')
    finally:
        os.chdir('..')

def set_openssl_lib_path():
    global OPENSSL_LIB_DIR

    msg = ''
    try:
        libdir = subprocess.Popen(['pkg-config', '--variable=libdir', 'openssl'], stdout=subprocess.PIPE).communicate()[0].strip()
    except (subprocess.CalledProcessError, OSError), e:
        libdir = None
        msg = str(e)
    if not libdir or not os.path.exists(libdir):
        sys.stderr.write('Warning: Unable to identify the lib directory for openssl: %s\nProceeding without support for dynamically loaded engines.\n' % msg)
    else:
        OPENSSL_LIB_DIR = "'%s'" % libdir

class MyBuild(build):
    def run(self):
        make_documentation()
        build.run(self)

class MyInstall(install):
    def run(self):
        set_openssl_lib_path()
        # if this an alternate root is specified, then embed the install_data
        # path relative to that alternate root
        if self.root is not None:
            install_data = os.path.join(os.path.sep, os.path.relpath(self.install_data, self.root))
        else:
            install_data = self.install_data
        apply_substitutions(os.path.join('dnsviz','config.py.in'), install_data)
        install.run(self)

DOC_FILES = [('share/doc/dnsviz', ['README.md'])]
DATA_FILES = [('share/dnsviz/icons', ['doc/images/error.png', 'doc/images/warning.png']),
        ('share/dnsviz/css', ['share/css/dnsviz.css']),
        ('share/dnsviz/js', ['share/js/dnsviz.js']),
        ('share/dnsviz/html', ['share/html/dnssec-template.html']),
        ('share/dnsviz/trusted-keys', ['share/trusted-keys/root.txt'])]
MAN_FILES = [('share/man/man1', ['doc/man/dnsviz.1', 'doc/man/dnsviz-probe.1', 'doc/man/dnsviz-grok.1', 'doc/man/dnsviz-graph.1', 'doc/man/dnsviz-print.1', 'doc/man/dnsviz-query.1'])]
DOC_EXTRA_FILES = [('share/doc/dnsviz', ['doc/dnsviz-graph.html']),
        ('share/doc/dnsviz/images', glob.glob(os.path.join('doc', 'images', '*.png')))]

# third-party files are only installed if they're included in the package
if os.path.exists(os.path.join('external', 'jquery-ui')):
    JQUERY_UI_FILES = [('share/dnsviz/js', ['external/jquery-ui/jquery-ui-1.11.4.custom.min.js']),
            ('share/dnsviz/css', ['external/jquery-ui/jquery-ui-1.11.4.custom.min.css']),
            ('share/dnsviz/css/images', glob.glob(os.path.join('external', 'jquery-ui', 'images', '*.png')))]
    JQUERY_UI_PATH = "'file://' + os.path.join(DNSVIZ_SHARE_PATH, 'js', 'jquery-ui-1.11.4.custom.min.js')"
    JQUERY_UI_CSS_PATH = "'file://' + os.path.join(DNSVIZ_SHARE_PATH, 'css', 'jquery-ui-1.11.4.custom.min.css')"
else:
    JQUERY_UI_FILES = []
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

setup(name='dnsviz',
        version='0.5.1',
        author='Casey Deccio',
        author_email='casey@deccio.net',
        url='https://github.com/dnsviz/dnsviz/',
        description='DNS analysis and visualization tool suite',
        long_description=open('README.md', 'r').read(),
        license='LICENSE',
        packages=['dnsviz','dnsviz.viz','dnsviz.analysis','dnsviz.commands'],
        scripts=['bin/dnsviz'],
        data_files=DOC_FILES + DATA_FILES + MAN_FILES + \
                DOC_EXTRA_FILES + JQUERY_UI_FILES + JQUERY_FILES + RAPHAEL_FILES,
        requires=[
                'pygraphviz (>=1.1)',
                'm2crypto (>=0.21.1)',
                'dnspython (>=1.11)',
        ],
        cmdclass={ 'build': MyBuild, 'install': MyInstall },
)
