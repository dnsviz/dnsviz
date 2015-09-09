#!/usr/bin/env python

import glob
import os
import stat
import sys

from distutils.core import setup
from distutils.dist import Distribution
from distutils.command.install import install
from distutils.command.build import build

_install = install(Distribution())
_install.finalize_options()
INSTALL_DATA = _install.install_data

def apply_install_prefix(filename):
    assert filename.endswith('.in'), 'Filename supplied for customization must end with \'.in\': %s' % (filename)

    filename_out = filename[:-3]

    if os.path.exists(filename_out) and os.path.getctime(filename_out) > os.path.getctime(filename):
        return

    in_fh = open(filename, 'r')
    out_fh = open(filename_out, 'w')
    s = in_fh.read()
    s = s.replace('__DNSVIZ_INSTALL_PREFIX__', INSTALL_DATA)
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

class MyBuild(build):
    def run(self):
        apply_install_prefix(os.path.join('dnsviz','config.py.in'))
        make_documentation()
        build.run(self)

DOC_FILES = [('share/doc/dnsviz', ['README.md', 'LICENSE'])]
DATA_FILES = [('share/dnsviz/icons', glob.glob(os.path.join('share', 'icons', '*.png'))),
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
else:
    JQUERY_UI_FILES = []
if os.path.exists(os.path.join('external', 'jquery')):
    JQUERY_FILES = [('share/dnsviz/js', ['external/jquery/jquery-1.11.3.min.js'])]
else:
    JQUERY_FILES = []
if os.path.exists(os.path.join('external', 'raphael')):
    RAPHAEL_FILES = [('share/dnsviz/js', ['external/raphael/raphael-min.js'])]
else:
    RAPHAEL_FILES = []

setup(name='dnsviz',
        version='0.4.0',
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
        cmdclass={ 'build': MyBuild },
)
