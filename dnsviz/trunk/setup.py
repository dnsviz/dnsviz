#!/usr/bin/env python

import glob
import os
import sys

from distutils.core import setup
from distutils.dist import Distribution
from distutils.command.install import install

_install = install(Distribution())
_install.finalize_options()
INSTALL_DATA = _install.install_data

def apply_install_prefix(filename):
    assert filename.endswith('.in'), 'Filename supplied for customization must end with \'.in\': %s' % (filename)

    filename_out = filename[:-3]
    in_fh = open(filename, 'r')
    out_fh = open(filename_out, 'w')
    out_fh.write(in_fh.read().replace('DNSVIZ_INSTALL_PREFIX', INSTALL_DATA))
    in_fh.close()
    out_fh.close()

apply_install_prefix(os.path.join('dnsviz','config.py.in'))

setup(name='dnsviz',
        version='0.1.0',
        author='Casey Deccio',
        author_email='casey@deccio.net',
        url='http://dnsviz.net/',
        description='DNS analysis and visualization tool suite',
        long_description=open('README', 'r').read(),
        license='COPYING',
        packages=['dnsviz','dnsviz.viz'],
        scripts=['bin/dnsget', 'bin/dnsviz', 'bin/dnsgrok'],
        data_files=[
                ('share/doc/dnsviz', ['README', 'COPYING']),
                ('share/dnsviz/icons', glob.glob(os.path.join('share', 'icons', '*.png'))),
                ('share/dnsviz/css', ['share/css/dnsviz.css']),
                ('share/dnsviz/css/redmond', ['share/css/redmond/jquery-ui-1.10.4.custom.min.css']),
                ('share/dnsviz/css/redmond/images', glob.glob(os.path.join('share', 'css', 'redmond', 'images', '*.png')) + glob.glob(os.path.join('share', 'css', 'redmond', 'images', '*.gif'))),
                ('share/dnsviz/js', glob.glob(os.path.join('share', 'js', '*.js'))),
                ('share/dnsviz/html', glob.glob(os.path.join('share', 'html', '*.html'))),
        ],
        requires=[
                'pygraphviz (==1.1)',
                'm2crypto (>=0.21.1)',
                'dnspython (==1.10)',
        ],
)
