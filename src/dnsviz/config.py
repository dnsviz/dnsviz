#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2014-2016 Verisign, Inc.
#
# Copyright 2016-2021 Casey Deccio
#
# DNSViz is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# DNSViz is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with DNSViz.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import unicode_literals

from importlib.resources import files
import os
from pathlib import Path
import sys

DNSVIZ_SHARE_PATH = os.getenv('DNSVIZ_SHARE_PATH', '')
if DNSVIZ_SHARE_PATH:
    DNSVIZ_SHARE_PATH = Path(DNSVIZ_SHARE_PATH)
else:
    DNSVIZ_SHARE_PATH = files('dnsviz.data')

DNSVIZ_MEDIA_PATH = DNSVIZ_SHARE_PATH / 'media'
DNSVIZ_TEMPLATE_PATH = DNSVIZ_SHARE_PATH / 'templates'
DNSVIZ_ROOT_DATA_PATH = DNSVIZ_SHARE_PATH / 'root-dns-data'

JQUERY_PATH = 'https://code.jquery.com/jquery-1.11.3.min.js'
JQUERY_UI_PATH = 'https://code.jquery.com/ui/1.11.4/jquery-ui.min.js'
JQUERY_UI_CSS_PATH = 'https://code.jquery.com/ui/1.11.4/themes/redmond/jquery-ui.css'
RAPHAEL_PATH = 'https://cdnjs.cloudflare.com/ajax/libs/raphael/2.1.4/raphael-min.js'
RESOLV_CONF = '/etc/resolv.conf'
