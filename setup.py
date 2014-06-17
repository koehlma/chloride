#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# Copyright (C) 2014, Maximilian Köhl <linuxmaxi@googlemail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import os
import sys

from distutils.core import setup

__path__ = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(__path__, 'src'))

import chloride

setup(name=chloride.__short_name__,
      version=chloride.__version__,
      description=chloride.__desc_short__,
      long_description=chloride.__desc_long__,
      author=chloride.__author__,
      author_email=chloride.__email__,
      url=chloride.__website__,
      download_url=chloride.__download_url__,
      license='GPLv3+',
      packages=['chloride'],
      package_dir={'' : 'src'},
      classifiers=['Development Status :: 5 - Production/Stable',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: GNU General Public License v3 '
                   'or later (GPLv3+)',
                   'Operating System :: MacOS :: MacOS X',
                   'Operating System :: Microsoft :: Windows',
                   'Operating System :: POSIX',
                   'Programming Language :: Python :: 3'])
