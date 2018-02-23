__license__ = '''
This file is part of Kniopass.

Kniopass is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation, either version 3 of
the License, or (at your option) any later version.

Kniopass is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General
Public License along with Kniopass.  If not, see
<http://www.gnu.org/licenses/>.
'''
# pylint: disable=bad-whitespace

from setuptools import setup

import imp
_version = imp.load_source("kniopass._version", "kniopass/_version.py")

long_description = open('README.md').read()


setup(
  name    = 'kniopass',
  version = _version.__version__,
  author  = 'Tom Flanagan',
  author_email = 'tom@zkpq.ca',
  license = 'LICENSE',
  url     = 'http://github.com/Knio/kniopass/',

  description      = 'Kniopass is a command line password manager.',
  long_description = long_description,
  keywords         = 'python password manager keepass lastpass',

  classifiers = [
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: Implementation :: PyPy',
  ],

  packages = ['kniopass'],
  include_package_data = True,
)
