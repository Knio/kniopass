from setuptools import setup

import imp
_version = imp.load_source("kniopass._version", "kniopass/_version.py")

setup(
    name='kniopass',
    version=_version.__version__,
    author='Tom Flanagan',
    author_email='tom@zkpq.ca',
    license='GPL3',
    url='https://github.com/Knio/kniopass',

    description='Simple command-line password manager',
    packages=['kniopass'],
    keywords='python password security encryption',

    classifiers=[
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities',
    ]
)
