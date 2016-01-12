# -*- coding: utf-8 -*-
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

import reverse

setup(
    name='reverse',
    version='1.0',
    description='Reverse engineering tool for x86/ARM/MIPS',

    url="https://github.com/joelpx/reverse",
    author="joelpx",
    author_email="Unknown",

    license="GPLv3",

    packages=['reverse',
              'reverse.lib',
              'reverse.lib.arch',
              'reverse.lib.arch.x86',
              'reverse.lib.arch.mips',
              'reverse.lib.arch.arm',
              'reverse.lib.ui',
              'reverse.lib.fileformat'],
    package_dir={'reverse':'reverse'},
    install_requires=[
        'capstone',
        'pefile',
        'pyelftools',
        'msgpack-python'
    ],
    test_suite='nose.collector',
    tests_require=[
        'nose'
    ],
    zip_safe=True,
    entry_points = {
        "console_scripts": [
            "reverse = reverse.main:console_entry",
        ],
    }
)
