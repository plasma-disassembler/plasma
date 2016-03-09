# -*- coding: utf-8 -*-
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

import plasma

setup(
    name='plasma',
    version='1.0',
    description='plasma disassembler for x86/ARM/MIPS',

    url="https://github.com/joelpx/plasma",
    author="joel",
    author_email="Unknown",

    license="GPLv3",

    packages=['plasma',
              'plasma.lib',
              'plasma.lib.arch',
              'plasma.lib.arch.x86',
              'plasma.lib.arch.mips',
              'plasma.lib.arch.arm',
              'plasma.lib.ui',
              'plasma.lib.fileformat'],
    package_dir={'plasma':'plasma'},
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
    entry_points = {
        "console_scripts": [
            "plasma = plasma.main:console_entry",
        ],
    }
)
