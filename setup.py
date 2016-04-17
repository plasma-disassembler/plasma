# -*- coding: utf-8 -*-
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

from distutils.core import Extension
import plasma


x86_analyzer = Extension('plasma.lib.arch.x86.analyzer',
    sources = ['plasma/lib/arch/x86/analyzer.c'])

mips_analyzer = Extension('plasma.lib.arch.mips.analyzer',
    sources = ['plasma/lib/arch/mips/analyzer.c'])

arm_analyzer = Extension('plasma.lib.arch.arm.analyzer',
    sources = ['plasma/lib/arch/arm/analyzer.c'])



setup(
    name='plasma',
    version='1.0',
    description='plasma disassembler for x86/ARM/MIPS',

    url="https://github.com/joelpx/plasma",
    author="joel",
    author_email="Unknown",

    license="GPLv3",

    ext_modules=[
        x86_analyzer,
        mips_analyzer,
        arm_analyzer,
    ],

    packages=['plasma',
              'plasma.lib',
              'plasma.lib.arch',
              'plasma.lib.arch.x86',
              'plasma.lib.arch.mips',
              'plasma.lib.arch.arm',
              'plasma.lib.ui',
              'plasma.lib.fileformat',
              'plasma.lib.fileformat.relocations'],
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
    },

)
