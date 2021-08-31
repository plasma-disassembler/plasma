# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

from distutils.core import Extension

setup(
    ext_modules=[
        Extension('plasma.lib.arch.x86.analyzer', sources = ['plasma/lib/arch/x86/analyzer.c']),
        Extension('plasma.lib.arch.mips.analyzer', sources = ['plasma/lib/arch/mips/analyzer.c']),
        Extension('plasma.lib.arch.arm.analyzer', sources = ['plasma/lib/arch/arm/analyzer.c']),
    ]
)
