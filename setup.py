# -*- coding: utf-8 -*-

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup


from pip.req import parse_requirements
from distutils.core import Extension
import plasma

requirements = parse_requirements('requirements.txt', session=False)

requires = []
for item in requirements:
    # we want to handle package names and also repo urls
    if getattr(item, 'url', None):  # older pip has url
        links.append(str(item.url))
    if getattr(item, 'link', None): # newer pip has link
        links.append(str(item.link))
    if item.req:
        requires.append(str(item.req))


x86_analyzer = Extension('plasma.lib.arch.x86.analyzer',
    sources = ['plasma/lib/arch/x86/analyzer.c'])

mips_analyzer = Extension('plasma.lib.arch.mips.analyzer',
    sources = ['plasma/lib/arch/mips/analyzer.c'])

arm_analyzer = Extension('plasma.lib.arch.arm.analyzer',
    sources = ['plasma/lib/arch/arm/analyzer.c'])


setup(
    name='plasma',
    version='1.0',
    url="https://github.com/joelpx/plasma",
    description='plasma disassembler for x86/ARM/MIPS',
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
              'plasma.lib.fileformat.relocations',
              'plasma.scripts',
    ],
    package_dir={'plasma':'plasma'},
    install_requires=requires,
    entry_points = {
        "console_scripts": [
            "plasma = plasma.main:console_entry",
        ],
    },
)
