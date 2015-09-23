#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import shutil

from setuptools import setup, find_packages

from iplantauth import __version__


requirements = open("requirements.txt").read()


if sys.argv[-1] == 'publish':
    if os.system("pip freeze | grep wheel"):
        print("wheel not installed.\nUse `pip install wheel`.\nExiting.")
        sys.exit()
    if os.system("pip freeze | grep twine"):
        print("twine not installed.\nUse `pip install twine`.\nExiting.")
        sys.exit()
    os.system("python setup.py sdist bdist_wheel")
    os.system("twine upload dist/*")
    print("You probably want to also tag the version now:")
    print("  git tag -a %s -m 'version %s'" % (version, version))
    print("  git push --tags")
    shutil.rmtree('dist')
    shutil.rmtree('build')
    shutil.rmtree('django_iplant_auth.egg-info')
    sys.exit()


setup(
    name='django-iplant-auth',
    version=__version__,
    author='iPlantCollaborative',
    author_email='atmodevs@gmail.com',
    description="Authentication support for iPlantCollaborative.",
    install_requires=requirements,
    license="BSD License, 3 clause",
    packages=find_packages(),
    url="https://github.com/iPlantCollaborativeOpenSource/django-iplant-auth",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 1.7",
        "Framework :: Django :: 1.8",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Systems Administration"
    ])
