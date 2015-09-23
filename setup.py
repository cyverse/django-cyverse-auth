from setuptools import setup, find_packages
from iplantauth import __version__

requirements = open("requirements.txt").read()

setup(
    name='django-iplant-auth',
    version=__version__,
    author='iPlantCollaborative',
    author_email='atmodevs@gmail.com',
    description="Authentication support for iPlantCollaborative.",
    install_requires=requirements,
    long_description=description,
    license="BSD License, 3 clause",
    packages=get_packages("iplantauth"),
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
