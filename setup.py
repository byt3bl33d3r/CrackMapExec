#!/usr/bin/env python3

import os
from setuptools import setup, find_packages
from subprocess import *

VER_MAJOR = 5
VER_MINOR = 0
VER_MAINT = 1
VER_PREREL = "dev1"
if call(["git", "branch"], stderr=STDOUT, stdout=open(os.devnull, 'w')) == 0:
    p = Popen("git log -1 --format=%cd --date=format:%Y%m%d.%H%M%S", shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
    (outstr, errstr) = p.communicate()
    (VER_CDATE,VER_CTIME) = outstr.strip().decode("utf-8").split('.')

    p = Popen("git rev-parse --short HEAD", shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
    (outstr, errstr) = p.communicate()
    VER_CHASH = outstr.strip().decode("utf-8")
    
    VER_LOCAL = "+{}.{}.{}".format(VER_CDATE, VER_CTIME, VER_CHASH)

else:
    VER_LOCAL = ""

setup(name='crackmapexec',
    version = "{}.{}.{}.{}{}".format(VER_MAJOR,VER_MINOR,VER_MAINT,VER_PREREL,VER_LOCAL),
    description='A swiss army knife for pentesting networks',
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
    keywords='pentesting security windows active-directory networks',
    url='http://github.com/byt3bl33d3r/CrackMapExec',
    author='byt3bl33d3r',
    author_email='byt3bl33d3r@protonmail.com',
    license='BSD',
    packages=find_packages(include=[
        "cme", "cme.*"
    ]),
    install_requires=[
        'gevent>=1.2.0',
        'requests>=2.9.1',
        'requests-ntlm>=0.3.0',
        'bs4',
        'termcolor',
        'msgpack',
        'pylnk3',
        'pywinrm',
        'paramiko',
        'impacket',
        'xmltodict',
        'terminaltables'
    ],
    entry_points={
        'console_scripts': ['crackmapexec=cme.crackmapexec:main', 'cme=cme.crackmapexec:main', 'cmedb=cme.cmedb:main'],
    },
    include_package_data=True,
    zip_safe=False)
