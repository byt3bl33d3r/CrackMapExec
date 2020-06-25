#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(name='crackmapexec',
    version='5.1.0dev',
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
        'lsassy',
        'termcolor',
        'msgpack',
        'neo4j',
        'pylnk3',
        'pypsrp',
        'paramiko',
        'impacket',
        'xmltodict',
        'terminaltables',
        'lsassy'
    ],
    entry_points={
        'console_scripts': ['crackmapexec=cme.crackmapexec:main', 'cme=cme.crackmapexec:main', 'cmedb=cme.cmedb:main'],
    },
    include_package_data=True,
    zip_safe=False)
