from setuptools import setup, find_packages

setup(name='crackmapexec',
    version='3.1.0',
    description='A swiss army knife for pentesting Windows/Active Directory environments',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='pentesting security windows smb active-directory',
    url='http://github.com/byt3bl33d3r/CrackMapExec',
    author='byt3bl33d3r',
    author_email='byt3bl33d3r@gmail.com',
    license='BSD',
    packages=find_packages(include=[
        "cme", "cme.*"
    ]),
    install_requires=[
        'impacket==0.9.15dev0',
        'gevent',
        'netaddr',
        'pyOpenSSL',
        'pycrypto',
        'pyasn1',
        'termcolor',
        'requests'
      ],
    dependency_links = ['https://github.com/CoreSecurity/impacket/archive/master.zip#egg=impacket-0.9.15dev0'],
    entry_points = {
        'console_scripts': ['crackmapexec=cme.crackmapexec:main', 'cmedb=cme.cmedb:main'],
    },
    include_package_data=True,
    zip_safe=False)
