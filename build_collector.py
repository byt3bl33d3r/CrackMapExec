# -*- coding: latin-1 -*-

import os
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path

from shiv.bootstrap import Environment

# from distutils.ccompiler import new_compiler
from shiv.builder import create_archive
from shiv.cli import __version__ as VERSION

def build_cme():
    print("building CME")
    try:
        shutil.rmtree("build")
        shutil.rmtree("bin")
    except:
        pass

    try:
        print("remove useless files")
        os.mkdir("build")
        os.mkdir("bin")
        shutil.copytree("cme", "build/cme")
        #remove useless file > 10mo
        shutil.copy("cme/data/netripper/PowerShell/Invoke-NetRipper.ps1", "cme/data/")
        shutil.rmtree("cme/data/netripper")
        os.mkdir("cme/data/netripper/")
        os.mkdir("cme/data/netripper/PowerShell/")
        shutil.move("cme/data/Invoke-NetRipper.ps1", "cme/data/netripper/PowerShell/")

        shutil.copy("cme/data/invoke-vnc/Invoke-Vnc.ps1", "cme/data/")
        shutil.rmtree("cme/data/invoke-vnc/")
        os.mkdir("cme/data/invoke-vnc/")
        shutil.move("cme/data/Invoke-Vnc.ps1", "cme/data/invoke-vnc/")      

        shutil.rmtree("cme/data/powersploit/Recon/Dictionaries/")
        shutil.rmtree("cme/data/powersploit/Exfiltration/NTFSParser/")
        shutil.rmtree("cme/data/powersploit/CodeExecution/Invoke-ReflectivePEInjection_Resources/")
        shutil.rmtree("cme/data/powersploit/Exfiltration/LogonUser/")
        shutil.rmtree("cme/data/powersploit/Tests/")  
    except Exception as e:
        print(e)
        return

    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt" ,"-t", "build"],
        check=True
    )

    #[shutil.rmtree(p) for p in Path("build").glob("**/__pycache__")]
    [shutil.rmtree(p) for p in Path("build").glob("**/*.dist-info")]

    env = Environment(
        built_at=datetime.utcfromtimestamp(int(time.time())).strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        entry_point="cme.crackmapexec:main",
        script=None,
        compile_pyc=False,
        extend_pythonpath=True,
        shiv_version=VERSION,
    )
    create_archive(
        [Path("build").absolute()],
        Path("bin/cme"),
        "/usr/bin/env -S python3 -sE",
        "_bootstrap:bootstrap",
        env,
        True,
    )

def build_cmedb():
    print("building CMEDB")
    env = Environment(
        built_at=datetime.utcfromtimestamp(int(time.time())).strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        entry_point="cme.cmedb:main",
        script=None,
        compile_pyc=False,
        extend_pythonpath=True,
        shiv_version=VERSION,
    )
    create_archive(
        [Path("build").absolute()],
        Path("bin/cmedb"),
        "/usr/bin/env -S python3 -sE",
        "_bootstrap:bootstrap",
        env,
        True,
    )

if __name__ == "__main__":
    try:
        build_cme()
        build_cmedb()
    except:
        pass
    finally:
        shutil.rmtree("build")
