![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/byt3bl33d3r?label=byt3bl33d3r&style=social)](https://twitter.com/intent/follow?screen_name=byt3bl33d3r) [![Twitter](https://img.shields.io/twitter/follow/mpgn_x64?label=mpgn_x64&style=social)](https://twitter.com/intent/follow?screen_name=mpgn_x64)

# CrackMapExec

<p align="center">
  <img src="https://cloud.githubusercontent.com/assets/5151193/17577511/d312ceb4-5f3b-11e6-8de5-8822246289fd.jpg" alt="cme"/>
</p>

This project was initially created in 2015 by **@byt3bl33d3r**, in 2019 I started to invest myself in the project. Five years laters this awesome project is still maintained and up to date ! Lot of new additions have been made to create a tool still relevant to the new Active Directory attacks paths and countermeasures setup by Microsoft ! ⚔️

You are on the **latest up-to-date** repository of the project CrackMapExec ! 🎉

- 🚧 If you want to report a problem, open un [Issue](https://github.com/mpgn/CrackMapExec/issues) 
- 🔀 If you want to contribute, open a [Pull Request](https://github.com/mpgn/CrackMapExec/pulls)
- 💬 If you want to discuss, open a [Discussion](https://github.com/mpgn/CrackMapExec/discussions)

## Official Discord Channel

If you don't have a Github account, you can ask your question on Discord

[![Porchetta Industries](https://discordapp.com/api/guilds/736724457258745996/widget.png?style=banner3)](https://discord.gg/ycGXUxy)

# Acknowledgments
**(These are the people who did the hard stuff)**

This project was originally inspired by:
- [CredCrack](https://github.com/gojhonny/CredCrack)
- [smbexec](https://github.com/pentestgeek/smbexec)
- [smbmap](https://github.com/ShawnDEvans/smbmap)

Unintentional contributors:

- The [Empire](https://github.com/PowerShellEmpire/Empire) project
- @T-S-A's [smbspider](https://github.com/T-S-A/smbspider) script
- @ConsciousHacker's partial Python port of Invoke-obfuscation from the [GreatSCT](https://github.com/GreatSCT/GreatSCT) project

# Installation

There are multiple ways you can choose to go about the installation part, it depends on your goals and on which one you find the easiest. 

### Python Package

If you want to use this method over the others, it is highly recommended to use [pipx](https://pypi.org/project/pipx/) instead of the classical pip. pipx is a tool that lets you install and run Python applications in isolated environments, making them globally accessible from your terminal, just like standard Linux commands. This way, you can avoid dependency conflicts, system breakage, and other issues that might occur when you install Python packages globally. To use pipx, you need to follow these steps:

- Install pipx using `python3 -m pip install pipx`. This command uses pip to install pipx on your system.
- Run `pipx ensurepath` to add the pipx binary directory to your PATH environment variable. This allows you to run pipx commands from anywhere on your terminal.
- Install crackmapexec using `pipx install crackmapexec`. This command creates a separate virtual environment for crackmapexec and installs it there. You can then run crackmapexec as a command-line tool.

### Docker

Use docker to run the tool in a containerized environment. Docker is a platform that allows you to build, run, and share applications using containers. Containers are isolated environments that contain everything your application needs to run, such as code, libraries, and dependencies. This way, you can run your application on any system that supports docker, without worrying about compatibility issues. For this method, you can just run the following command: `docker pull byt3bl33d3r/crackmapexec`.

### Binaries

Download the correct and latest binaries of CrackMapExec for your OS [here](https://github.com/byt3bl33d3r/CrackMapExec/releases).

### Installing from Source

**IMPORTANT:** you should only install from source if you intend on making changes to the code and/or submitting a PR.

To install CME from source, you need to do the following:

- Use the `--recursive` flag when you clone the repository. This flag ensures that you download all of the sub-modules that CME depends on. Without this flag, the installation will likely fail.
- Download [Poetry](https://python-poetry.org/docs/#installing-with-pipx), a tool that helps you build, manage, and publish Python projects. Poetry automatically handles the creation of virtual environments and the installation of dependencies for CME. This way, you can avoid conflicts and errors that might occur when you use pip or other tools.
- Run the commands below to install the required packages, clone the repository, install CME, and run it.

```
#~ apt-get install -y libssl-dev libffi-dev python-dev build-essential
#~ git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec
#~ cd CrackMapExec
#~ poetry install
#~ poetry run crackmapexec
```

To learn more about installation instructions, please refer to [official wiki](https://www.crackmapexec.wiki/getting-started/installation) or [here](https://github.com/byt3bl33d3r/CrackMapExec/wiki/Installation).

# Documentation, Tutorials, Examples
See the project's [wiki](https://www.crackmapexec.wiki/) for documentation and usage examples

# Code Contributors

Awesome code contributors of CME:

[![](https://github.com/Marshall-Hallenbeck.png?size=50)](https://github.com/Marshall-Hallenbeck)
[![](https://github.com/zblurx.png?size=50)](https://github.com/zblurx)
[![](https://github.com/NeffIsBack.png?size=50)](https://github.com/NeffIsBack)
[![](https://github.com/Hackndo.png?size=50)](https://github.com/Hackndo)
[![](https://github.com/nurfed1?size=50)](https://github.com/nurfed1)


# To do
- ~~0wn everything~~
