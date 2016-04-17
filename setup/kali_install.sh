#! /bin/bash

IFS='/' read -a array <<< pwd

if [[ "$(pwd)" != *setup ]]
then
    cd ./setup
fi

echo -e '\n [*] Installing core deps\n'
apt-get install -y libssl-dev libffi-dev python-dev virtualenvwrapper build-essential

echo -e '\n [*] Intializing and updating submodules\n'
git submodule init
git submodule update --recursive

echo -e '\n [*] Setting up virtualenvwrapper and creating the CME virtualenv\n'
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
echo 'source /usr/share/virtualenvwrapper/virtualenvwrapper.sh' >> ~/.bashrc
mkvirtualenv CME
workon CME
echo 'CME' > ../.venv

echo -e '\n [*] Installing python deps\n'
pip install -r ../requirements.txt

echo -e '\n [*] Creating the database\n'
python setup_database.py

echo -e '\n [*] Setup complete!\n'

echo -e "[*] To run CME you must first do 'workon CME' (first time you might get a 'command not found' error if so restart your terminal or run 'source /usr/share/virtualenvwrapper/virtualenvwrapper.sh'\n"
echo -e "[*] To use Kali's python dependencies and run other python tools run 'deactivate CME'"