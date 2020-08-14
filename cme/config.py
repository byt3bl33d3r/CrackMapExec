
from pathlib import Path

VERSION='xxx'
RELEASED='n/a'

# grabs the install directory to reference cme's location.
# dont edit this one. 
CME_DIR = Path(__file__).parents[0]

########################################################################
#                    Make Edits below this line                        #
########################################################################

WORKSPACE = 'default'
last_used_db = None
pwn3d_label = 'LocalAdmin!'

#Modify the home directory where everything gets stored
CME_HOME = Path.home() / '.cme'

TMP_PATH = CME_HOME / 'tmp'
WS_PATH = CME_HOME / 'workspaces'
CERT_PATH = CME_HOME / 'cmecert.pem'
KEY_PATH = CME_HOME / 'cmekey.pem'
CONFIG_PATH = CME_HOME / 'cme.conf'
LOGS_PATH = CME_HOME / 'logs'
OBF_PATH = CME_HOME / 'obfuscated_scripts'


THIRD_PARTY_PATH = CME_DIR / 'thirdparty'
CME_MOD_DIR = CME_DIR / 'modules'
CME_PROTO_DIR = CME_DIR / 'protocols'
DATA_PATH = CME_DIR / 'data'
PS_PATH = DATA_PATH / 'powershell_scripts'


PROC_PATH = CME_HOME / 'procdump64.exe'
DUMP_PATH = 'safe.dmp'

AZ_PATH = CME_HOME / 'azure'
AZ_CONFIG_PATH = AZ_PATH / 'configdone.txt'

TEST_PATH = CME_HOME / 'test.txt'
