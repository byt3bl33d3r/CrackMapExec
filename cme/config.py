import os
import configparser
from cme.paths import CME_PATH
from cme.first_run import first_run_setup
from cme.logger import cme_logger

cme_config = configparser.ConfigParser()
cme_config.read(os.path.join(CME_PATH, 'cme.conf'))

try:
    audit_mode = cme_config.get("CME", "audit_mode")
except configparser.NoSectionError:
    first_run_setup(cme_logger)

cme_workspace = cme_config.get("CME", "workspace", fallback="default")
config_log = cme_config.getboolean("CME", "log_mode", fallback=False)
