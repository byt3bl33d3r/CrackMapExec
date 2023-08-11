# coding=utf-8
import os
import configparser
from cme.paths import CME_PATH
from cme.first_run import first_run_setup

cme_config = configparser.ConfigParser()
cme_config.read(os.path.join(CME_PATH, "cme.conf"))

if "CME" not in cme_config.sections():
    first_run_setup()
    cme_config.read(os.path.join(CME_PATH, "cme.conf"))

cme_workspace = cme_config.get("CME", "workspace", fallback="default")
config_log = cme_config.getboolean("CME", "log_mode", fallback=False)
ignore_opsec = cme_config.getboolean("CME", "ignore_opsec", fallback=False)
pwned_label = cme_config.get("CME", "pwn3d_label")
audit_mode = cme_config.get("CME", "audit_mode")
reveal_chars_of_pwd = int(cme_config.get("CME", "reveal_chars_of_pwd"))

# this should probably be put somewhere else, but if it's in the config helpers, there is a circular import
def process_secret(text):
    hidden = text[:reveal_chars_of_pwd]
    return text if not audit_mode else hidden+audit_mode * 8 
