# coding=utf-8
import os
from os.path import join as path_join
import configparser
from cme.paths import CME_PATH, DATA_PATH
from cme.first_run import first_run_setup
from cme.logger import cme_logger

cme_default_config = configparser.ConfigParser()
cme_default_config.read(path_join(DATA_PATH, "cme.conf"))

cme_config = configparser.ConfigParser()
cme_config.read(os.path.join(CME_PATH, "cme.conf"))

if "CME" not in cme_config.sections():
    first_run_setup()
    cme_config.read(os.path.join(CME_PATH, "cme.conf"))

for option in cme_default_config.options("CME"):
    if option not in cme_config.options("CME"):
        cme_logger.info("Adding missing option '{}' to cme.conf".format(option))
        cme_config.set("CME", option, cme_default_config.get("CME", option))

# These options have to exist in the default config file!!
cme_workspace = cme_config.get("CME", "workspace", fallback="default")
config_log = cme_config.getboolean("CME", "log_mode", fallback=False)
ignore_opsec = cme_config.getboolean("CME", "ignore_opsec", fallback=False)
pwned_label = cme_config.get("CME", "pwn3d_label", fallback="Pwn3d!")
audit_mode = cme_config.get("CME", "audit_mode", fallback=False)
reveal_chars_of_pwd = int(cme_config.get("CME", "reveal_chars_of_pwd", fallback=0))
host_info_colors = cme_config.get("CME", "host_info_colors", fallback=["green", "red", "yellow", "cyan"])

if len(host_info_colors) != 4:
    host_info_colors = ["green", "red", "yellow", "cyan"]


# this should probably be put somewhere else, but if it's in the config helpers, there is a circular import
def process_secret(text):
    hidden = text[:reveal_chars_of_pwd]
    return text if not audit_mode else hidden+audit_mode * 8 
