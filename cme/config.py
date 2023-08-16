# coding=utf-8
import os
from os.path import join as path_join
import configparser
from cme.paths import CME_PATH, DATA_PATH
from cme.first_run import first_run_setup
from cme.logger import cme_logger
from ast import literal_eval

cme_default_config = configparser.ConfigParser()
cme_default_config.read(path_join(DATA_PATH, "cme.conf"))

cme_config = configparser.ConfigParser()
cme_config.read(os.path.join(CME_PATH, "cme.conf"))

if "CME" not in cme_config.sections():
    first_run_setup()
    cme_config.read(os.path.join(CME_PATH, "cme.conf"))

# Check if there are any missing options in the config file
for section in cme_default_config.sections():
    for option in cme_default_config.options(section):
        if not cme_config.has_option(section, option):
            cme_logger.display(f"Adding missing option '{option}' in config section '{section}' to cme.conf")
            cme_config.set(section, option, cme_default_config.get(section, option))

            with open(path_join(CME_PATH, "cme.conf"), "w") as config_file:
                cme_config.write(config_file)

#!!! THESE OPTIONS HAVE TO EXIST IN THE DEFAULT CONFIG FILE !!!
cme_workspace = cme_config.get("CME", "workspace", fallback="default")
pwned_label = cme_config.get("CME", "pwn3d_label", fallback="Pwn3d!")
audit_mode = cme_config.get("CME", "audit_mode", fallback=False)
reveal_chars_of_pwd = int(cme_config.get("CME", "reveal_chars_of_pwd", fallback=0))
config_log = cme_config.getboolean("CME", "log_mode", fallback=False)
ignore_opsec = cme_config.getboolean("CME", "ignore_opsec", fallback=False)
host_info_colors = literal_eval(cme_config.get("CME", "host_info_colors", fallback=["green", "red", "yellow", "cyan"]))


if len(host_info_colors) != 4:
    cme_logger.error("Config option host_info_colors must have 4 values! Using default values.")
    host_info_colors = cme_default_config.get("CME", "host_info_colors")


# this should probably be put somewhere else, but if it's in the config helpers, there is a circular import
def process_secret(text):
    hidden = text[:reveal_chars_of_pwd]
    return text if not audit_mode else hidden+audit_mode * 8 
