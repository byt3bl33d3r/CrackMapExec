import os
import sys
import cme

CME_PATH = os.path.expanduser("~/.cme")
TMP_PATH = os.path.join("/tmp", "cme_hosted")
if os.name == "nt":
    TMP_PATH = os.getenv("LOCALAPPDATA") + "\\Temp\\cme_hosted"
if hasattr(sys, "getandroidapilevel"):
    TMP_PATH = os.path.join("/data", "data", "com.termux", "files", "usr", "tmp", "cme_hosted")
WS_PATH = os.path.join(CME_PATH, "workspaces")
CERT_PATH = os.path.join(CME_PATH, "cme.pem")
CONFIG_PATH = os.path.join(CME_PATH, "cme.conf")
WORKSPACE_DIR = os.path.join(CME_PATH, "workspaces")
DATA_PATH = os.path.join(os.path.dirname(cme.__file__), "data")
