import sys
from core.logger import *

def shutdown(exit_code):
    print_status("KTHXBYE")
    sys.exit(int(exit_code))