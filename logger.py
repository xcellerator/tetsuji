#!/usr/bin/env python3

import logging
import colorama as c
import sys

from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import Terminal256Formatter
from pprint import pformat, pprint

class ExitOnExceptionHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        if record.levelno == logging.FATAL:
            #raise KeyboardInterrupt
            sys.exit()

c.init(autoreset=True)

logging.addLevelName(logging.DEBUG, f"{c.Fore.BLUE}[D]")
logging.addLevelName(logging.INFO, f"{c.Fore.GREEN}[+]")
logging.addLevelName(logging.WARN, f"{c.Fore.YELLOW}[-]")
logging.addLevelName(logging.ERROR, f"{c.Fore.RED}[!]")
logging.addLevelName(logging.FATAL, f"{c.Style.DIM}{c.Fore.BLACK}{c.Back.RED}[!!]")

logging.basicConfig(
    format=f"%(levelname)s %(message)s{c.Style.RESET_ALL}",
    level=logging.INFO,
    handlers=[ExitOnExceptionHandler()]
)

log = logging.getLogger()
