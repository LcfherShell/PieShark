try:
	from .abc import ABC, ABCMeta, abstractmethod 
except:
	from abc import ABC, ABCMeta, abstractmethod

import logging, sys, traceback
from datetime import datetime

import logging
#info = logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
logger = logging.getLogger("color")
"""import logging
import colorama
from colorama import Fore, Back, Style
 
# Initialize the terminal for color
colorama.init(autoreset = True)
 
# Set up logger as usual
logger = logging.getLogger("color")
logger.setLevel(logging.DEBUG)
shandler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(message)s')
shandler.setFormatter(formatter)
logger.addHandler(shandler)
 
# Emit log message with color
logger.debug('Debug message')
logger.info(Fore.GREEN + 'Info message')
logger.warning(Fore.BLUE + 'Warning message')
logger.error(Fore.YELLOW + Style.BRIGHT + 'Error message')
logger.critical(Fore.RED + Style.BRIGHT + 'Critical message')
"""
class Socket_Error(Exception):
	pass
class Do_Under(NameError):
	pass
class Typping(TypeError):
	pass

class AbstractClass:
	__metaclass__ = ABCMeta
	@abstractmethod
	def Socket_Error(self):
		raise Socket_Error(self)

	@abstractmethod
	def Name_Error(self):
		raise Do_Under(self)

	@abstractmethod
	def Typ_Error(self):
		raise Typping(self)

	@abstractmethod
	def get_error(self):
		type_, value_, traceback_ = sys.exc_info()
		logger.error("".join(traceback.format_exception(type_ , value_, traceback_)))

class Handlerr(AbstractClass):
	def __init__(self):
		super(Handlerr, self).__init__()

		