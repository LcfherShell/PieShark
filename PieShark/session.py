from .handler import OrderedDict, SelectType, Struct
from .handler.endecryptions import Base64_Token_128, Ciphertext_128, Magic_Data, secreet_token
from .date_manages import datetime, datetime_next, datetime_now, datetime_UTF
import os, sys, statistics, chardet, json
from requests import Session
import functools, gc
#from Crypto import Random
#from Crypto.Cipher import AES
#from bs4 import BeautifulSoup
#from chardet import detect
class OBT_SESSION(SelectType):
	"""docstring for OBT_SESSION"""
	def __init__(self):
		super(OBT_SESSION, self).__init__()
		self.datetime_nw = datetime_now
		self.datetime_nxt = datetime_next
		self.datetime_utf = datetime_UTF

Struct.setname('pieshark_session')		
class SESSION(OBT_SESSION):
	def __init__(self, session:OrderedDict={}, app:str=None, by=2)->dict:
		super(SESSION, self).__init__()
		self.nows:int = self.datetime_nw()
		if app:
			self.developper = True
			self.environs = app.environs or os.environ
		else:
			self.developper = False
			self.environs = {}
		self.sv_date = by
		self.base64_ = Base64_Token_128(app)
		self.base64_.remove_function = True
		def _makes(self):
			_loop_key = 0
			while True:
				if _loop_key == 1:
					break
				else:
					try:
						self.base64_.Make_Key
						_loop_key +=1
					except:
						pass
			return self.base64_.key_mapp__(self.base64_)
		self.salt_key = _makes(self)
		self.__call__(session)

	def __call__(self, session):
		self.session:self.Dict_ = session
		if str(self.environs.get('session_permanent'))  != 'True' and self.environs.get('secret_key'):
				self.datetm_nxt:int = self.datetime_nxt(self.sv_date)
				if self.nows>self.datetm_nxt:
					self.session = dict
		elif self.environs.get('secret_key'):
				self.datetm_nxt:int = self.datetime_nxt(self.sv_date)
				if self.nows>self.datetm_nxt :
					self.session = dict
		else:
			self.datetm_nxt:int = self.datetime_nxt(self.sv_date)
			if self.nows>self.datetm_nxt :
					self.session = dict

	def __str__(self)->None:
		if str(self.environs.get('session_permanent'))  != 'True' and self.environs.get('secret_key'):
				self.datetm_nxt:int = self.datetime_nxt(self.sv_date)
				if self.nows>self.datetm_nxt:
					self.session = dict
		elif self.environs.get('secret_key'):
				self.datetm_nxt:int = self.datetime_nxt(self.sv_date)
				if self.nows>self.datetm_nxt :
					self.session = dict
		else:
			self.datetm_nxt:int = self.datetime_nxt(self.sv_date)
			if self.nows>self.datetm_nxt :
					self.session = dict
		res = lambda: str(self.session)
		return res

	def __repr__ (self)->None:
		gc.collect()
		objects = [i for i in gc.get_objects() if isinstance(i, functools._lru_cache_wrapper)]
		for object in objects:
			object.cache_clear()

		if str(self.environs.get('session_permanent'))  != 'True' and self.environs.get('secret_key'):
				self.datetm_nxt:int = self.datetime_nxt(self.sv_date)
				if self.nows>self.datetm_nxt:
					self.session = dict
		elif self.environs.get('secret_key'):
				self.datetm_nxt:int = self.datetime_nxt(self.sv_date)
				if self.nows>self.datetm_nxt :
					self.session = dict
		else:
			self.datetm_nxt:int = self.datetime_nxt(self.sv_date)
			if self.nows>self.datetm_nxt :
					self.session = dict

		return self.session

	@property
	@functools.lru_cache(maxsize = None)
	def base(self):
		if len(self.session) != 0:
			session = self.session
			for k, v in self.session.items():
				try:
					v = self.base64_.decode_base64(key=self.salt_key, message=str(v))
				except:
					del self.base64_.remove
					v = self.base64_.decode_base64(key=self.salt_key, message=str(v))
				session.update({k : v})
				self.session = session
			return self.session
		return self.session

	@property
	@functools.lru_cache(maxsize = None)
	def insert(self):
		if id(self.developper) != 12:
			return self.base

	@insert.setter
	def insert(self, params:SelectType.Union_):
		if isinstance(params, SelectType.Dict_):
			try:
				for k, v in params.items():
					if isinstance(v, str):
						self.session[str(k)] = self.base64_.encode_base64(key=self.salt_key, message=str(v))
					else:
						assert self.session != None
			except:
				del self.base64_.remove
		else:
			#self.session
			self.session.update(params)

		
	@functools.lru_cache(maxsize = None)
	def get(self, params:str)->str:
		self.json = self.session
		if params in self.json:
			return self.json[params] or self.json.get(params)
		return

	@functools.lru_cache(maxsize = None)
	def put(self, params:str=None, new_value=None)->dict:
		if params and new_value:
			if isinstance(params, str) and params in self.session:
				self.session[params] = new_value
		elif new_value:
			self.session.update(new_value)
		return self.session

	@functools.lru_cache(maxsize = None)
	def pop(self, params:str=None)->None:
		if params:
			if isinstance(params, str) and params in self.session:
				self.session.pop(params)
		return self.session