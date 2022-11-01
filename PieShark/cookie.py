from .date_manages import datetime, datetime_next, datetime_now, datetime_UTF, UTC_DATE_TIME, TimeStamp
from .handler import OrderedDict, SelectType, Struct
from .handler.endecryptions import AESCipher, AESCipher_2
from os import environ as env
from hashlib import md5


class Cookie(SelectType):
	def __init__(self, salt, exp=1, app=None):
		super(Cookie, self).__init__()
		if app:
			self.environ:self.Union_ = app.environs
		else:
			self.environ:self.Union_ = env
		self.exp = exp
		self.cookie_secure = {}
		Cookie._Cookie__encreet(secure=True, salt=salt, environs=self.environ)

	def __call__(self, response):
		response.headers['Set-Cookie'] = self.cookie_secure

	def __repr__(self):
		return self.cookie_secure

	def __paired__(self, **kwargs):
		return tuple(kwargs)
	
	def base(self, request):
		cookie = self.cookie_secure
		try:
			cookies = (dict(i.split('=', 1) for i in cookie.split('; ')))
		except:
			cookies = request.cookies
		return cookies

	@classmethod
	def __encreet(cls, secure, salt, environs):
		if secure and environs.get('secret_key'):
			assert len(str(environs.get('secret_key'))) >= 3 and len(str(environs.get('secret_key'))) <= 14
			cls.defend_sec = 'rec'
			if salt and len(salt) >= 23 and len(salt) <=34:
				cls.aes = AESCipher_2(secretKey=environs.get('secret_key').strip(), salt=salt)
			else:
				cls.aes = AESCipher(key=environs.get('secret_key').strip())

	def __enc(self, path):
		get_dir = dir(self)
		self.cookie_secure = path
		if 'aes' in get_dir:
			split_get_key = str(path).split('=')
			get_key_head_cookie = split_get_key[0]
			self.path = path.replace(get_key_head_cookie, '')
			self.cookie_secure = "=" .join( [ get_key_head_cookie, "'"+self.aes.encrypt(self.path).decode('utf-8')+"'" ] )

	def __dec(self, path):
		get_dir = dir(self)
		if 'aes' in get_dir:
			path = path.replace('\'', '')
			split_get_key = str(path).split('=')
			get_key_head_cookie = split_get_key[0]
			self.path = path.replace(get_key_head_cookie, '')
			return "=" .join( [ get_key_head_cookie, self.aes.decrypt(self.path).decode('utf-8') ] )
		return path

	def crt(self, domain=None, h=None, m=None,**kwargs):
		utc = ''
		max_age, expires = [False, False]
		for x in kwargs:
			if 'max_age' in x.lower() and kwargs.get(x):
				max_age = True
			if 'expires' in x.lower() and kwargs.get(x):
				expires = True
		if expires and max_age:
			if h == None or h == False:
				h = 0
			if m == None or m == False:
				m = 0
			max_ages = self.exp * 86400
			max_ages = int(max_ages)
			utc = "Expires="+UTC_DATE_TIME(d=self.exp, h=h, m=m).toUTC+" GMT; Max-Age="+str(max_ages)+";"
			utc = str(utc)
		elif expires and max_age == False:
			if h == None or h == False:
				h = 0
			if m == None or m == False:
				m = 0
			utc = "Expires="+UTC_DATE_TIME(d=self.exp, h=h, m=m).toUTC+" GMT;"
		else:
			pass

		if domain:
			self.cookie_secure = self.cookie_secure+"; Domain="+domain+"; "+utc
		else:
			self.cookie_secure = self.cookie_secure+"; "+utc
		return self.cookie_secure