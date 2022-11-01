import re, os, sys, uuid
from .handler.error_handler import Handlerr
from .handler.requests_ansyc import REQUESTS
from .handler import OrderedDict, SelectType, Struct
from multiprocessing import Process
import asyncio, time, timeit
try:
    from urllib.parse import urlparse
except:
    from urlparse import urlparse

libs_version, libs_limit, all_libs = [ "https://api.cdnjs.com/libraries/{filename}?fields=versions", "https://api.cdnjs.com/libraries?search={filename}&fields=filename&limit={num}", "https://api.cdnjs.com/libraries?limit={num}" ]
#filename_, extention  = [r'\/([a-zA-Z0-9_]*)\.[a-zA-Z]*\"$', r'([a-zA-Z]*)\"$']

class PY_deJS(SelectType):
	def __init__(self):
		super(PY_deJS, self).__init__()
		self.map_token:self.Union_ = ''
		self.app = REQUESTS()
		self.json = self.Dict_
		self.jnode = self.Dict_


	def js_map(self, maps):
		try:
			filename = re.findall(r'\/([a-zA-Z0-9_]*)\.[a-zA-Z]*\"$', maps)[0]
			extention = re.findall(r'([a-zA-Z]*)\"$', maps)[0]
		except:
			path = urlparse(maps).path
			filename, extention = os.path.splitext(path)

		if filename in maps and extention.replace('.', '') == 'js':
			self.js_map_token = str(uuid.uuid3(uuid.NAMESPACE_DNS, 'cdnjs.cloudflare.com'))
			self.map_token:self.Union_ = str(self.js_map_token)
		else:
			self.js_map_token:self.Union_ = str(self.map_token)

	def requests(self, search, limit, select=None):
		#if self.js_map_token.bytes != uuid.UUID( "{{token}}".format(token=self.map_token)):
		#	assert len(self.js_map_token) >= 30
		if select:
			if isinstance(select, str):
				if select.lower() == "all":
					maps = all_libs
				elif select.lower() == "select":
					maps  = libs_limit
		else:
			if select == None or select.strip() == '':
				maps = all_libs
		return maps.format(filename=search, num=limit)


	def get(self, search, limit=4, select='select'):
		if limit <= 2:
			assert 0 == 0
		loop = asyncio.get_event_loop()
		response = loop.run_until_complete(self.app.async_requests([self.requests(search=search, limit=limit, select=select)]))
		if response[0].headers.get('Content-Type') != "application/json":
			assert 0 == 0
		
		self.json = response[0].json()['results']

	def select(self, select):
		if len(self.json) != 0:
			mu = 0
			for data_json in self.json:
				if select in data_json.get('latest'):
					self.jnode = self.json[mu]
					break
				else:
					mu +=1
	@property
	def link(self):
		link:str = self.jnode['latest']
		return link

	@property
	def script(self):
		script:str = self.jnode['latest']
		self.js_map(script)
		return '<script type="text/javascript" scr="{script}" jnode="{jnode}"></script>'.format(script=script, jnode=self.js_map_token)