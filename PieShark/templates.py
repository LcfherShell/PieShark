import os, sys
from io import BytesIO, StringIO, open as IOpen
from lxml.html import fromstring
from .handler import SelectType
from .handler.obfuscator import find_between, JS_Obfuscator
from jinja2 import Environment, FileSystemLoader, BaseLoader
from webob import Request, Response
import mimetypes

def allow_extent(extend:SelectType.Union_)->None:
	for ext in ['html', 'html5', 'jinja2', 'jinja']:
		if extend.lower() == ext:
			break
			return True
	return False

class Jinja2_Base_Templates(SelectType):
	def __init__(self, base_html:SelectType.Union_) -> None:
		super(Jinja2_Base_Templates, self).__init__()
		if isinstance(base_html, bytes):
			self.decode_html_ = base_html.decode('utf-8')
		else:
			self.decode_html_ = str(base_html)

	def render(self, **kwargs) -> SelectType.Any_:
		if os.path.isfile(self.decode_html_):
			self.decode_html_ = read_file(self.decode_html_)
		try:
			if os.environ.get('templates'):
				paths = os.environ.get('templates')
				if os.path.isdir(paths):
					response_templates = Environment(loader=FileSystemLoader("templates/")).from_string(self.decode_html_)
			else:
				response_templates = Environment(loader=BaseLoader).from_string(self.decode_html_)
		except:
			response_templates = Environment(loader=BaseLoader).from_string(self.decode_html_)
		return response_templates.render(**kwargs)

session = []
def read_file(file_name:str)->str:
	global session
	if os.path.isfile(file_name):
		def try_utf8(data):
			try:
				return data.decode('utf-8')
			except UnicodeDecodeError:
				return data
	if len(session):
		output = "".join(session)
		session = []
	else:
		isOpen = IOpen(file_name, "rb", buffering = 0)
		output = try_utf8(isOpen.read())
		session.append(output)
	return output or "".join(session)

#####TEMPLATES
session_bytes = bytes(''.encode('utf-8'))
def Templates(filename:str, **kwargs):
	try:
		isOpen = IOpen(filename, "rb")
		output = isOpen.read()
		#session_bytes = output
		exts = os.path.splitext(filename)[1][1:].strip().lower()
		if exts == 'shark' or allow_extent(exts)==True:
			output_bytes = output.decode()
		else:
			pass
	except:
		output_bytes = filename
		#session_bytes = output_bytes
	if '{ obfusc_js }' in output_bytes:
		try:
			output_bytes = output_bytes.decode('utf-8')
		except:
			pass
		finds = find_between(output_bytes, first='{ obfusc_js }', last='{ endobfusc_js }')
		output_bytes = output_bytes.replace('{ obfusc_js }', '')
		output_bytes = output_bytes.replace('{ endobfusc_js }', '')
		obfuscator = JS_Obfuscator()
		obfuscator_result = obfuscator.javascript_start(str(finds))
		output_bytes = output_bytes.replace(finds, obfuscator_result)

	output_bytes = Jinja2_Base_Templates(output_bytes).render(**kwargs)
	return bytes(output_bytes.encode('utf-8'))

def html_parser(data, select):
	doc = fromstring(data)
	return "".join(filter(None, (e.text for e in doc.cssselect(select)[0])))

def ge_typ(filename):
	type, encoding = mimetypes.guess_type(filename)
	return type or 'application/octet-stream'

def read_file_byets(data, **kwarg):
	if os.path.isfile(data) == True:
		try:
			_read_file_ = read_file(data)
			for key in kwargs.keys():
				if f'{{ key }}' in _read_file_:
					_read_file_ = _read_file_.replace(f'{{ key }}', kwargs[key])
		except:
			pass
	else:
		_read_file_ = data

	session_bytes = bytes(_read_file_.encode('utf-8'))
	return session_bytes