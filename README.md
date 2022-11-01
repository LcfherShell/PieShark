<p align="center">
	<img src="https://user-images.githubusercontent.com/41547742/195372022-4e48d086-7af3-4f5a-a871-72522f3bde9b.jpg" width=200px height=200px>
</p>
# PieShark is a small framework for creating secure APIs and is recommended using python 3.4^.

What you get from this framework:

- Cryptography

- Javascript obfuscator

- Fast HTTP Requests

- Javascript CDN

## Installation steps:
```console
$ pip install pieshark

---> 100%
```
## Simple Code:
```Python hl_lines="4  9-12  25-27"

from PieShark.main import pieshark, read_file
from PieShark.session import SESSION
from PieShark.cookie import Cookie
from PieShark.templates import Templates
from PieShark.handler.error_handler import Handlerr
from PieShark.pydejs import PY_deJS
import os

error_res = Handlerr()
app = pieshark()
app.config.update(dict(
	secret_key = 'qxn203jsj02',
	session_permanent=True,
	url_dbase='base://sqlite3:static'
	)
	)

session = SESSION(app=app, by=1)
cookie = Cookie(salt="tJHnN5b1i6wvXMwzYMRk128", app=app)

deJS = PY_deJS()
deJS.get(search='jquery', limit=1)
deJS.select('min')


@app.route("/")
def home(request, response):
	session.insert['log'] = '222kkknk'
	cookie._Cookie__enc('data=nanda')
	templates = """
	<html>
	<head>
	    <link rel="stylesheet" href="static/example.css">
	    {{ jquery }}
	</head>
	<body>
		Hello from the HOME {{ hello }}
		<script>
		{ obfusc_js }
		alert('sss');
		{ endobfusc_js }
		</script>
		"""

	cookie.crt(max_age=True, expires=True)
	cookie(response)
	response.headers['X-Frame-Options'] = 'SAMEORIGIN'
	response.headers['Content-Type'] = 'text/html'
	response.body = Templates(templates, hello="papa", jquery=deJS.script)


@app.route("/hello/{name}")
def greeting(request, response, name):
    response.text = f"Hello, {name}"
    
@app.route("/about")
def about(request, response):
	if 'log' in session.base and session.base:
		print(session.base['log'])

	if app.request.method == 'POST':
		print(app.form.tex) #['tex'].file.read())
	#print('wsgi.file_wrapper' in request.environ)
		#print(app.cookies._environ)
	#app.cookies = {'sex':'111dd'}

	print(cookie.base(request).get('data'))
	
	response.headers['X-Frame-Options'] = 'SAMEORIGIN'
	response.headers['Content-Type'] = 'text/html'
	response.body = Templates('example.shark')

@app.route("/static/{name}")
def static(request, response, name):
	try:
		types, encoding = app.loads_files(name)
		stat = os.stat(name)
		text = read_file(name)
		response.headers['Content-Length'] = str(stat.st_size) 
		response.headers['Last-Modified'] = str(stat.st_mtime)
		response.headers['Content-Type'] =  types
		response.headers['Content-Encoding'] = encoding
		response.headers['Accept-Ranges'] = 'bytes'
	except:
		error_res.get_error()
		text = str('error_res')
		response.headers['Content-Type'] = 'text/plain'
	response.text = text



if __name__=='__main__':
	app.run()

```

f there is a bug or error please discuss

Happy coding
