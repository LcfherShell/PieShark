import inspect, os, mimetypes, re, requests, socket
from parse import parse
from webob import Request, Response
from webob.static import DirectoryApp, FileApp, FileIter
from webob.cookies import RequestCookies , SAMESITE_VALIDATION, make_cookie, CookieProfile
from webob.dec import wsgify
import asyncio
from wsgiref.simple_server import make_server

from .handler import OrderedDict, SelectType, Struct
from .handler.error_handler import Handlerr as ERROR_MESSAGES
from .handshake import Shake as handshakes
from .templates import read_file, read_file_byets
from .configuration import config_pieshark
from threading import Thread
from werkzeug.serving import run_simple

TYPE_LOADS = {
    'jp': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'css': 'text/plain',
    'js':'text/plain'
}

ERROR_MESSAGES = ERROR_MESSAGES()
SAMESITE_VALIDATION = True
mimetypes._winreg = None
mimetypes.add_type(
    "text/javascript", ".js"
)  # stdlib default is application/x-javascript
mimetypes.add_type("image/x-icon", ".ico") 
BLOCK_SIZE = 1 << 16

class FileWrapper:
    def __init__(self, filelike, blksize=8192):
        self.filelike = filelike
        self.blksize = blksize
        if hasattr(filelike, 'close'):
            self.close = filelike.close

    def __getitem__(self, key):
        data = self.filelike.read(self.blksize)
        if data:
            return data
        raise IndexError



Struct.setname('pieshark_environ')
class pieshark(config_pieshark):
    SAMESITE_VALIDATION = SAMESITE_VALIDATION
    def __init__(self):
        self.routes = OrderedDict()
        self.configt = Struct()
        self.headers = OrderedDict()
        self.environ = OrderedDict()
        self.static_file = OrderedDict()
        self.cookie = RequestCookies(self.environ)
        self.memory = Struct()
        self.request = Struct(method=self.method)
        self.forms = self.form
    def __call__(self, environ, start_response):
        request = Request(environ)
        self.environ = environ
        if request.method == "POST":
            self.method = request.method
            #self.form = dict(request.POST)
            self.form = dict(request.POST) 
            try:
                for x in request.params:
                    self.form = { str(x) : [ request.params[x].filename , request.params[x].file.read() ] }
                    #request.params.pop(x)
            except:
                pass
            self._handler_files
        response =  self.handle_request(request)
        try:
            start_response(200, self.headers)
        except:
            pass
        return response(environ, start_response)

    def __getitem__(self, params):
        return self.__dict__

    def route(self, path):
        assert path not in self.routes, "Such route already exists."

        def wrapper(handler):
            self.routes[path] = handler
            return handler

        return wrapper

    def default_response(self, response):
        response.status_code = 404
        response.text = "Not found."

    def find_handler(self, request_path):
        for path, handler in self.routes.items():
            parse_result = parse(path, request_path)
            if parse_result is not None:
                return handler, parse_result.named

        return None, None

    def handle_request(self, request):
        response = Response()
        handler, kwargs = self.find_handler(request_path=request.path)                    
        if handler is not None:
            if inspect.isclass(handler):
                handler = getattr(handler(), request.method.lower(), None)
                if handler is None:
                    raise AttributeError("Method not allowed", request.method)
            handler(request, response, **kwargs)
        else:
            self.default_response(response)
        return response

    def loads_files(self, files):
        try:
            if os.environ.get('static'):
                root = os.environ.get('static')
                files = os.path.join(root, files)
                if os.path.isfile(files):
                    pass
                else:
                    print(f'Warning file {file} not found')
        except:
            pass
        filename, file_extension = os.path.splitext(files)
        content_type, content_encoding = mimetypes.guess_type(files)
        if file_extension in TYPE_LOADS:
            types:str = TYPE_LOADS[file_extension.lower()]
        types:self.Dict_ = content_type
        return types, content_encoding

    @property
    def _handler_files(self):
        pass

    @_handler_files.setter
    def _handler_files(self, filelike):
        if 'wsgi.file_wrapper' in self.environ:
            self.environ['wsgi.file_wrapper'](filelike, 8192)
        else:
            self.environ['wsgi.file_wrapper'] = FileWrapper

    @property
    def method(self):
        pass

    @method.setter
    def method(self, meth):
        paths = {'GET':'GET', 'POST': 'POST', 'PUT':'PUT'}
        if meth in ['GET', 'POST', 'PUT']:
            params = paths.get(meth) or paths[meth]
        del paths
        self.request.update_dict = {'method': params}

    @property
    def form(self): 
        return self.memory

    @form.setter
    def form(self, data):
        self.memory.update_dict = data

    @property 
    def header(self):
        pass

    @header.setter
    def header(self, params: SelectType.Union_):
        if isinstance(self.params, tuple):
            self.headers.append(self.params)
        elif isinstance(self.params, list):
            if len(self.params) == 2:
                self.headers.append(tuple(self.params))
        elif isinstance(self.params, dict):
            if len(self.params) == 1:
                self.headers.append( [(k, v) for k, v in self.params.items()][0] )
        else:
            raise TypeError("")

    @property
    def cookies(self):
        return self.cookie

    @cookies.setter
    def cookies(self, cookie):
        self.cookies.update(cookie)

    def run(self, host='0.0.0.0', port=80):
        handshake = handshakes()
        handshake.response(host=host, port=port)
        if handshake.saving == 'ERROR URL' or handshake.saving =='Private APP':
            try:    
                return run_simple(host, port, self)
            except:
                server = make_server(host, port, self)
                return server.serve_forever()
        else:
            ERROR_MESSAGES.Socket_Error()



























from webob import exc

class static(pieshark, SelectType):
    """docstring for static"""
    def __init__(self, filename):
        super(static, self).__init__()
        self.static = self.static_file
        """self.root = self.routes
                                self.open = read_file
                                self.types, self.content_encoding =  self.loads_files(filename)
                        
                            @wsgify
                            def __call__(self, req):
                                if req.method not in ("GET", "HEAD") or self.environ not in ("GET", "HEAD"):
                                    return exc.HTTPMethodNotAllowed("You cannot %s a file" % req.method)
                                try:
                                    stat = os.stat(self.filename)
                                except OSError as e:
                                    msg = f"Can't open {self.filename!r}: {e}"
                                    return exc.HTTPNotFound(comment=msg)
                                try:
                                    file = self.open(self.filename)
                                    print(file)
                                except OSError as e:
                                    msg = f"Can't open {self.filename!r}: {e}"
                                    return exc.HTTPForbidden(msg)
                                if "wsgi.file_wrapper" in req.environ or "wsgi.file_wrapper" in self.environ:
                                    app_iter = req.environ["wsgi.file_wrapper"](file, BLOCK_SIZE) or \
                                                self.environ["wsgi.file_wrapper"](file, BLOCK_SIZE)
                                else:
                                    app_iter = FileIter(file)
                                return Response(app_iter=app_iter, content_length=stat.st_size,
                                                last_modified=stat.st_mtime, content_type= self.types,
                                                content_encoding=self.content_encoding, accept_ranges='bytes').conditional_response_app"""
    def loads_file(self, files):
        try:
            if os.environ.get('static'):
                root = os.environ.get('static')
                files = os.path.join(root, files)
                if os.path.isfile(files):
                    pass
                else:
                    print(f'Warning file {file} not found')
        except:
            pass
        filename, file_extension = os.path.splitext(files)
        content_type, content_encoding = mimetypes.guess_type(files)
        if file_extension in TYPE_LOADS:
            types:str = TYPE_LOADS[file_extension.lower()]
        types:self.Dict_ = content_type
        return types, content_encoding
        #response = FileApp(files, content_type=types, content_encoding=content_encoding)

"""
if os.environ.get('static'):
                    paths = os.environ.get('static')
                    files_dir = os.path.join(paths, files)
            except:
                pass
            try:

if os.environ.get('static'):
            for root, subfolders, filenames in os.walk(os.environ.get('static')):
                for filename in filenames:
                    files_dir = os.path.join(root, filename)
                    print(files_dir)
                    self.loads_files(response, files_dir)
"""