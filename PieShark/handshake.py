import socket, OpenSSL, ssl, threading, socketserver, requests
from urllib import request as request_header

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = str(self.request.recv(1024), 'ascii')
        cur_thread = threading.current_thread()
        response = bytes("{}: {}".format(cur_thread.name, data), 'ascii')
        self.request.sendall(response)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

def client(ip, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.sendall(bytes(message, 'ascii'))
        response = str(sock.recv(1024), 'ascii')
        print("Received: {}".format(response))

HOST, PORT = "127.0.0.1", 80

"""if __name__ == "__main__":
    # Port 0 means to select an arbitrary unused port
    

    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    with server:
        ip, port = server.server_address
        print(ip, port)
        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        print("Server loop running in thread:", server_thread.name)

        client(ip, port, "Hello World 1")
        client(ip, port, "Hello World 2")
        client(ip, port, "Hello World 3")
        server.serve_forever()

"""
"""import ssl

hostname = 'www.google.com'
context = ssl.create_default_context()

with socket.create_connection((hostname, 80)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssock.version())"""

"""with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b"Hello, world")
    data = s.recv(1024)
print(data)
"""
class Shake:
    def __init__(self):
        super(Shake, self).__init__()
        self.response_outputs = ''

    def response(self, host:str,port:int=80):
            response_output = 'Private APP'
            if port != 80:
                urls = 'http://{host}:{port}'.format(host=host, port=port)
            else:
                urls = 'http://{host}'.format(host=host)

            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with request_header.urlopen(urls, context=ctx) as f:
                    response_output = f.headers
            except:
                try:
                    with requests.get(urls) as res:
                        response_output = res.headers
                except:
                    response_output = 'ERROR URL'
                    """try:
                                                                                    s = socket.create_connection((host, port))
                                                                                    s.send("GET / HTTP/1.1\r\n\r\n".encode('utf-8'))
                                                                                    x = s.recv(800)
                                                                                    response_output =  x.decode('utf-8')
                                                                                    if '404' in response_output:
                                                                                        response_output = 'Private APP'
                                                                                except:
                                                                                    """

            finally:
                self.saving = str(response_output)

    @property
    def saving(self):
        return self.response_outputs

    @saving.setter
    def saving(self, response_output:str):
        self.response_outputs = response_output
