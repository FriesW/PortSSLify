import socket, threading, time, uuid, re
from http.server import BaseHTTPRequestHandler
from io import BytesIO

class HTTPHeaderRewriter:
    
    def __init__(self,
                 bind = ('127.0.0.1', 80),
                 header_processor = None,
                 max_active = 10, socket_queue = 2,
                 debug_level = 0):
        self.__bind_addr = bind
        self.__external = header_processor
        self.__active = threading.Semaphore(max_active)
        self.__queue_size = socket_queue
        self.__debug_level = debug_level
    
    def __pd(self, dl, *args, **kwargs):
        if self.__debug_level > dl or self.__debug_level < 0:
            o = ''
            o += time.strftime('%x %X %Z :: ')
            if kwargs.get('id'):
                o += str(kwargs.get('id')) + ' :: '
            o += ' '.join([str(e) for e in args])
            print( o )
    
    def serve_forever(self):
        self.__pd(0, 'Starting up server...')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(self.__bind_addr)
            sock.listen(self.__queue_size)
            self.__pd(0, 'Server successfully started.')
            while True:
                self.__active.acquire()
                addr = "'connection failure'"
                conn = None
                try:
                    conn, addr = sock.accept()
                    self.__pd(2, 'Connection from client', addr)
                    threading.Thread(target = self.__handler, args=(conn,)).start()
                except Exception as e:
                    self.__pd(1, 'Building bridge for client', addr, 'encountered error:', repr(e))
                    if conn != None:
                        try: conn.shutdown(socket.SHUT_RDWR)
                        except: pass
                        conn.close()
                    self.__active.release()
                    

    def __handler(self, conn):
    
        total_read = 0
        body_beginning = None
        message_headers = ''
        
        while body_beginning == None:
            
            if total_read > 8000:
                raise ClientMaxHeaderLengthError()
            data = r.recv(1024)
            if not data:
                raise ClientEarlyDisconnectError()
            total_read += len(data)
            
            lines = re.split(r'(\r?\n){2}', data, maxsplit = 1)
            message_headers += lines[0]
            if len(lines) == 1:
                continue
            
            body_beginning = lines[1]
        
        request = HTTPRequest(message_headers)
        
        if request.error_code != None:
            raise ClientInvalidHeaderError(request.error_code)
        
        headers = request.headers
        cmd = request.command
        path = request.path
        ver = request.request_version
        
        #Do stuff...

# https://stackoverflow.com/questions/4685217/parse-raw-http-headers
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(sef, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

class ClientError(Exception):
    pass

class ClientEarlyDisconnectError(ClientError):
    pass

class ClientInvalidHeaderError(ClientError):
    def __init__(self, error):
        self.error_code = error

class ClientMaxHeaderLengthError(ClientError): #413 Entity Too Large
    pass