import socket, threading, time, uuid, re

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
        headers = {}
        
        start_line = None
        body = None
        total_read = 0
        leftover = ''
        
        while body == None:
        
            if total_read > 8000:
                raise ClientMaxHeaderLengthError()
            data = r.recv(1024)
            if not data:
                raise ClientEarlyDisconnectError()
            
            total_read += len(data)
            leftover += data
            lines = re.split(r'\r?\n', leftover, maxsplit = 1)
            if len(lines) == 1:
                continue
            
            leftover = lines[1]
            line = lines[0]
            
            if start_line == None:
                start_line = line.split(' ')
                if len(start_line) != 3:
                    raise ClientInvalidHeaderError()
                    map(str.strip, start_line)
                continue
            
            if line[0] == '':
                body = line[1]
                continue
            
            header = line.split(':', 1)
            if len(header) != 2:
                raise ClientInvalidHeaderError()
            headers[header[0].strip()] = header[1].strip()
        
        #Do stuff...
        

class ClientError(Exception):
    pass

class ClientEarlyDisconnectError(ClientError):
    pass

class ClientInvalidHeaderError(ClientError):
    pass

class ClientMaxHeaderLengthError(ClientError):
    pass