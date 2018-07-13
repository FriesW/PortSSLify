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
        raw_headers = ''
        leftover = None
        while leftover == None:
            data = r.recv(1024)
            if not data:
                return #TODO exit
            s = re.split('\n\n|\r\n\r\n', data, maxsplit = 1)
            raw_headers += s[0]
            if len(s) > 1:
                leftover = s[1]
            elif len(raw_headers) > 8000:
                return #TODO exit
                
        
        rows = raw_headers.replace('\r', '').split('\n')
        headers = {}
        for r in rows[1:]:
            k, v = r.split(':', 1)
            headers[k.strip()] = v.strip()
        
        start_line = rows[0].strip().split(' ')
        if len(start_line) != 3:
            return #TODO exit
        method, target, version = start_line
    
        