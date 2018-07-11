import socket, ssl, threading, time

_debug_level = -1
def _pd(dl, *args):
    if _debug_level < dl:
        print( time.strftime('%x %X %Z :: ') + ' '.join([str(e) for e in args]) )

class PortSSLify:
    
    def __init__(self,
                 certfile_path = 'cert.pem', keyfile_path = 'key.pem',
                 bind = ('127.0.0.1', 443), forward = ('127.0.0.1', 80),
                 max_active = 10, socket_queue = 2,
                 ssl_protocol = ssl.PROTOCOL_TLSv1_2,
                 timeout = 10,
                 debug_level = -1):
        self.bind_addr = bind
        self.forward_addr = forward
        self.active = threading.Semaphore(max_active)
        self.queue_size = socket_queue
        self.protocol = ssl_protocol
        self.timeout = timeout
        _debug_level = debug_level
        
        self.context = ssl.SSLContext(self.protocol)
        self.context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)
    
    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(self.bind_addr)
            sock.listen(self.queue_size)        
            with self.context.wrap_socket(sock, server_side=True) as sslsock:
                while True:
                    self.active.acquire()
                    try:
                        ibc, addr = sslsock.accept()
                        _pd(1, 'Connection from', addr)
                        obc = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                        obc.connect(self.forward_addr)
                        conns = __connections(ibc, obc, self.timeout, self.active.release)
                        __send(conns).start()
                        __recv(conns).start()
                    except:
                        self.active.release()

    
    class __connections:
        def __init__(self, inbound_conn, outbound_conn, timeout = 60, call_on_completion = None):
            self.ibc = inbound_conn
            self.obc = outbound_conn
            self.ibc.settimeout(timeout)
            self.obc.settimeout(timeout)
            self.ext_method = call_on_completion
            self.__s = 0
        
        def status(self):
            return self.__s == 0
        
        def exit(self, close_recv, close_send):
            close_recv.shutdown(socket.SHUT_RD)
            close_send.shutdown(socket.SHUT_WR)
            self.__s += 1
            if self.__s == 2:
                self.ibc.close()
                self.obc.close()
                if self.ext_method != None:
                    self.ext_method()
        
    
    class __transfer(threading.Thread):
        def __init__(self, state):
            self.state = state
        
        def run_as(self, r, s):
            def recv():
                while self.state.status():
                    try: return r.recv(1024)
                    except socket.timeout: pass
            try:
                data = recv()
                while data:
                    s.sendall(data)
                    data = recv()
            finally:
                self.state.exit(r, s)
                
    
    class __send(__transfer):
        def run(self):
            self.run_as(self.state.ibc, self.state.obc)
    
    class __recv(__transfer):
        def run(self):
            self.run_as(self.state.obc, self.state.ibc)