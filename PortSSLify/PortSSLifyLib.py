import socket, ssl, threading, time

_debug_level = -1
def _pd(dl, *args):
    if _debug_level < dl:
        print( time.strftime('%x %X %Z :: ') + ' '.join([str(e) for e in args]) )

class PortSSLify:
    
    def __init__(self,
                 certfile_path = 'cert.pem', keyfile_path = 'key.pem',
                 bind = ('127.0.0.1', 443), forward = ('127.0.0.1', 80),
                 timeout = 60, max_active = 10, socket_queue = 2,
                 ssl_protocol = ssl.PROTOCOL_TLSv1_2,
                 debug_level = -1):
        self.bind_addr = bind
        self.forward_addr = forward
        self.active = threading.Semaphore(max_active)
        self.timeout = timeout
        self.queue_size = socket_queue
        self.protocol = ssl_protocol
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
                        conns = __connections(ibc, obc)
                        __send(conns).start()
                        __recv(conns).start()
                    except:
                        self.active.release()

    
    class __connections:
        def __init__(self, inbound_conn, outbound_conn):
            self.ibc = inbound_conn
            self.obc = outbound_conn
            self.__s = 2
        
        def status(self):
            return bool(self.__s)
        
        def exit(self, close_recv, close_send):
            self.__s -= 1
            try: close_recv.shutdown(socket.SHUT_RD)
            finally: pass
            try: close_send.shutdown(socket.SHUT_WR)
            finally: pass
            if not self.__s:
                self.ibc.close()
                self.obc.close()
                self.active.release()
        
    
    class __transfer(threading.Thread):
        def __init__(self, state):
            self.state = state
        
        def run_as(self, r, s):
            try:
                data = r.recv(1024)
                while data and self.state.status():
                    s.sendall(data)
                    data = r.recv(1024)
            finally:
                self.state.exit(r, s) # <- no good. Need to swap r and s depending upon where error came from
                
    
    class __send(__transfer):
        def run(self):
            self.run_as(self.state.ibc, self.state.obc)
    
    class __recv(__transfer):
        def run(self):
            self.run_as(self.state.obc, self.state.ibc)