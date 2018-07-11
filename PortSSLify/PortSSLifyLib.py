import socket, ssl, threading, time

_debug_level = -1
def _pd(dl, *args):
    if _debug_level > dl or _debug_level < 0:
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
        _pd(0, 'Starting up server...')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(self.bind_addr)
            sock.listen(self.queue_size)        
            with self.context.wrap_socket(sock, server_side=True) as sslsock:
                _pd(0, 'Server successfully started.')
                while True:
                    self.active.acquire()
                    try:
                        addr = "'connection failure'"
                        ibc, addr = sslsock.accept()
                        _pd(2, 'Connection from client', addr)
                        obc = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                        obc.connect(self.forward_addr)
                        _pd(3, 'Success connecting to', self.forward_addr)
                        conns = _connections(ibc, obc, self.timeout, self.active.release)
                        _send(conns).start()
                        _recv(conns).start()
                        _pd(5, 'Success building bridge.')
                    except Exception as e:
                        _pd(1, 'Building bridge for client', addr, 'encountered error:', repr(e))
                        try: ibc.shutdown(socket.SHUT_RDWR)
                        finally: pass
                        try: obc.shutdown(socket.SHUT_RDWR)
                        finally: pass
                        ibc.close()
                        obc.close()
                        self.active.release()

    
class _connections:
    def __init__(self, inbound_conn, outbound_conn, timeout = 60, call_on_completion = None):
        self.ibc = inbound_conn
        self.obc = outbound_conn
        self.ibc.settimeout(timeout)
        self.obc.settimeout(timeout)
        self.id = "'"+str(object().__hash__())+"'"
        self.ext_method = call_on_completion
        self.__s = 0
        _pd(2, 'Connection state object', self.id, 'made for client', self.ibc.getpeername())
    
    def status(self):
        return self.__s == 0
    
    def exit(self, close_recv, close_send):
        try: close_recv.shutdown(socket.SHUT_RD)
        except: _pd(4, 'Socket SHUT_RD error in exit for connection', self.id)
        try: close_send.shutdown(socket.SHUT_WR)
        except: _pd(4, 'Socket SHUT_WR error in exit for connection', self.id)
        self.__s += 1
        if self.__s == 2:
            _pd(2, 'Closing connection for connection', self.id)
            self.ibc.close()
            self.obc.close()
            if self.ext_method != None:
                self.ext_method()


class _transfer(threading.Thread):
    def __init__(self, state):
        threading.Thread.__init__(self)
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
            _pd(3, 'transfer thread', "'"+type(self).__name__+"'", 'is exiting for connection', self.state.id)
            self.state.exit(r, s)


class _send(_transfer):
    def run(self):
        self.run_as(self.state.ibc, self.state.obc)

class _recv(_transfer):
    def run(self):
        self.run_as(self.state.obc, self.state.ibc)
