import socket, ssl, threading, time, uuid

_debug_level = -1
def _pd(dl, *args, **kwargs):
    if _debug_level > dl or _debug_level < 0:
        o = ''
        o += time.strftime('%x %X %Z :: ')
        if kwargs.get('id'):
            o += str(kwargs.get('id')) + ' :: '
        o += ' '.join([str(e) for e in args])
        print( o )

class PortSSLify:
    
    def __init__(self,
                 certfile_path = 'cert.pem', keyfile_path = 'key.pem',
                 bind = ('127.0.0.1', 443), forward = ('127.0.0.1', 80),
                 max_active = 10, socket_queue = 2,
                 ssl_protocol = ssl.PROTOCOL_TLSv1_2,
                 debug_level = -1):
        self.bind_addr = bind
        self.forward_addr = forward
        self.active = threading.Semaphore(max_active)
        self.queue_size = socket_queue
        self.protocol = ssl_protocol
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
                    addr = "'connection failure'"
                    ibc = None
                    obc = None
                    try:
                        ibc, addr = sslsock.accept()
                        _pd(2, 'Connection from client', addr)
                        obc = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                        obc.connect(self.forward_addr)
                        _pd(3, 'Success connecting to', self.forward_addr)
                        conns = _connections(ibc, obc, self.active.release)
                        _send(conns).start()
                        _recv(conns).start()
                        _pd(5, 'Success building bridge.')
                    except Exception as e:
                        _pd(1, 'Building bridge for client', addr, 'encountered error:', repr(e))
                        if ibc != None:
                            try: ibc.shutdown(socket.SHUT_RDWR)
                            except: pass
                            ibc.close()
                        if obc != None:
                            try: obc.shutdown(socket.SHUT_RDWR)
                            except: pass
                            obc.close()
                        self.active.release()

    
class _connections:
    def __init__(self, inbound_conn, outbound_conn, call_on_completion = None):
        self.ibc = inbound_conn
        self.obc = outbound_conn
        self.id = "'"+str(uuid.uuid4())[:8]+"'"
        self.ext_method = call_on_completion
        self.__exit_lock = threading.Lock()
        _pd(2, 'Connection state object made for client', self.ibc.getpeername(), id=self.id)
    
    def exit(self):
        if not self.__exit_lock.acquire(False):
            return
        _pd(2, 'Closing connection', id=self.id)
        try: self.ibc.shutdown(socket.SHUT_RDWR)
        except: _pd(4, 'error during \'ibc.shutdown(socket.SHUT_RDWR)\' in exit', id=self.id)
        try: self.obc.shutdown(socket.SHUT_RDWR)
        except: _pd(4, 'error during \'obc.shutdown(socket.SHUT_RDWR)\' in exit', id=self.id)
        self.ibc.close()
        self.obc.close()
        if self.ext_method != None:
            self.ext_method()


class _transfer(threading.Thread):
    def __init__(self, state):
        threading.Thread.__init__(self)
        self.state = state
        self.name = 'TransferThread-conn' + self.state.id + '-mode\'' + type(self).__name__ + "'"
    
    def run_as(self, r, s):
        try:
            data = r.recv(1024)
            while data:
                s.sendall(data)
                data = r.recv(1024)
        finally:
            _pd(3, 'Exiting', id=self.name)
            self.state.exit()


class _send(_transfer):
    def run(self):
        self.run_as(self.state.ibc, self.state.obc)

class _recv(_transfer):
    def run(self):
        self.run_as(self.state.obc, self.state.ibc)
