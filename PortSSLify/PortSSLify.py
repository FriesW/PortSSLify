import socket, ssl, threading, time, uuid, argparse, sys

class PortSSLify:
    
    def __init__(self,
                 certfile_path = 'cert.pem', keyfile_path = 'key.pem',
                 bind = ('127.0.0.1', 443), forward = ('127.0.0.1', 80),
                 max_active = 10, socket_queue = 2,
                 ssl_protocol = ssl.PROTOCOL_TLSv1_2,
                 debug_level = 0):
        self.__bind_addr = bind
        self.__forward_addr = forward
        self.__active = threading.Semaphore(max_active)
        self.__queue_size = socket_queue
        self.__debug_level = debug_level
        
        self.context = ssl.SSLContext(ssl_protocol)
        self.context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)
    
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
            with self.context.wrap_socket(sock, server_side=True) as sslsock:
                self.__pd(0, 'Server successfully started.')
                while True:
                    self.__active.acquire()
                    addr = "'connection failure'"
                    ibc = None
                    obc = None
                    try:
                        ibc, addr = sslsock.accept()
                        self.__pd(2, 'Connection from client', addr)
                        obc = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                        obc.connect(self.__forward_addr)
                        self.__pd(3, 'Success connecting to', self.__forward_addr)
                        self.__build(ibc, obc)
                        self.__pd(5, 'Success building bridge.')
                    except Exception as e:
                        self.__pd(1, 'Building bridge for client', addr, 'encountered error:', repr(e))
                        if ibc != None:
                            try: ibc.shutdown(socket.SHUT_RDWR)
                            except: pass
                            ibc.close()
                        if obc != None:
                            try: obc.shutdown(socket.SHUT_RDWR)
                            except: pass
                            obc.close()
                        self.__active.release()

    
    def __build(self, ibc, obc):
        pd = self.__pd
        
        class __connections:
            def __init__(self, inbound_conn, outbound_conn, call_on_completion = None):
                self.ibc = inbound_conn
                self.obc = outbound_conn
                self.id = "'"+str(uuid.uuid4())[:8]+"'"
                self.__ext_method = call_on_completion
                self.__exit_lock = threading.Lock()
                pd(2, 'Connection state object made for client', self.ibc.getpeername(), id=self.id)
            
            def exit(self):
                if not self.__exit_lock.acquire(False):
                    return
                pd(2, 'Closing connection', id=self.id)
                try: self.ibc.shutdown(socket.SHUT_RDWR)
                except: pd(4, 'error during \'ibc.shutdown(socket.SHUT_RDWR)\' in exit', id=self.id)
                try: self.obc.shutdown(socket.SHUT_RDWR)
                except: pd(4, 'error during \'obc.shutdown(socket.SHUT_RDWR)\' in exit', id=self.id)
                self.ibc.close()
                self.obc.close()
                if self.__ext_method != None:
                    self.__ext_method()


        class __transfer(threading.Thread):
            def __init__(self, state):
                threading.Thread.__init__(self)
                self._state = state
                self.name = 'TransferThread-conn' + self._state.id + '-mode\'' + type(self).__name__ + "'"
            
            def run_as(self, r, s):
                try:
                    data = r.recv(1024)
                    while data:
                        s.sendall(data)
                        data = r.recv(1024)
                except Exception as e:
                    pd(4, 'Encountered error:', repr(e), id=self.name)
                finally:
                    pd(3, 'Exiting', id=self.name)
                    self._state.exit()


        class __send(__transfer):
            def run(self):
                self.run_as(self._state.ibc, self._state.obc)

        class __recv(__transfer):
            def run(self):
                self.run_as(self._state.obc, self._state.ibc)
        
        
        conns = __connections(ibc, obc, self.__active.release)
        __send(conns).start()
        __recv(conns).start()



if __name__ == '__main__':
    
    proto_pref = ['PROTOCOL_TLS_SERVER', 'PROTOCOL_TLSv1_2', 'PROTOCOL_TLSv1_1', 'PROTOCOL_TLSv1']
    proto_list = []
    for i in dir(ssl):
        if i[:9] == 'PROTOCOL_':
            proto_list.append(i)
    proto_default = None
    for p in proto_pref:
        if p in proto_list:
            proto_default = p
            break
    
    p = argparse.ArgumentParser(description = 'PortSSLify: accepts an incoming SSL connection and sends out a plaintext connection. Wrap any socket with SSL!',
        epilog = 'Supported SSL/TLS protocols: ' + ', '.join(proto_list))
    p.add_argument('-cf', '--cert_file', dest='cert', type=str, default='cert.pem', metavar='PATH', help='File path to SSL certificate file (default: ./cert.pem)')
    p.add_argument('-kf', '--key_file', dest='key', type=str, default='key.pem', metavar='PATH', help='File path to SSL key file (default ./key.pem)')
    p.add_argument('-p', '--protocol', dest='proto', type=str, default=proto_default, metavar='PROTO', help='SSL/TLS protocol. See bottom for supported list.' +
        (' (default: ' + proto_default + ')' if proto_default else ''), required = proto_default == None  )
    p.add_argument('-bl', '--listen_addr', dest='bl', type=str, default='127.0.0.1', metavar='ADDR', help='Binding address on which to listen for incomming SSL connections (default: \'127.0.0.1\')')
    p.add_argument('-pl', '--listen_port', dest='pl', type=int, default=443, metavar='N', help='Binding port on which to listen for incomming SSL connections (default: 443)')
    p.add_argument('-bc', '--connect_addr', dest='bc', type=str, default='127.0.0.1', metavar='ADDR', help='Address for outgoing plain text connections (default: \'127.0.0.1\')')
    p.add_argument('-pc', '--connect_port', dest='pc', type=int, default=80, metavar='N', help='Port for outoing plain text connections (default: 80)')
    p.add_argument('-ac', '--active_conns', dest='ac', type=int, default=10, metavar='N', help='Max number of active connections (default: 10)')
    p.add_argument('-v', '--verbose', dest='debug', type=int, nargs='?', const=-1, default=1, metavar='N', help='Verbosity of stdout. Only flag is max verbosity, 0 is none, increasing int is increasing verbosity (default: 1)' )
    
    a = p.parse_args()
    
    if a.proto not in proto_list:
        sys.exit( p.format_usage() + ': error: the value for the following argument is invalid: -p/--protocol\nSupported values are: ' + ', '.join(proto_list) )
    if a.proto in ['PROTOCOL_SSLv3', 'PROTOCOL_SSLv2']:
        if 'Y' != input('WARNING: ' + a.proto + ' is insecure. Its use is highly discouraged.\nStill continue (Y/n)? '):
            sys.exit()
    proto = eval('ssl.'+a.proto)
    
    PortSSLify(
        certfile_path = a.cert,
        keyfile_path = a.key,
        bind = (a.bl, a.pl),
        forward = (a.bc, a.pc),
        max_active = a.ac,
        ssl_protocol = proto,
        debug_level = a.debug
    ).serve_forever()
    