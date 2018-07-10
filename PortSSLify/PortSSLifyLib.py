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
                 ssl_protocol = ssl.PROTOCOL_TLSv1_2
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
    
    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(self.bind_addr)
            sock.listen(self.queue_size)        
            with self.context.wrap_socket(sock, server_side=True) as sslsock:
                while True:
                    self.active.acquire()
                    conn, addr = sslsock.accept()
                    _pd(1, 'Connection from', addr)
                    threading.Thread(target = self.__handler, args = (conn,)).start()
    
    def __handler(self, conn):
        try:
            conn.send(b'hello world!')
        finally:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            self.active.release()
