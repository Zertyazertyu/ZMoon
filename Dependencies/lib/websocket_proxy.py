import socket
import ssl
import threading
import base64
import hashlib
import struct
import os
import queue
import sys
import datetime
import traceback

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes



def clean_error():
    error_traceback = traceback.format_exc().splitlines()
    last_call_index = None

    for index, line in enumerate(reversed(error_traceback)):
        if "File " in line:
            last_call_index = len(error_traceback) - index - 1
            break

    if last_call_index is not None:
        last_call = error_traceback[last_call_index:]
        print('\n'.join(last_call))


def generate_domain_certificate(domain_name):
    path = os.path.dirname(os.path.dirname(__file__))+'\\certfiles\\'


    if os.path.exists(f"{path+domain_name}_cert.pem") and os.path.exists(f"{path+domain_name}_key.pem"):return f"{path+domain_name}_cert.pem",f"{path+domain_name}_key.pem"

    ca_key_path = path+'ca_key.pem'
    ca_cert_path = path+'ca_cert.pem'
    
    with open(ca_key_path, "rb") as ca_key_file:
        ca_key = ca_key_file.read()
    
    with open(ca_cert_path, "rb") as ca_cert_file:
        ca_cert = ca_cert_file.read()

    ca_private_key = serialization.load_pem_private_key(
        ca_key, password=None
    )
    ca_certificate = x509.load_pem_x509_certificate(ca_cert)
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, domain_name)
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_certificate.issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(domain_name)
        ]),
        critical=False
    ).sign(ca_private_key, hashes.SHA256())
    


    with open(f"{path+domain_name}_key.pem", "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(f"{path+domain_name}_cert.pem", "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))


    return f"{path+domain_name}_cert.pem",f"{path+domain_name}_key.pem"



def handle_client(conn):
    request = conn.recv(4096)
    first_line = request.split(b'\r\n')[0]
    method, url, _ = first_line.split(b' ')
    if method == b'CONNECT':
        return handle_https(conn, url)

def handle_https(conn, url):
    encoded=False
    remote_host, remote_port = url.decode().split(':')
    remote_port = int(remote_port)
    conn.send(b'HTTP/1.1 200 OK\r\n\r\n')
    cert_path,key_path = generate_domain_certificate(remote_host)
    client_sock = ssl.wrap_socket(conn,server_side=True, certfile=cert_path, keyfile=key_path)
    client_sock.settimeout(0.1)
    return handle_request(client_sock, remote_host, remote_port)


def handle_request(client_sock, remote_host, remote_port):
    try: request = client_sock.recv(4096)
    except:
        client_sock.close()
        return None
    headers = {}
    request_parts = request.split(b'\r\n\r\n')
    if len(request_parts) > 1:
        header_lines = request_parts[0].decode().split('\r\n')[1:]
        for line in header_lines:
            name, value = line.split(': ')
            headers[name] = value
            if name == 'Sec-WebSocket-Extensions':encoded =True
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock = ssl_context.wrap_socket(s, server_hostname=remote_host)
    server_sock.connect((remote_host, remote_port))
    if 'Upgrade' in headers and headers['Upgrade'] == 'websocket':
        path = request_parts[0].split(b' ')[1]
        if encoded:
            filtered_headers = [f"{name}: {value}" for name, value in headers.items() if name != 'Sec-WebSocket-Extensions']
            filtered_request = b'\r\n'.join([b'GET '+path+b' HTTP/1.1'] + [header.encode() for header in filtered_headers] + [b'', b''])
            server_sock.send(filtered_request)
        else:
            server_sock.send(request)
        server_sock.settimeout(1.0)
        response = b''
        try:
            while 1:
                tmp = server_sock.read()
                response+=tmp
                if tmp == b'': break
        except:pass
        server_sock.settimeout(None)
        client_sock.settimeout(None)
        return *handle_websockets(server_sock,client_sock, headers['Sec-WebSocket-Key']),remote_host,encoded
    else:
        server_sock.settimeout(0.5)
        server_sock.send(request)
        response = b''
        while True:
            try: tmp = server_sock.recv(4096)
            except: break
            response+=tmp
            if not tmp:break
        client_sock.sendall(response)
        server_sock.close()
        a = handle_request(client_sock, remote_host, remote_port)
        return a


def handle_websockets(server,client, key):
    accept_key = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
    headers = [
        b'HTTP/1.1 101 Switching Protocols',
        b'Upgrade: websocket',
        b'Connection: Upgrade',
        b'Sec-WebSocket-Accept: ' + accept_key,
        b'\r\n'
    ]
    response = b'\r\n'.join(headers)
    client.send(response)
    return server,client


def encode_websocket_data(data: bytes, encode: int = 128) -> bytes:
    data_length:int = len(data)
    header = bytearray([0x82 | encode])

    if data_length <= 125:
        header.append(data_length | encode)
    elif data_length <= 65535:
        header.extend([0x7E | encode, (data_length >> 8) & 0xFF, data_length & 0xFF])
    else:
        header.extend(
                    [0x7F | encode, (data_length >> 56) & 0xFF, (data_length >> 48) & 0xFF,
                    (data_length >> 40) & 0xFF,(data_length >> 32) & 0xFF, (data_length >> 24) & 0xFF,
                    (data_length >> 16) & 0xFF,(data_length >> 8) & 0xFF, data_length & 0xFF])
    if encode:
        #masked_data = numpy.bitwise_xor(numpy.frombuffer(data, dtype=numpy.uint8), 0xCC)
        #header.extend([0xCC, 0xCC, 0xCC, 0xCC])
        #header.extend(masked_data.tobytes())
        masked_data = bytearray(len(data))
        for i in range(len(data)):masked_data[i] = data[i] ^ 0xCC
        header.extend([0xCC, 0xCC, 0xCC, 0xCC])
        header.extend(masked_data)
    else:
        header.extend(data)
    return bytes(header)

def split_packets(data:bytes) -> list:
    buffer:list = []
    pointer:int = 0
    unpack_length_32 = struct.Struct('!I')
    while pointer<len(data):
        size:int = unpack_length_32.unpack_from(data,pointer)[0]
        buffer.append(data[pointer:pointer+size+4])
        pointer+=size+4
    return buffer



class Session:
    def __init__(self,server,client,host,compressed=False):
        self.host=host
        self.alive=True
        self.compressed = compressed
        self.server = server
        self.client = client
        self.flow = queue.Queue()
        self.client_queue = queue.Queue()
        self.server_queue = queue.Queue()
        self.threads = (
            threading.Thread(target=self.listen_packets, args=(self.server,False)),
            threading.Thread(target=self.listen_packets, args=(self.client,True)),
            threading.Thread(target=self.proceed_out,args=(True,)),
            threading.Thread(target=self.proceed_out,args=(False,)),
            )



    def proceed_flow(self,on_message,callback):
        self.callback = callback
        while self.alive:
            p = self.flow.get()
            try:on_message(p)
            except Exception:
                if self.alive:clean_error()
            if not p.killed:
                if p.from_client:self.server_queue.put(encode_websocket_data(p.content,128))
                else:
                    self.client_queue.put(encode_websocket_data(p.content,0))

    def proceed_out(self,to_client):
        if to_client:
            q=self.client_queue
            target=self.client
        else:
            q=self.server_queue
            target=self.server
        while self.alive:
            target.sendall(q.get(block=True))



    def listen_packets(self, source, from_client):
        message_buffer = bytearray()
        unpack_header = struct.Struct('!BB')
        unpack_length_16 = struct.Struct('!H')
        unpack_length_64 = struct.Struct('!Q')
        decompress = self.compressed and not from_client
        while self.alive:
            header=None
            header = source.read(2)
            if not header:continue
            try:opcode_and_length = unpack_header.unpack(header)
            except:opcode_and_length = unpack_header.unpack(header+source.read(1))
            opcode = opcode_and_length[0] & 0x0F
            final = opcode_and_length[0] & 0x80
            length = opcode_and_length[1] & 0x7F
            if length == 126:
                length = unpack_length_16.unpack(source.read(2))[0]
            elif length == 127:
                length = unpack_length_64.unpack(source.read(8))[0]
            masked = opcode_and_length[1] & 0x80
            if masked: mask = source.read(4)
            data = b''
            while len(data) < length:
                remaining = length - len(data)
                chunk = source.read(remaining)
                if not chunk:break
                data+=chunk
            if opcode>2:
                build = header + (mask if masked else b'') + (unpack_length_16.pack(length) if (opcode_and_length[1] & 0x7F) == 126 else (unpack_length_64.pack(length) if (opcode_and_length[1] & 0x7F) == 127 else b''))+data
                self.server_queue.put(build) if from_client else self.client_queue.put(build)
                #print(build, 'from_client' if from_client else 'from_server')
                if opcode==8:break
                else:continue
            if masked:
                #mask_array = numpy.frombuffer(mask * (len(data) // 4 + 1), dtype=numpy.uint8)[:len(data)]
                #unmasked_data = numpy.bitwise_xor(numpy.frombuffer(data, dtype=numpy.uint8), mask_array)
                #data = unmasked_data.tobytes()
                unmasked_data = bytearray(len(data))
                for i in range(len(data)):unmasked_data[i] = data[i] ^ mask[i % 4]
                data = bytes(unmasked_data)
            message_buffer += data

            if final and message_buffer:
                if decompress:
                    for depacked in split_packets(message_buffer):#for depacked in split_packets(zlib.decompress(message_buffer, -zlib.MAX_WBITS)):
                        self.flow.put(message(from_client,depacked))
                else:self.flow.put(message(from_client, message_buffer))
                message_buffer = b''
        if self.alive:
            #print("MESSAGE A LORIGINE DU CUT: ",header,'from_client' if from_client else 'from_server', build)
            self.callback()
            self.flow.put(message(False,b''))
            if from_client:self.server_queue.put(b'\x00\x00')
            else:self.client_queue.put(b'\x00\x00')

    def send_to_server(self,data):
        self.server.send(encode_websocket_data(data,128))
    def send_to_client(self, data):
        self.client.send(encode_websocket_data(data,0))


class message:
    def __init__(self,from_client,content):
        self.from_client = from_client
        self.killed = False
        self.content = content
    def kill(self):
        self.killed = True


def getSession(port):
    
    bind_address = ('localhost', port)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(bind_address)
    server_sock.listen()
    conn, addr = server_sock.accept()
    on_connect = handle_client(conn)
    if on_connect: return Session(*on_connect)


    

