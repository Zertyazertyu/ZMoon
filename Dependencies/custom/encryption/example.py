
class Cipher:
    def __init__(self, *args): 
        ...

    def decrypt_client(self, buffer: bytes) -> bytes: return buffer
    def encrypt_client(self, buffer: bytes) -> bytes: return buffer

    def decrypt_server(self, buffer: bytes) -> bytes: return buffer
    def encrypt_server(self, buffer: bytes) -> bytes: return buffer