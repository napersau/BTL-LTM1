"""
TLS Server Implementation
Sử dụng socket và ssl để tạo secure server
"""
import socket
import ssl
import os

class TLSServer:
    """TLS Server với certificate verification"""
    
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.certfile = 'certs/server.crt'
        self.keyfile = 'certs/server.key'
        
    def start(self):
        """Khởi động TLS server"""
        print(f"\n🔒 Starting TLS Server on {self.host}:{self.port}...")
        
        # Tạo SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Load certificate và private key
        try:
            context.load_cert_chain(self.certfile, self.keyfile)
            print(f"✓ Loaded certificate: {self.certfile}")
            print(f"✓ Loaded private key: {self.keyfile}")
        except Exception as e:
            print(f"❌ Error loading certificates: {e}")
            return
        
        # Cấu hình SSL parameters
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        print(f"✓ TLS version: {context.minimum_version}")
        print(f"✓ Cipher suites configured")
        
        # Tạo socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(5)
            
            print(f"\n✅ Server listening on {self.host}:{self.port}")
            print("Waiting for client connection...\n")
            
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    try:
                        conn, addr = ssock.accept()
                        print(f"\n{'='*60}")
                        print(f"🔗 New connection from {addr}")
                        print(f"{'='*60}")
                        
                        self.handle_client(conn)
                        
                    except KeyboardInterrupt:
                        print("\n\n⚠️  Server shutting down...")
                        break
                    except Exception as e:
                        print(f"❌ Error: {e}")
    
    def handle_client(self, conn):
        """Xử lý kết nối từ client"""
        try:
            # Hiển thị thông tin TLS
            self.print_tls_info(conn)
            
            # Nhận dữ liệu
            data = conn.recv(4096)
            if data:
                message = data.decode('utf-8')
                print(f"\n📩 Received encrypted message")
                print(f"📝 Decrypted content: {message}")
                
                # Gửi phản hồi
                response = f"Server received: {message}"
                conn.send(response.encode('utf-8'))
                print(f"📤 Sent response: {response}")
            
        except Exception as e:
            print(f"❌ Error handling client: {e}")
        finally:
            conn.close()
            print(f"\n🔌 Connection closed")
    
    def print_tls_info(self, conn):
        """Hiển thị thông tin TLS connection"""
        print(f"\n🔐 TLS Connection Information:")
        print(f"{'─'*60}")
        
        # TLS version
        print(f"TLS Version: {conn.version()}")
        
        # Cipher suite
        cipher = conn.cipher()
        if cipher:
            print(f"Cipher Suite: {cipher[0]}")
            print(f"Protocol: {cipher[1]}")
            print(f"Encryption bits: {cipher[2]}")
        
        # Certificate info
        cert = conn.getpeercert()
        if cert:
            print(f"\nClient Certificate:")
            print(f"Subject: {dict(x[0] for x in cert['subject'])}")
        else:
            print(f"\nNo client certificate presented")
        
        print(f"{'─'*60}")


if __name__ == "__main__":
    server = TLSServer()
    server.start()