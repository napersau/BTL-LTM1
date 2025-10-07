"""
TLS Client Implementation
Kết nối đến TLS server và gửi dữ liệu mã hóa
"""
import socket
import ssl
import os

class TLSClient:
    """TLS Client với certificate verification"""
    
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.ca_cert = 'certs/server.crt'
        
    def connect_and_send(self, message):
        """Kết nối đến server và gửi message"""
        print(f"\nConnecting to {self.host}:{self.port}...")
        
        # Tạo SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Load CA certificate để verify server
        try:
            context.load_verify_locations(self.ca_cert)
            print(f"✓ Loaded CA certificate: {self.ca_cert}")
        except Exception as e:
            print(f"❌ Error loading CA certificate: {e}")
            return
        
        # Cấu hình verification cho self-signed certificate
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Chấp nhận self-signed cert
        
        print(f"✓ Certificate verification: DISABLED (for self-signed demo)")
        
        # Tạo kết nối
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                with context.wrap_socket(sock) as ssock:
                    ssock.connect((self.host, self.port))
                    
                    print(f"\n✅ TLS connection established!")
                    
                    # Hiển thị thông tin TLS
                    self.print_tls_info(ssock)
                    
                    # Gửi message
                    print(f"\n📤 Sending message: {message}")
                    ssock.send(message.encode('utf-8'))
                    print(f"✓ Message encrypted and sent")
                    
                    # Nhận phản hồi
                    response = ssock.recv(4096).decode('utf-8')
                    print(f"\n📩 Received response: {response}")
                    
            except ssl.SSLError as e:
                print(f"❌ SSL Error: {e}")
            except ConnectionRefusedError:
                print(f"❌ Connection refused. Make sure server is running!")
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def print_tls_info(self, ssock):
        """Hiển thị thông tin TLS connection"""
        print(f"\n🔐 TLS Connection Information:")
        print(f"{'─'*60}")
        
        # TLS version
        print(f"TLS Version: {ssock.version()}")
        
        # Cipher suite
        cipher = ssock.cipher()
        if cipher:
            print(f"Cipher Suite: {cipher[0]}")
            print(f"Protocol: {cipher[1]}")
            print(f"Encryption bits: {cipher[2]}")
        
        # Server certificate
        cert = ssock.getpeercert()
        if cert:
            print(f"\nServer Certificate:")
            subject = dict(x[0] for x in cert['subject'])
            print(f"Subject: {subject}")
            print(f"Issuer: {dict(x[0] for x in cert['issuer'])}")
            print(f"Valid from: {cert['notBefore']}")
            print(f"Valid until: {cert['notAfter']}")
            print(f"Serial number: {cert['serialNumber']}")
        else:
            print(f"\nNo certificate information available")
        
        print(f"{'─'*60}")


if __name__ == "__main__":
    client = TLSClient()
    client.connect_and_send("Hello from TLS Client!")