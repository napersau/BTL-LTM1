import os


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          TLS/SSL IMPLEMENTATION DEMO                         ║
║          Using Python Cryptography Library                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    while True:
        print("\n" + "="*60)
        print("DEMO OPTIONS:")
        print("="*60)
        print("1. Generate Certificates (CA & Server)")
        print("2. Start TLS Server")
        print("3. Run TLS Client (connect to server)")
        print("4. Demo Encryption Algorithms (AES-GCM, RSA)")
        print("5. Full Demo (All steps)")
        print("0. Exit")
        print("="*60)
        
        choice = input("\nSelect option: ").strip()
        
        if choice == "1":
            from cert_manager import CertificateManager
            ca = CertificateManager()
            print("\n🔧 Generating certificates...")
            private_key = ca.generate_private_key()
            cert = ca.create_self_signed_cert(private_key, "localhost")
            ca.save_private_key(private_key, "certs/server.key")
            ca.save_certificate(cert, "certs/server.crt")
            print("\n✓ Certificates generated successfully!")
        
        elif choice == "2":
            from tls_server import TLSServer
            if not os.path.exists("certs/server.crt") or not os.path.exists("certs/server.key"):
                print("\n❌ Certificates not found! Run option 1 first.")
                continue
            
            server = TLSServer()
            try:
                server.start()
            except Exception as e:
                print(f"❌ Server error: {e}")
        
        elif choice == "3":
            from tls_client import TLSClient
            if not os.path.exists("certs/server.crt"):
                print("\n❌ Certificate not found! Run option 1 first.")
                continue
            
            message = input("Enter message to send: ").strip() or "Hello TLS Server!"
            client = TLSClient()
            try:
                client.connect_and_send(message)
            except Exception as e:
                print(f"❌ Client error: {e}")
                print("💡 Make sure server is running (option 2)")
        
        elif choice == "4":
            from encryption_demo import EncryptionDemo
            demo = EncryptionDemo()
            demo.demo_aes_gcm()
            demo.demo_rsa_encryption()
        
        elif choice == "5":
            from cert_manager import CertificateManager
            from encryption_demo import EncryptionDemo
            
            print("\n🚀 Running full demo...")
            print("\n[STEP 1/3] Generating certificates...")
            ca = CertificateManager()
            private_key = ca.generate_private_key()
            cert = ca.create_self_signed_cert(private_key, "localhost")
            ca.save_private_key(private_key, "certs/server.key")
            ca.save_certificate(cert, "certs/server.crt")
            print("\n[STEP 2/3] Demonstrating encryption algorithms...")
            demo = EncryptionDemo()
            demo.demo_aes_gcm()
            demo.demo_rsa_encryption()
            print("\n[STEP 3/3] Server/Client Demo")
            print("To test TLS connection:")
            print("1. Run this program in terminal 1: Select option 2 (Start Server)")
            print("2. Run this program in terminal 2: Select option 3 (Run Client)")
        
        elif choice == "0":
            print("\n👋 Goodbye!")
            break
        
        else:
            print("\n❌ Invalid option!")


if __name__ == "__main__":
    main()