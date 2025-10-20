import os
from ui_manager import ui


def main():
    # Show enhanced banner
    ui.show_banner()
    
    while True:
        # Show enhanced main menu
        ui.show_main_menu()
        
        choice = ui.get_user_input("\nSelect option: ").strip()
        
        if choice == "1":
            ui.show_section_header("Certificate Generation", "Generating TLS certificates for secure communication")
            
            from cert_manager import CertificateManager
            ca = CertificateManager()
            
            try:
                tasks = ["Generating RSA private key", "Creating self-signed certificate", "Saving certificate files"]
                ui.show_progress(tasks, "Certificate Generation")
                
                private_key = ca.generate_private_key()
                cert = ca.create_self_signed_cert(private_key, "localhost")
                ca.save_private_key(private_key, "certs/server.key")
                ca.save_certificate(cert, "certs/server.crt")
                
                ui.show_success(
                    "Certificates generated successfully!",
                    "Files saved: certs/server.crt, certs/server.key"
                )
            except Exception as e:
                ui.show_error(f"Certificate generation failed: {e}")
        
        elif choice == "2":
            ui.show_section_header("TLS Server", "Starting secure TLS server on localhost:8443")
            
            if not os.path.exists("certs/server.crt") or not os.path.exists("certs/server.key"):
                ui.show_error("Certificates not found!", "Run option 1 to generate certificates first")
                continue
            
            from tls_server import TLSServer
            server = TLSServer()
            try:
                ui.show_status("Starting TLS server...", "info")
                server.start()
            except Exception as e:
                ui.show_error(f"Server error: {e}")
        
        elif choice == "3":
            ui.show_section_header("TLS Client", "Connecting to TLS server and sending encrypted message")
            
            if not os.path.exists("certs/server.crt"):
                ui.show_error("Certificate not found!", "Run option 1 to generate certificates first")
                continue
            
            message = ui.get_user_input("Enter message to send (or press Enter for default): ").strip()
            if not message:
                message = "Hello TLS Server!"
            
            from tls_client import TLSClient
            client = TLSClient()
            try:
                ui.show_status("Connecting to TLS server...", "info")
                client.connect_and_send(message)
            except Exception as e:
                ui.show_error(f"Client error: {e}", "Make sure server is running (option 2)")
        
        elif choice == "4":
            from encryption_demo import EncryptionDemo
            demo = EncryptionDemo()
            demo.demo_aes_gcm()
            demo.demo_rsa_encryption()
        
        elif choice == "0":
            print("\n👋 Goodbye! Thank you for exploring TLS/SSL security!")
            break
        
        else:
            print("\n❌ Invalid option! Please select 0-4.")


if __name__ == "__main__":
    main()