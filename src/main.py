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
        
        elif choice == "5":
            print("\n🔐 Manual TLS Handshake Simulation")
            from manual_tls_handshake import TLSHandshakeSimulator
            simulator = TLSHandshakeSimulator()
            simulator.demo_tls_handshake()
        
        elif choice == "6":
            print("\n📜 Advanced Certificate Validation")
            if not os.path.exists("certs/server.crt"):
                print("\n❌ Certificate not found! Run option 1 first.")
                continue
            from certificate_validator import AdvancedCertificateValidator
            validator = AdvancedCertificateValidator()
            validator.comprehensive_validation("certs/server.crt", "localhost")
        
        elif choice == "7":
            print("\n📊 TLS Protocol & Cipher Suite Analysis")
            from tls_protocol_analyzer import TLSProtocolAnalyzer
            analyzer = TLSProtocolAnalyzer()
            analyzer.comprehensive_tls_analysis()
        
        elif choice == "8":
            print("\n🛡️ Comprehensive Security Analysis")
            from tls_security_analyzer import TLSSecurityAnalyzer
            security_analyzer = TLSSecurityAnalyzer()
            print("Note: Start TLS server (option 2) first for live analysis")
            try:
                security_analyzer.comprehensive_security_analysis('localhost', 8443)
            except Exception as e:
                print(f"Analysis requires running TLS server: {e}")
        
        elif choice == "9":
            print("\n🔬 Advanced Encryption Demonstrations")
            from advanced_crypto_demo import AdvancedCryptographyDemo
            crypto_demo = AdvancedCryptographyDemo()
            crypto_demo.comprehensive_crypto_demo()
        
        elif choice == "10":
            print("\n🚀 Full Security Audit - Running all advanced features...")
            
            # Generate certificates if needed
            if not os.path.exists("certs/server.crt"):
                print("\n[STEP 1/6] Generating certificates...")
                from cert_manager import CertificateManager
                ca = CertificateManager()
                private_key = ca.generate_private_key()
                cert = ca.create_self_signed_cert(private_key, "localhost")
                ca.save_private_key(private_key, "certs/server.key")
                ca.save_certificate(cert, "certs/server.crt")
            
            print("\n[STEP 2/6] TLS Handshake Analysis...")
            from manual_tls_handshake import TLSHandshakeSimulator
            simulator = TLSHandshakeSimulator()
            simulator.demo_tls_handshake()
            
            print("\n[STEP 3/6] Certificate Validation...")
            from certificate_validator import AdvancedCertificateValidator
            validator = AdvancedCertificateValidator()
            validator.comprehensive_validation("certs/server.crt", "localhost")
            
            print("\n[STEP 4/6] Protocol Analysis...")
            from tls_protocol_analyzer import TLSProtocolAnalyzer
            analyzer = TLSProtocolAnalyzer()
            analyzer.comprehensive_tls_analysis()
            
            print("\n[STEP 5/6] Advanced Cryptography...")
            try:
                from advanced_crypto_demo import AdvancedCryptographyDemo
                crypto_demo = AdvancedCryptographyDemo()
                crypto_demo.comprehensive_crypto_demo()
            except ImportError:
                print("Advanced crypto demo not available")
            
            print("\n[STEP 6/6] Complete!")
            print("🏆 Full security audit completed successfully!")
        
        elif choice == "11":
            print("\n🎓 Educational Demo - Step by step learning...")
            print("\nThis demo will walk you through TLS/SSL concepts:")
            print("1. Basic cryptographic concepts")
            print("2. Certificate management") 
            print("3. TLS handshake process")
            print("4. Security analysis")
            print("\nPress Enter to continue through each section...")
            
            input("\nReady to start? Press Enter...")
            
            from manual_tls_handshake import TLSHandshakeSimulator
            simulator = TLSHandshakeSimulator()
            simulator.demo_tls_handshake()
            
            input("\nPress Enter to continue to certificate analysis...")
            if os.path.exists("certs/server.crt"):
                from certificate_validator import AdvancedCertificateValidator
                validator = AdvancedCertificateValidator()
                validator.comprehensive_validation("certs/server.crt", "localhost")
        
        elif choice == "0":
            print("\n👋 Goodbye! Thank you for exploring TLS/SSL security!")
            break
        
        else:
            print("\n❌ Invalid option! Please select 0-11.")


if __name__ == "__main__":
    main()