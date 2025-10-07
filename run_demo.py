import os
import subprocess
import time

def run_tls_server():
    print("Starting TLS Server...")
    server_process = subprocess.Popen(['python', 'src/tls_server.py'])
    time.sleep(2)  # Give the server time to start
    return server_process

def run_tls_client():
    print("Running TLS Client...")
    subprocess.run(['python', 'src/tls_client.py'])

def main():
    # Ensure certificates are generated
    if not os.path.exists('certs/server.crt') or not os.path.exists('certs/server.key'):
        print("Certificates not found! Generating certificates...")
        subprocess.run(['python', 'src/cert_manager.py'])

    # Start the TLS server
    server_process = run_tls_server()

    try:
        # Run the TLS client
        run_tls_client()
    finally:
        # Terminate the server after the client has finished
        print("Shutting down TLS Server...")
        server_process.terminate()
        server_process.wait()

if __name__ == "__main__":
    main()