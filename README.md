<<<<<<< HEAD
# Python TLS/SSL Implementation Demo

This project demonstrates a simple implementation of TLS/SSL using Python. It includes a certificate manager, a TLS server, a TLS client, and encryption demonstrations. The project is designed for educational purposes to showcase how TLS works and how to implement it in Python.

## Project Structure

```
python-tls-demo
├── src
│   ├── cert_manager.py        # Manages TLS certificates
│   ├── tls_client.py          # Implements the TLS client
│   ├── tls_server.py          # Implements the TLS server
│   ├── encryption_demo.py      # Demonstrates encryption algorithms
│   └── main.py                # Entry point for the application
├── certs
│   ├── .gitignore             # Files to ignore in the certs directory
│   └── README.md              # Documentation for certificate usage
├── requirements.txt           # Python dependencies
├── README.md                  # Overall project documentation
└── run_demo.py                # Script to run the demo
```

## Features

- **Certificate Management**: Generate and manage self-signed TLS certificates.
- **TLS Server**: Set up a secure server that can accept TLS connections.
- **TLS Client**: Connect to the TLS server and send/receive messages securely.
- **Encryption Demonstration**: Showcase encryption algorithms like AES-GCM and RSA.
- **User-Friendly Menu**: Interactive menu for users to navigate through functionalities.

## Setup Instructions

1. **Clone the Repository**:
   ```
   git clone <repository-url>
   cd python-tls-demo
   ```

2. **Install Dependencies**:
   Ensure you have Python installed, then run:
   ```
   pip install -r requirements.txt
   ```

3. **Generate Certificates**:
   Run the application and select the option to generate certificates.

4. **Run the Demo**:
   Execute the demo script:
   ```
   python run_demo.py
   ```

## Usage

- Start the server by selecting the appropriate option in the menu.
- Connect to the server using the client and send messages.
- Explore the encryption demo to see how different algorithms work.

## License

This project is for educational purposes only. Feel free to modify and use it as needed.
=======
🟡 T30: Network Security Protocols - TLS/SSL Implementation <br/>
Tech Focus: Handshake process, encryption, certificate validation <br/>
Demo: Custom HTTPS client/server với TLS implementation <br/>
Innovation: Understanding secure communication <br/>
Languages: C/C++, Java, Python (cryptography) <br/>
Difficulty: Challenging - Complex security protocol <br/>
>>>>>>> 4a6ec88b7dcbfaa0effdb1a11d15ad118f7587e1
