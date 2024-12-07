###  Overview of Application 

The program simulates the process how data is sent in a secure manner through encryption and decryption using keys and VPN through a TlS Handshake. There are four components: The certificate authority, the client, the VPN, and the server. 
The certificate authority provides the public key for the client to be used for verification on the server. It also signs the certificate sent by the server to ensure that it is the server that is communicating with the client. The VPN acts as a secure middleground between the client and server and adds a layer of security and privacy for the client and server when data is being sent. Symmetric keys are generated, which is a nonce, and is sent to the server from the client. The server sends back an acknowledgement of the nonce. Then the message is sent to the server, which is decoded and processed by the server. 


### Format of an unsigned certificate
This is the general format.
unsigned_certificate = str(SERVER_IP) + '~IP~' + str(SERVER_PORT) + '~PORT~' + str(public_key)

In my program, the format is 
127.0.0.1~IP~65432~port~Hello, world -> "SERVERIP"+ + ~IP~ + "PORTNUMBER" + ~port~ + "MSG"

ServerIP = 127.0.0.1
Port = 65432
MSG = Hello, world


### Example output 

Note: The message underwent processing by the server
# Certificate Authority 
python3 certificate_authority.py
Certificate Authority started using public key '(22081, 56533)' and private key '34452'
Certificate authority starting - listening for connections at IP 127.0.0.1 and port 55553
Connected established with ('127.0.0.1', 50000)
Received client message: 'b'$127.0.0.1~IP~65432~PORT~(36207, 56533)'' [39 bytes]
Signing '127.0.0.1~IP~65432~PORT~(36207, 56533)' and returning it to the client.
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 50000) has closed the remote connection - listening 
Connected established with ('127.0.0.1', 50005)
Received client message: 'b'key'' [3 bytes]
Sending the certificate authority's public key (22081, 56533) to the client
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 50005) has closed the remote connection - listening 
^CCertificate authority is done!

Note: The message underwent processing by the server
# VPN
python3 VPN.py
VPN starting - listening for connections at IP 127.0.0.1 and port 55554
Connected established with ('127.0.0.1', 50006)
Received client message: 'b'127.0.0.1~IP~65432~port~Hello, world'' [36 bytes]
connecting to server at IP 127.0.0.1 and port 65432
server connection established, sending message 'Hello, world'
message sent to server, waiting for reply
Received server response: 'b'D_(34452, 56533)[127.0.0.1~IP~65432~PORT~(36207, 56533)]'' [56 bytes], forwarding to client
Received client message: 'b'E_(36207, 56533)[10908]'' [23 bytes], forwarding to server
Received server response: 'b"symmetric_10908[Symmetric key '10908' received]"' [47 bytes], forwarding to client
Received client message: 'b'HMAC_47085[symmetric_10908[Hello, world]]'' [41 bytes], forwarding to server
Received server response: 'b'HMAC_36529[symmetric_10908[Hello, world has 12 characters.]]'' [60 bytes], forwarding to client
VPN is done!

Note: The message underwent processing by the server
# Server
python3 secure_server.py
Generated public key '(36207, 56533)' and private key '20326'
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Prepared the formatted unsigned certificate '127.0.0.1~IP~65432~PORT~(36207, 56533)'
Connection established, sending certificate '127.0.0.1~IP~65432~PORT~(36207, 56533)' to the certificate authority to be signed
Received signed certificate 'D_(34452, 56533)[127.0.0.1~IP~65432~PORT~(36207, 56533)]' from the certificate authority
server starting - listening for connections at IP 127.0.0.1 and port 65432
Connected established with ('127.0.0.1', 50007)
Received acknowledge: Hello, world
Sending signed certificate D_(34452, 56533)[127.0.0.1~IP~65432~PORT~(36207, 56533)] to client
Receiving symmetric key from client
Decrypting symmetric key E_(36207, 56533)[10908] using private key 20326
TLS handshake complete: established symmetric key '10908', acknowledging to client
Received client message: 'b'HMAC_47085[symmetric_10908[Hello, world]]'' [41 bytes]
Decoded message 'Hello, world' from client
Responding 'Hello, world has 12 characters.' to the client
Sending encoded response 'HMAC_36529[symmetric_10908[Hello, world has 12 characters.]]' back to the client
server is done!

Note: The message underwent processing by the server
# Client 
python3 secure_client.py
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Connection established, requesting public key
Received public key (22081, 56533) from the certificate authority for verifying certificates
Client starting - connecting to VPN at IP 127.0.0.1 and port 55554
Requesting a TLS Handshake from server
Receiving signed certificate D_(34452, 56533)[127.0.0.1~IP~65432~PORT~(36207, 56533)] from the server
Verifying the signed certificate with the Certificate Authority's public key: 127.0.0.1~IP~65432~PORT~(36207, 56533)
Extracting and verifying server socket information: IP - 127.0.0.1, Port: 65432, public key: (36207, 56533)
Generating symmetric key for server: 10908
encrypted symmetric key using server public key (36207, 56533): E_(36207, 56533)[10908]
Sending encrypted symmetric key E_(36207, 56533)[10908] to the server
TLS handshake complete: sent symmetric key '10908', waiting for acknowledgement
Received acknowledgement 'Symmetric key '10908' received', preparing to send message
Sending message 'HMAC_47085[symmetric_10908[Hello, world]]' to the server
Message sent, waiting for reply
Received raw response: 'b'HMAC_36529[symmetric_10908[Hello, world has 12 characters.]]'' [60 bytes]
Decoded message 'Hello, world has 12 characters.' from server
client is done!

### Walkthrough of TLS Handshake 

First, the client requests a public key from the certificate authority, which the certificate authority sends back its Certificate Authority Public Key to be used for verification later by the client. 

The client sends the serverIP + serverPort + message to the VPN, which the VPN extracts the message and forwards the message to the server. 

The server then sends an unsigned certificate, which contains server's socket information and public key, to the certificate authority for the certificate authority to sign. The server forwards the signed certificate to the VPN and then to the client. The client receives the signed certificate and verifies the certificate with the certificate authority using the certificate authority public key. This is to ensure that the server the client is communicating with is not an imposter server. 

After verifying, the unsigned certificate is sent back to the client, who extracts the server's socket information and the server's public key and verifies again that it is the correct server IP and port. If it is correct, then it generates a symmetric key, which is a nonce, or a random number. The symmetric key is encrypted using the server's public key, and then sent to the VPN and the server. 

The server decrypts the encrypted symmetric key using its private key, and then sends the symmetric key back to the client as acknowledgement. 

Then, the client will begin to send its message with an HMAC to the server, which decrypts it and processes the message. 

### Description of how simulation is weak 

The simulation is weak due to its asymmetric key generation process and using the built-in python function, eval(). 

In the cryptography simulator, the asymmetric key is generated between 0 and 56533, which is not a very secure key. Since larger keys are more secure, asymmetric key in the simulation would be easy to intercept. In addition, the generation of the private key is very simple. It is a subtraction equation by subtracting the first index of the public key from 56533. Private keys should not be easy to guess/crack, because it should not be known to anyone. 

The eval() function is also weak, because it is not secure. Because eval() is a built-in function by python, it could be easily breached. And especially inputting the symmetric key to be evaluated, it is valuable information that when breached, could break the security of the system.  

### Acknowledgements 
Thank you to Emily, Quinn, and Chris for answering my questions. 

### Client->Server and Server->Client application layer message format

# Client to server Message format: 
The message format is HMAC_47085[symmetric_10908[Hello, world]]

HMAC_(HMAC_key)[symmetric_{sym_key} [message]]

HMAC_key = 47085
sym_key = 10908 
message = Hello, world 

# Server to client Message format: 
HMAC_36529[symmetric_10908[Hello, world has 12 characters.]]

HMAC_{hmac_key}[symmetric_{sym_key}[processed_message]]
hmac_key = 26529
sym_key = 10908
processed_message = Hello, world has 12 characters.



