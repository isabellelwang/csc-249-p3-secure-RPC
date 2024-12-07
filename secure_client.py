#!/usr/bin/env python3

import socket
import arguments
import argparse
import cryptgraphy_simulator

# Run 'python3 secure_client.py --help' to see what these lines do
parser = argparse.ArgumentParser('Send a message to a server at the given address and print the response')
parser.add_argument('--server_IP', help='IP address at which the server is hosted', **arguments.ip_addr_arg)
parser.add_argument('--server_port', help='Port number at which the server is hosted', **arguments.server_port_arg)
parser.add_argument('--VPN_IP', help='IP address at which the VPN is hosted', **arguments.ip_addr_arg)
parser.add_argument('--VPN_port', help='Port number at which the VPN is hosted', **arguments.vpn_port_arg)
parser.add_argument('--CA_IP', help='IP address at which the certificate authority is hosted', **arguments.ip_addr_arg)
parser.add_argument('--CA_port', help='Port number at which the certificate authority is hosted', **arguments.CA_port_arg)
parser.add_argument('--CA_public_key', default=None, type=arguments._public_key, help='Public key for the certificate authority as a tuple')
parser.add_argument('--message', default=['Hello, world'], nargs='+', help='The message to send to the server', metavar='MESSAGE')
args = parser.parse_args()

SERVER_IP = args.server_IP  # The server's IP address
SERVER_PORT = args.server_port  # The port used by the server
VPN_IP = args.VPN_IP  # The server's IP address
VPN_PORT = args.VPN_port  # The port used by the server
CA_IP = args.CA_IP # the IP address used by the certificate authority
CA_PORT = args.CA_port # the port used by the certificate authority
MSG = ' '.join(args.message) # The message to send to the server

if not args.CA_public_key:
    # If the certificate authority's public key isn't provided on the command line,
    # fetch it from the certificate authority directly
    # This is bad practice on the internet. Can you see why?
    print(f"Connecting to the certificate authority at IP {CA_IP} and port {CA_PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((CA_IP, CA_PORT))
        print("Connection established, requesting public key")
        s.sendall(bytes('key', 'utf-8'))
        CA_public_key = s.recv(1024).decode('utf-8')
        # close the connection with the certificate authority
        s.sendall(bytes('done', 'utf-8'))
    print(f"Received public key {CA_public_key} from the certificate authority for verifying certificates")
    CA_public_key = eval(CA_public_key)
else:
    CA_public_key = eval(args.CA_public_key)

# Add an application-layer header to the message that the VPN can use to forward it
def encode_message(message):
    message = str(SERVER_IP) + '~IP~' +str(SERVER_PORT) + '~port~' + message
    return message

def TLS_handshake_client(connection, server_ip=SERVER_IP, server_port=SERVER_PORT):
    ## Instructions ##
    # Fill this function in with the TLS handshake:
    #  * Request a TLS handshake from the server
    #  * Receive a signed certificate from the server
    #  * Verify the certificate with the certificate authority's public key
    #    * Use cryptography_simulator.verify_certificate()
    #  * Extract the server's public key, IP address, and port from the certificate
    #  * Verify that you're communicating with the port and IP specified in the certificate
    #  * Generate a symmetric key to send to the server
    #    * Use cryptography_simulator.generate_symmetric_key()
    #  * Use the server's public key to encrypt the symmetric key
    #    * Use cryptography_simulator.public_key_encrypt()
    #  * Send the encrypted symmetric key to the server
    #  * Return the symmetric key for use in further communications with the server
    # Make sure to use encode_message() on communications so the VPN knows which 
    # server to send them to

    # request a handshake from server 
    print("Requesting a TLS Handshake from server")
    handshake = encode_message(MSG)
    connection.sendall(bytes(handshake, 'utf-8'))

    # receive the signed certificate from server
    signed_certificate = connection.recv(1024).decode('utf-8') #receive signed certificate from the server 
    print(f"Receiving signed certificate {signed_certificate} from the server")

    # verify the signed certificate using CA public key 
    verified_certificate = cryptgraphy_simulator.verify_certificate(CA_public_key, signed_certificate)
    print(f"Verifying the signed certificate with the Certificate Authority's public key: {verified_certificate}")

    # extract and verify the server socket information 
    SERVER_IP = verified_certificate[:verified_certificate.index('~IP~')]
    SERVER_PORT = verified_certificate[verified_certificate.index('~IP~')+4:verified_certificate.index('~PORT~')]
    server_public_key = verified_certificate[verified_certificate.index('~PORT~')+6:]
    print(f"Extracting and verifying server socket information: IP - {SERVER_IP}, Port: {SERVER_PORT}, public key: {server_public_key}")

    try: 
        if server_ip == SERVER_IP and str(server_port) == SERVER_PORT: 

            # generate a symmetric key for the server 
            symmetric_key = cryptgraphy_simulator.generate_symmetric_key()
            print(f"Generating symmetric key for server: {symmetric_key}")

            # encrypt the symmetric key using server's public key
            encrypted_symmetric_key = cryptgraphy_simulator.public_key_encrypt(server_public_key, symmetric_key)
            print(f"encrypted symmetric key using server public key {server_public_key}: {encrypted_symmetric_key}")

            # send encrypted symmetric key to the server 
            sending_key = encrypted_symmetric_key
            print(f"Sending encrypted symmetric key {sending_key} to the server") #send to the server
            connection.sendall(bytes(sending_key, 'utf-8'))
        
        return symmetric_key
        
    except Exception as e: 
        print(f"Exception Occured {e}")
        return 
    
    
print("Client starting - connecting to VPN at IP", VPN_IP, "and port", VPN_PORT)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((VPN_IP, VPN_PORT))
    symmetric_key = TLS_handshake_client(s)
    print(f"TLS handshake complete: sent symmetric key '{symmetric_key}', waiting for acknowledgement")
    data = s.recv(1024).decode('utf-8')
    print(f"Received acknowledgement '{cryptgraphy_simulator.symmetric_decrypt(symmetric_key, data)}', preparing to send message")
    MSG = cryptgraphy_simulator.tls_encode(symmetric_key,MSG)
    print(f"Sending message '{MSG}' to the server")
    s.sendall(bytes(MSG, 'utf-8'))
    print("Message sent, waiting for reply")
    data = s.recv(1024)

print(f"Received raw response: '{data}' [{len(data)} bytes]")
print(f"Decoded message '{cryptgraphy_simulator.tls_decode(symmetric_key, data.decode('utf-8'))}' from server")
print("client is done!")
