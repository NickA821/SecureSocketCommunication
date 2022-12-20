from genericpath import exists
from Crypto.Hash import SHA256
import socket
from Crypto.Random import get_random_bytes
import ipaddress
from base64 import b64encode
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
##
# Authors: Nick Buchanan and Josh Vancleave 
# Version: Fall 2022
# 
# Description: A menu-driven software that will facilitate communication
# between a host and a guest. The port we will be using is 65432 in order
# for the host and guest to communicate properly. The host or guest will
# attempt to send message while the other attempts to receive it. 
##

PORT = 65432 #The port used by the server
VM_IP = "152.30.110.89" #The ip address of the virtual machine
MESSAGE_CHARS_MAX = 4096 #the maximum chars that a message can contain
RECEIVE_CHARS = 1024 #the amount of characters to receive

# main function 'set'. sets are comprised of functions that are highly related to each other
def main():
    '''Run the program by asking the user to enter an option and then by acting
    on that option with the do_option command.'''
    option = ''
    ip_address = get_ip()
    while option != "0":
        menu()
        option = input("Enter Option> ")
        do_option(option, ip_address)

def menu():
    '''This models the menu that the host and guest will be using
       throughout the duration of their communication.
    '''
    print("\n===The Python Communicator===" +
    "\n1) Generate RSA key pair\n2) View RSA key pairs\n3) Send message\n4) Receive message\n0) Exit")

def do_option(option, ip_address):
    ''' A helper method that models the decision making process
        that the menu will go through once an input has been
        provided. If an invalid input has been provided, the
        program will provide a meaningful error message

        option : (String) A string representing the user's choice
    '''  
    if option == "1":
        make_rsa_keys()         
    elif option == "2":
        list_own_key_pairs()
    elif option == "3":
        send(ip_address)
    elif option == "4":
        receive(ip_address)
    elif option == "0":
        print("\nGoodbye!") #ends program
    else:
        print("\nError, invalid input")

# LISTING DIRECTORIES
def iterate_dir(dir_path):
    """Iterates through the directory
       Parameters
       ----------
       dir_path: str
        The path of the directory
    """
    file_holder = []
    for path in os.listdir(dir_path):
        # check if current path is a file
        if os.path.isfile(os.path.join(dir_path, path)):
            file_holder.append(path)
    return file_holder

def list_shared_keys():
    """ Lists all key pairs in the shared keys directory"""
    # folder path
    dir_path = './shared_keys'
    # header
    print("======Shared Key Pairs=======")
    # Iterate directory
    for x in iterate_dir(dir_path):
        print(x)

def list_own_key_pairs():
    """ Lists all key pairs in the shared keys directory"""
    # folder path
    dir_path = './my_key_pairs'
    # header
    print("======Own Key Pairs=======")
    # Iterate directory
    for x in iterate_dir(dir_path):
        print(x)

def list_public_keys():
    """ Lists all key pairs in the shared keys directory"""
    # folder path
    dir_path = './public_keys'
    # header
    print("======Own Key Pairs=======")
    # Iterate directory
    for x in iterate_dir(dir_path):
        print(x)


# KEY CREATION
def make_rsa_keys():
    """Makes a new rsa key and takes input for the name then creates a new file
        containing the new rsa key"""
    user_name = input("Enter a name: ")
    key = RSA.generate(2048)
    private_key = key.export_key('PEM', 'passphrase')
    public_key = key.publickey().export_key('PEM')
    f = open('./my_key_pairs/' + user_name + '_prv.pem', 'wb')
    f.write(private_key)
    f.close()

    f = open('./my_key_pairs/' + user_name + '.pem', 'wb')
    f.write(public_key)
    f.close()

def make_aes_key():

    """Creates new aes key of ether 16/24/32 bytes then stores it in new file"""
    name = "my_key.aes"
    length = 16
    # create aes key based on chosen length
    key = get_random_bytes(length) # 32 bytes * 8 = 256 bits (1 byte = 8 bits
    with open("./shared_keys/" + name, "wb") as f:
        f.write(key)


# KEY/IP RETRIEVAL 
def get_public_rsa():
    """Lets user select the public rsa key they want to use.
        Makes sure the key exists and if it does not will send user
        back to the menu"""
    list_public_keys()
    rsa_name = input("Enter an RSA to retrieve (include extension) : ")
    if exists("./public_keys/" + rsa_name):
        return rsa_name

def get_rsa():
    """Lets user select the public rsa key they want to use.
        Makes sure the key exists and if it does not will send user
        back to the menu"""
    list_own_key_pairs()
    rsa_name = input("Enter an RSA to retrieve (include extension) : ")
    if exists("./my_key_pairs/" + rsa_name):
        return rsa_name

def get_aes():
    """Lets the user select the aes key they want to use.
        Makes sure the key exists and if it does not will send user
        back to the menu"""
    list_shared_keys()
    aes_name = input("Enter an AES key to retrieve (include extension) : ")
    if exists("./shared_keys/" + aes_name):
        return aes_name

def get_ip():
    '''A helper function that will ask for a valid ip address from
       the user. If the input is invalid, then the function will
       loop until a valid address hass been provided.
        
    Return:
        A valid IP Address that the user has inputted.
    '''
    ip = "";
    done = False

    while not done:
        try:
            ip = input("\nEnter Recipient IP: ") #enters an ip address
            ipaddress.ip_address(ip) #checks to see if ip is valid
            done = True #becomes true if ip is valid
        except ValueError: #catches if ip is invalid
            print("Error: not a valid IPv4 Address")

    return ip


# SEND
def send(ip_address):
    pub_key_name = get_rsa()
    prv_key_name = pub_key_name.replace('.pem', '_prv.pem')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            
            sock.settimeout(30.0)
            sendPublicKey(ip_address, sock, pub_key_name)
            receive_aes_key(sock)
            decrypt_aes_key_with_rsa(prv_key_name)

            print("\nSending.")
            user_input = 'Y'
            while user_input == 'Y':
                msg = get_message()
                encrypted_msg = encrypt_message(msg, 0)
                sock.sendall(encrypted_msg)
                data = sock.recv(1024)
                decrypted_data = decrypt_message(data, 0)
                if decrypted_data == "#<<END>>#":
                    user_input = False
                    print("\nMessage sent successfully.")
                else:  
                    print(decrypted_data)
                    user_input = input("Respond (Y/N): ")
                    if user_input == 'N':
                        sock.sendall("#<<END>>#".encode())
                        data = sock.recv(1024)
        
    except socket.timeout: #catches if the timeout() method timed out
        print("\nMessage sending error. Message not sent. (Timed Out)")
    except ConnectionRefusedError: #catches if the connection was refused
        print("\nMessage sending error. Connection has been refused")  
    #except OSError: 
            #print("\nError: IP Address could not be resolved")
        
    except socket.timeout: #catches if the timeout() method timed out
        print("\nMessage sending error. Message not sent. (Timed Out)")
    except ConnectionRefusedError: #catches if the connection was refused
        print("\nMessage sending error. Connection has been refused")

# SEND HELPER FUNCS
def sendPublicKey(ip_address, sock, pub_key_name):

        sock.settimeout(30.0) #Time out of 30 seconds if not received   
        sock.connect((ip_address, PORT))
        sock.settimeout(None) #Always set timeout to none before sending.
      
        prv_key_name = pub_key_name.replace('.pem', '_prv.pem')
        f = open('./my_key_pairs/' + pub_key_name, "rb")
        public_key = f.read()
        sock.sendall(pub_key_name.encode() + public_key)
        print("\nSending public key...")

def receive_aes_key(sock):
    aes_key = sock.recv(RECEIVE_CHARS)  
    f = open('./shared_keys/rsa_encrypted_sym_key.aes', 'wb')
    f.write(aes_key)

def decrypt_aes_key_with_rsa(prv_key_name):

    """decrypts an aes key that has been encrypted using a rsa key. Stores the decrypted key
        in a new file. If the hash has been changed it will issue a warning message."""
    
    dest_name = './shared_keys/decrypted_key.aes'
    rsa_key = RSA.importKey(open('./my_key_pairs/' + prv_key_name).read(), 'passphrase')
    with open('./shared_keys/rsa_encrypted_sym_key.aes', "rb") as file:
        aes_key_digest = file.read(32)
        encrypted_aes_key = file.read()

    # open same aes file and store entirety of contents into variable
    f = open('./shared_keys/rsa_encrypted_sym_key.aes', "rb")
    full_encrypted_aes = f.read()
    # create cipher and decrypt the key
    encrypted_key = PKCS1_OAEP.new(rsa_key)
    decrypted_key = encrypted_key.decrypt(encrypted_aes_key)
    hashed_aes_key = SHA256.new(decrypted_key)
    hashed_aes_key.update(encrypted_aes_key)
    if hashed_aes_key.digest() != aes_key_digest:
        print("The hashed digests do not match. Authentication cannot be verified")
        menu()
    else:
        with open(dest_name, "wb") as f:
            f.write(decrypted_key)

# RECEIVE
def receive(ip_address):
    
    all_ip = "" #leave this blank so that it searches for any ip address

    # create socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((all_ip, PORT))
        print("\nWaiting for message on port", PORT)
        sock.listen()
        conn, addr = sock.accept()

    # helper functions
    receive_public_key(ip_address, sock, conn)
    make_aes_key()
    encrypt_aes_key_with_rsa()
    send_aes_key(conn)
   
    # receive
    with conn:
        print(f"\nConnected by {addr}")
        print("\nMessage: ")

        user_input = 'Y'
        decrypted_data = decrypt_message(conn.recv(1024), 1)
        if decrypted_data == "#<<END>>#":
            user_input = 'N'
            conn.sendall("#<<END>>#".encode())
        while user_input ==  'Y':
            print(decrypted_data)  
            if user_input == 'Y':
                user_input = input("Respond(Y/N): ")
                if user_input == 'Y':
                    msg = get_message()
                    conn.sendall(encrypt_message(msg, 1))
                    decrypted_data = decrypt_message(conn.recv(1024), 1)
                    if decrypted_data == "#<<END>>#":
                        user_input = 'N'
                        conn.sendall("#<<END>>#".encode())
                else: 
                    conn.sendall("#<<END>>#".encode())

# RECEIVE HELPER FUNCS
def receive_public_key(ip_address, sock, conn):
    '''This facilitates the process of receiving a message from the host.
       The receive function should simply listen for communication to be
       initiated from the specific port. The receive function should then
       print out the message in terms of 1024 bit packets. The receive
       function should then send a message receipt to the sender confirming
       that the message has been sent.
    '''        
    public_key = conn.recv(RECEIVE_CHARS) #receives a 1024 character packet
    sentInfo = public_key.decode().split('-----BEGIN PUBLIC KEY-----') # split public_key into filename and contents
    if public_key: #if there are packets, write to file
        f = open("./public_keys/" + sentInfo[0], "wb")
        f.write(public_key[len(sentInfo[0]):len(public_key)]) # write all parts of the file after the delimiter of sentInfo
        f.close()
    
def encrypt_aes_key_with_rsa():
    """encrypts an aes key with rsa encryption. Stores the encrypted key in a new file."""
    prsa_exists = get_public_rsa()
    dest_name = "rsa_encrypted_sym_key.aes"

    # load relevant files
    f = open('./public_keys/' + prsa_exists, 'r')
    prsa_key = RSA.import_key(f.read())
    with open('./shared_keys/my_key.aes', "rb") as file:
        aes_key = file.read()

    # hash aes key
    hashed_aes_key = SHA256.new(aes_key)

    # public key is used to encrypt the AES key with the PKCS1_OAEP
    cipher = PKCS1_OAEP.new(prsa_key)
    ciphertext = cipher.encrypt(aes_key)
    # append to already hashed AES key digest
    hashed_aes_key.update(ciphertext)
    with open("./shared_keys/" + dest_name, "wb") as file:
        file.write(hashed_aes_key.digest())
        file.write(ciphertext)

def send_aes_key(conn):
    f = open('./shared_keys/rsa_encrypted_sym_key.aes', 'rb')
    conn.sendall(f.read())


# MESSAGE MANIPULATION
def encrypt_message(data, side):
    # read AES key
    if side == 0:
        aes_name = './shared_keys/decrypted_key.aes'
    else:
        aes_name = './shared_keys/my_key.aes'
    r = open(aes_name, "rb")
    key = r.read()

    hash_obj = SHA256.new(data.encode())
    
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(data.encode(), AES.block_size))
    return hash_obj.digest() + cipher.iv + cipher_text


def decrypt_message(data, side):
    hash_size = 48
    # check if file exists
    if side == 0:
        aes_name = './shared_keys/decrypted_key.aes'
    else:
        aes_name = './shared_keys/my_key.aes'
    # read aes key
    with open(aes_name, "rb") as r:
        key = r.read()

    # create decryption cipher and initialization vector
    iv = os.urandom(16)
    if data != '#<<END>>#'.encode():
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_encoded_text = unpad(cipher.decrypt(data), AES.block_size)
        plain_text = plain_encoded_text.decode('latin-1');
        return plain_text[hash_size:]
    else:
        plain_encoded_text = data.decode('utf-8')
        return plain_encoded_text
    
 
 
def get_message():
    '''A helper function that will ask for a message with a maximum of
       4096 characters from the user. If the message exceeds the maximum
       number of characters, then the function will loop until a valid
       message has been provided.
        
    Return:
        A message with a maximum of 4096 characters.
    '''
    message = "";
    done = False

    while not done:
        message = input("\nEnter Message (max 4096 characters): ") #gets message
        
        #ensures that message is a maximum of 4096 characters
        if len(message) <= MESSAGE_CHARS_MAX:
            done = True
        #if it is greater than 4096 characters, the user is asked again
        else:
            print("Error: Message is over 4096 bits")
        
    return message



        
def menu():
    '''This models the menu that the host and guest will be using
       throughout the duration of their communication.
    '''
    print("\n===The Python Communicator===" +
    "\n1) Generate RSA key pair\n2) View RSA key pairs\n3) Send message\n4) Receive message\n0) Exit")

if __name__ == "__main__":
    main()
