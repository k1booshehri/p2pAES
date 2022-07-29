import socket
import threading
import os
from Crypto.Cipher import AES

s = socket.socket(socket.AF_INET , socket.SOCK_DGRAM )
s.bind(("192.168.31.204",50001))
nm = input("ENTER YOUR NAME : ")
print("\nType 'quit' to exit.")

ip,port = input("Enter IP address and Port number: ").split()

def send():
    while True:
        ms = input(">> ")

        if ms == "quit":
            os._exit(1)

        key = b'Sixteen byte key'
        data=bytes(ms,'ascii')
        cipher = AES.new(key, AES.MODE_EAX)
        
        ciphertext, tag = cipher.encrypt_and_digest(data)

        file_out = open("encrypted.bin", "wb")

        [ file_out.write(x) for x in (cipher.nonce, tag , ciphertext) ]
        file_out.close()
        s.sendto(ciphertext, (ip,int(port)))


def rec():
    while True:
        msg = s.recvfrom(1024)
        file_in = open("encrypted.bin", "rb")
        nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
        key = b'Sixteen byte key'
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(msg[0], tag)
        print("\t\t\t\t >> " +  data.decode()  )
        print(">> ")

x1 = threading.Thread( target = send )
x2 = threading.Thread( target = rec )

x1.start()
x2.start()


