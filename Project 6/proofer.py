# proofer.py

import socket
import hashlib
import pickle

# create a client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to the trusted issuer's socket on port 1234
client_socket.connect((socket.gethostname(), 1234))

# input your birth year
birth_year = int(input("Enter your birth year: "))
# send your birth year to the trusted issuer
client_socket.send(pickle.dumps(birth_year))
print(f"Sent birth year: {birth_year}")

# receive s and sig from the trusted issuer
s, sig = pickle.loads(client_socket.recv(1024))
print(f"Received s and sig from the trusted issuer")

# close the connection with the trusted issuer
client_socket.close()

# create another client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to the verifier's socket on port 4321
client_socket.connect((socket.gethostname(), 4321))

# input the lower and upper bound of the interval
lower = int(input("Enter the lower bound of the interval: "))
upper = int(input("Enter the upper bound of the interval: "))

# compute d = upper - birth_year, p = H(s^d)
d = upper - birth_year
p = s
for i in range(d):
    p = hashlib.sha256(p).digest()

# send p and sig to the verifier
client_socket.send(pickle.dumps((p, sig)))
print(f"Sent p and sig to the verifier")

# receive the verification result from the verifier
result = client_socket.recv(1024).decode()
print(f"Received verification result: {result}")

# close the connection with the verifier
client_socket.close()
