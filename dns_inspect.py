import socket

domain = input("Domain to lookup: ")


print(socket.gethostbyname(domain))