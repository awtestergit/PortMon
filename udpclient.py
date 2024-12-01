import socket
from argparse import ArgumentParser

def send(address, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(b"Hello UDP", (address, port))

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-a", "--addr", dest="address", type=str, default="127.0.0.1", help="UDP server listening address.")
    parser.add_argument("-p", "--port", dest="port", type=int, default=5001, help="UDP server listening port.")

    args = parser.parse_args()
    local_addr = args.address
    local_port = args.port

    send(local_addr, local_port)
