import socket
from argparse import ArgumentParser

def listen(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('0.0.0.0', port))
    print(f"Listening on UDP port {port}...")
    while True:
        data, addr = server.recvfrom(1024)
        print(f"Received {data} from {addr}")

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", dest="port", type=int, default=5001, help="UDP server listening port.")

    args = parser.parse_args()
    local_port = args.port

    listen(local_port)