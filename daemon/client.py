import socket 
import argparse

class Client():
    def __init__(self, conn, addr):
        # IP
        self.conn = conn

        self.addr = addr

        # Cookie
        self.cookie = None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Backend', description='', epilog='Beckend daemon')
    parser.add_argument('--server-ip', default='127.0.0.1')
    parser.add_argument('--server-port', type=int, default=8080)
 
    args = parser.parse_args()
    ip = args.server_ip
    port = args.server_port
    print("IP {} type {}, Port {} type {}".format(ip, type(ip), port, type(port)))
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(("127.0.0.1", 8080))
    print(conn)
    # conn.connect(((ip, port), 80))
    print(conn)
    print("Local:", conn.getsockname())
    print("Remote:", conn.getpeername())
    
    # addr_ip = input("IP: ")
    # addr_port = input("Port: ")
    # addr = (addr_ip, addr_port)
    # client = Client(conn, )
