"""Carries stdin and stdout to a TCP port, as `nc <host> <port>`: the tests' jump command.

In Python rather than `bash -c 'exec 3<>/dev/tcp/…; cat …'`, which depends on bash's network
redirections and on how the machine's `cat` copies between a socket and a pipe.
"""

import socket
import sys
import threading

conn = socket.create_connection((sys.argv[1], int(sys.argv[2])))


def upstream():
    while chunk := sys.stdin.buffer.read1(65536):
        conn.sendall(chunk)
    conn.shutdown(socket.SHUT_WR)


threading.Thread(target=upstream, daemon=True).start()
while chunk := conn.recv(65536):
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
