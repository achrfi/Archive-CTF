#!/usr/bin/env python3
import argparse
import socket
import sys
import time
import re
from typing import List, Optional

U32 = 0xFFFFFFFF
INT_AT_END = re.compile(rb"(\d+)\s*$")


class Remote:
    def __init__(self, host: str, port: int, timeout: float = 4.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(0.6)  # short per-recv timeout
        self.buf = b""

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def send_lines(self, nums: List[int]):
        payload = ("\n".join(str(n) for n in nums) + "\n").encode()
        self.sock.sendall(payload)

    def _recv_some(self) -> bytes:
        return self.sock.recv(4096)

    def recv_line(self, overall_timeout: float = 6.0) -> bytes:
        """Read until '\n' (handles '\r\n'), with overall timeout."""
        deadline = time.time() + overall_timeout
        while True:
            nl = self.buf.find(b"\n")
            if nl != -1:
                line = self.buf[: nl + 1]
                self.buf = self.buf[nl + 1 :]
                return line
            if time.time() > deadline:
                raise TimeoutError("recv_line timed out")
            try:
                chunk = self._recv_some()
                if not chunk:
                    raise EOFError("connection closed by remote")
                self.buf += chunk
            except socket.timeout:
                continue

    def read_int(self, overall_timeout: float = 8.0) -> int:
        """
        Read next integer printed by server.
        Accepts formats like:
          b'123\\n'
          b'>> 123\\r\\n'
          b'some text >> 123\\n'
        """
        deadline = time.time() + overall_timeout
        while True:
            if time.time() > deadline:
                raise TimeoutError("read_int timed out")
            line = self.recv_line(overall_timeout=max(0.2, deadline - time.time()))
            # Normalize CRLF and strip
            s = line.strip().replace(b"\r", b"")
            m = INT_AT_END.search(s)
            if m:
                return int(m.group(1))
            # otherwise ignore this line (banner, messages, etc.)


def lcg_unique_624(seed: int = 0xC0FFEE) -> List[int]:
    """
    Generate 624 unique 32-bit ints.
    Avoid tiny sequences (some services add extra validation).
    """
    x = seed & U32
    out = []
    seen = set()
    # LCG parameters (glibc-ish-ish, doesn't matter, just spreads bits)
    a = 1103515245
    c = 12345
    while len(out) < 624:
        x = (a * x + c) & U32
        if x == 0:
            continue
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def leak_outputs(host: str, port: int, timeout: float, dummy_inputs: List[int]) -> List[int]:
    """
    One connection: send 624 dummy inputs fast, then read 624 RNG outputs.
    """
    r = Remote(host, port, timeout=timeout)
    try:
        r.send_lines(dummy_inputs)
        outs = [r.read_int(overall_timeout=timeout * 4) for _ in range(624)]
        return outs
    finally:
        r.close()


def run_with_inputs(host: str, port: int, timeout: float, inputs: List[int]) -> bytes:
    """
    One connection: send 624 chosen inputs fast, drain 624 outputs, then read tail (flag / '!').
    """
    if len(set(inputs)) != len(inputs):
        raise ValueError("inputs contain duplicates; chall rejects duplicates")

    r = Remote(host, port, timeout=timeout)
    try:
        r.send_lines(inputs)
        # Drain 624 outputs (ignore values)
        for _ in range(624):
            _ = r.read_int(overall_timeout=timeout * 4)

        # Read whatever remains (Winning... + flag or '!')
        r.sock.settimeout(0.6)
        tail = b""
        end = time.time() + timeout * 3
        while time.time() < end:
            try:
                chunk = r._recv_some()
                if not chunk:
                    break
                tail += chunk
                if b"{" in tail and b"}" in tail:
                    # likely got the flag
                    break
            except socket.timeout:
                continue
        return tail
    finally:
        r.close()


def main():
    ap = argparse.ArgumentParser(description="teio-step solver (robust parsing, 2-conn leak+replay)")
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--sync-check", type=int, default=6, help="compare first N leaked outputs across two leaks")
    args = ap.parse_args()

    # Dummy inputs must be valid 32-bit and unique
    dummy = lcg_unique_624()

    # Leak once
    leak1 = leak_outputs(args.host, args.port, args.timeout, dummy)

    # Optional sanity check: if per-connection seed differs, leak2 won't match leak1.
    if args.sync_check > 0:
        leak2 = leak_outputs(args.host, args.port, args.timeout, dummy)
        if leak1[:args.sync_check] != leak2[:args.sync_check]:
            print(
                "[!] Streams differ across connections (seed per connection). "
                "Leak+replay method won't work on this deployment.",
                file=sys.stderr,
            )
            # Print a small sample so you can confirm it’s actually returning numbers
            print("\n".join(str(x) for x in leak1[:20]))
            return

    # Replay leaked RNG outputs as inputs in a fresh run
    tail = run_with_inputs(args.host, args.port, args.timeout, leak1)

    sys.stdout.buffer.write(tail)
    sys.stdout.flush()

    if b"{" not in tail:
        print("\n[!] No flag seen. If you saw '!', the service likely seeds per connection.", file=sys.stderr)


if __name__ == "__main__":
    main()
