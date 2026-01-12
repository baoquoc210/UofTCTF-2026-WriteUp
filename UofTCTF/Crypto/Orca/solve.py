#!/usr/bin/env python3
import base64
import socket
from collections import Counter

HOST = "34.186.247.84"
PORT = 5000

BLOCK_SIZE = 16
MAX_U = 256
NUM_BLOCKS = 65  # indices 0..64


class OrcaClient:
    def __init__(self, host: str, port: int):
        self.s = socket.create_connection((host, port))
        self.buf = b""
        self._recv_until(b"> ")

    def close(self) -> None:
        try:
            self.s.close()
        except Exception:
            pass

    def _recv_until(self, token: bytes) -> bytes:
        while token not in self.buf:
            data = self.s.recv(4096)
            if not data:
                raise EOFError("connection closed")
            self.buf += data
        i = self.buf.index(token) + len(token)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def _recv_line(self) -> bytes:
        while b"\n" not in self.buf:
            data = self.s.recv(4096)
            if not data:
                raise EOFError("connection closed")
            self.buf += data
        i = self.buf.index(b"\n") + 1
        line, self.buf = self.buf[:i], self.buf[i:]
        return line

    def batch_query(self, queries: list[tuple[int, bytes]]) -> list[bytes]:
        payload = b"".join(f"{idx}:{u.hex()}\n".encode() for idx, u in queries)
        self.s.sendall(payload)

        out: list[bytes] = []
        for _ in queries:
            line = self._recv_line().strip()
            self._recv_until(b"> ")
            if line == b"error":
                raise ValueError("oracle returned error (bad idx?)")
            out.append(base64.b64decode(line))
        return out


def find_alignment_pad(client: OrcaClient) -> int:
    run = b"Z" * (BLOCK_SIZE * 8)  # 8 identical blocks
    for t in range(BLOCK_SIZE):
        tail = bytes(range(MAX_U - t - len(run)))
        u = b"P" * t + run + tail
        outs = client.batch_query([(i, u) for i in range(NUM_BLOCKS)])
        if max(Counter(outs).values()) == 8:
            return t
    raise RuntimeError("failed to find alignment pad (unexpected)")


def stable_indices(client: OrcaClient, u: bytes, repeats: int = 2) -> dict[int, bytes]:
    queries: list[tuple[int, bytes]] = []
    for idx in range(NUM_BLOCKS):
        for _ in range(repeats):
            queries.append((idx, u))
    outs = client.batch_query(queries)

    stable: dict[int, bytes] = {}
    for idx in range(NUM_BLOCKS):
        samples = outs[idx * repeats : (idx + 1) * repeats]
        if all(s == samples[0] for s in samples):
            stable[idx] = samples[0]
    return stable


def map_permutation(client: OrcaClient, align_pad: int, num_controlled_blocks: int) -> dict[int, int]:
    pad = b"P" * align_pad
    blocks = [bytes([i]) * BLOCK_SIZE for i in range(num_controlled_blocks)]
    u0 = pad + b"".join(blocks)

    stable = stable_indices(client, u0, repeats=2)
    stable_idxs = sorted(stable.keys())
    baseline = {idx: stable[idx] for idx in stable_idxs}

    block_to_outidx: dict[int, int] = {}
    for bi in range(num_controlled_blocks):
        blocks2 = blocks.copy()
        blocks2[bi] = bytes([bi + 100]) * BLOCK_SIZE
        u1 = pad + b"".join(blocks2)

        outs = client.batch_query([(idx, u1) for idx in stable_idxs])
        changed = [idx for idx, out in zip(stable_idxs, outs) if out != baseline[idx]]
        if len(changed) != 1:
            raise RuntimeError(f"block {bi} expected 1 changed idx, got {changed}")
        block_to_outidx[bi] = changed[0]
    return block_to_outidx


def recover_flag(client: OrcaClient, align_pad: int, block_to_outidx: dict[int, int]) -> bytes:
    pad = b"P" * align_pad
    recovered = b""

    printable = list(range(32, 127))
    allbytes = list(range(256))

    max_block = max(block_to_outidx)
    for j in range(512):
        k = j // BLOCK_SIZE
        if k > max_block:
            break

        outidx = block_to_outidx[k]
        pad2 = (BLOCK_SIZE - 1) - (j % BLOCK_SIZE)
        prefix = b"A" * pad2
        base = prefix + recovered
        if len(base) % BLOCK_SIZE != BLOCK_SIZE - 1:
            raise AssertionError("bad alignment for dictionary attack")

        # 1) get target
        # 2) try printable bytes (fast), then fallback to all 256 if needed
        queries = [(outidx, pad + prefix)]
        queries += [(outidx, pad + base + bytes([b])) for b in printable]
        outs = client.batch_query(queries)
        target = outs[0]
        mapping = {c: b for c, b in zip(outs[1:], printable)}

        if target not in mapping:
            queries = [(outidx, pad + prefix)]
            queries += [(outidx, pad + base + bytes([b])) for b in allbytes]
            outs = client.batch_query(queries)
            target = outs[0]
            mapping = {c: b for c, b in zip(outs[1:], allbytes)}
            if target not in mapping:
                break

        recovered += bytes([mapping[target]])

        # stop once we have something that looks like a CTF flag
        if recovered.endswith(b"}") and b"{" in recovered:
            return recovered

    return recovered


def main() -> None:
    client = OrcaClient(HOST, PORT)
    try:
        align_pad = find_alignment_pad(client)
        block_to_outidx = map_permutation(client, align_pad, num_controlled_blocks=12)
        flag = recover_flag(client, align_pad, block_to_outidx)
        print(flag.decode(errors="replace"))
    finally:
        client.close()


if __name__ == "__main__":
    main()

