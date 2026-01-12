# Encryption Service — Write-up (258 solves)

## 1) What the challenge is “hiding” (what you’re supposed to break)

The service promises “free encrypted flags”, but **never gives you the AES key**.

Normally, if the flag is encrypted with **AES-CBC** using a **random secret key**, you *cannot* decrypt it without that key. So the “intended” obstacle is:

- You can get `Enc(flag)` as many times as you want
- But the key is unknown and changes each connection
- So “real crypto” decryption should be impossible

The twist is that the service doesn’t just have crypto — it has a **command-line / scripting bug** that lets us make the server encrypt the flag under a key we choose.

---

## 2) Provided files (how the service works)

### `enc.py`

`enc.py` is a simple AES encryptor:

- Input: command-line args: `enc.py <hex_key> <plaintext...>`
- It joins plaintext args with newlines: `pt = "\n".join(sys.argv[2:])`
- Generates a random IV
- Encrypts with AES-CBC + PKCS#7 padding
- Output: `iv || ciphertext` as hex

### `run.sh`

This is the actual “service” logic:

1. Generates a random key (16 bytes) and writes it as hex to `/tmp/input.txt` (first line)
2. Reads your lines until you send `EOF`, appending each line to `/tmp/input.txt`
3. Appends the real flag from `/flag.txt` to `/tmp/input.txt`
4. Encrypts everything with:

```sh
cat "$OUTFILE" | xargs /app/enc.py
```

This one line is the vulnerability.

---

## 3) The bug: `xargs` splits input + may run the command multiple times

### What `xargs` does (important beginner concept)

`xargs` reads text from stdin and turns it into **command-line arguments**.

Key details:

- It splits input on **whitespace** (spaces/newlines/tabs)
- It tries to build **one long command**
- If the command would exceed the system’s maximum command-line length, `xargs` automatically runs the command **multiple times**

So instead of:

```sh
/app/enc.py <key> <a lot of plaintext tokens...>
```

it can become:

```sh
/app/enc.py <key> <some tokens...>
/app/enc.py <more tokens...>
/app/enc.py <even more tokens...>
...
```

### Why that breaks the encryption scheme

`enc.py` interprets its **first argument** as the AES key:

```py
key_hex = sys.argv[1]
```

So if `xargs` runs `enc.py` multiple times, then **each new invocation uses a different “first argument” as the key**.

That means:

- First invocation: key = the real random key (good for them)
- A later invocation: key = *whatever token happens to be first in that invocation* (potentially attacker-controlled)

If we can make a later invocation start at a token that we control and that is a valid 32-hex-character key, we win.

---

## 4) Exploit idea (how we force “encrypt flag with our key”)

Goal: make `xargs` start a new `enc.py` process at a token we choose:

- We will include a line that is exactly a valid AES key in hex (32 hex chars), e.g.:
  - `00000000000000000000000000000000`
- We will send a **huge amount of filler** before it (lots of `A`s) so `xargs` is forced to split into multiple commands
- If the split happens right before our key token, then one `enc.py` invocation becomes:

```
/app/enc.py 00000000000000000000000000000000 <rest of tokens ... including the flag>
```

Now the service has encrypted the flag using our known key. We can decrypt locally.

### What to expect from the server output

Each `enc.py` invocation prints one hex string:

```
<IV (16 bytes)> <ciphertext>
```

So when `xargs` runs `enc.py` multiple times, you’ll receive **multiple hex lines**.

We just try to decrypt each line with our chosen key; only the one that used our key will decrypt cleanly and contain `uoftctf{...}`.

---

## 5) Step-by-step solution

### Step 1 — Pick a key you know

Use all-zero key (16 bytes):

```
00000000000000000000000000000000
```

### Step 2 — Craft input to force multiple `xargs` invocations

Send lots of filler lines first, then the key as its own line, then `EOF`.

One set of values that works reliably:

- 130 lines of `"A"*1000`
- 1 line of `"A"*864`
- 1 line containing the key `0000...0000`
- `EOF`

Why this works: it makes the argument list big enough that `xargs` must split, and in practice one of the splits starts at the key token.

### Step 3 — Parse the response and decrypt

For each hex output line:

1. Convert hex → bytes
2. Split: `iv = first 16 bytes`, `ct = rest`
3. Decrypt using AES-CBC with the known key and that IV
4. Unpad PKCS#7
5. Check if plaintext contains `uoftctf{`

---

## 6) Solver script (Python)

Save as `solve.py` locally (or just run it in a Python environment with `pycryptodome` installed):

```py
import re
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = "34.86.4.154"
PORT = 5000

KNOWN_KEY_HEX = "00" * 16
KNOWN_KEY = bytes.fromhex(KNOWN_KEY_HEX)

def main():
    # Build payload: lots of filler, then our chosen 32-hex key, then EOF
    lines = ["A" * 1000] * 130
    lines.append("A" * 864)
    lines.append(KNOWN_KEY_HEX)
    lines.append("EOF")
    payload = "\n".join(lines) + "\n"

    # Connect + send
    s = socket.create_connection((HOST, PORT))
    s.sendall(payload.encode())

    # Read all output
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()

    text = data.decode(errors="replace")

    # Collect hex-only lines (each is one enc.py output)
    hex_lines = []
    for line in text.splitlines():
        line = line.strip()
        if re.fullmatch(r"[0-9a-fA-F]+", line) and len(line) >= 64 and len(line) % 32 == 0:
            hex_lines.append(line)

    # Try decrypting each ciphertext with our known key
    for h in hex_lines:
        blob = bytes.fromhex(h)
        iv, ct = blob[:16], blob[16:]

        pt = AES.new(KNOWN_KEY, AES.MODE_CBC, iv).decrypt(ct)
        try:
            pt = unpad(pt, 16)
        except ValueError:
            continue

        try:
            spt = pt.decode()
        except UnicodeDecodeError:
            continue

        if "uoftctf{" in spt:
            # Print just the flag-looking part
            start = spt.index("uoftctf{")
            end = spt.index("}", start) + 1
            print(spt[start:end])
            return

    print("Did not find flag; try increasing filler size and retry.")

if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve.py
```

---

## 7) Flag

`uoftctf{x4rgs_d03sn7_run_in_0n3_pr0c3ss}`

---

## 8) Takeaway / lesson

This challenge looks like “break AES”, but the real bug is:

- **Using `xargs` to build a command line containing secrets and attacker-controlled data**
- Letting that command line **split into multiple invocations**, changing how arguments are interpreted

In real systems, secrets should not be handled like this. Prefer passing data via stdin, using fixed interfaces, and avoiding argument splitting tools (`xargs`) for security-sensitive pipelines.

