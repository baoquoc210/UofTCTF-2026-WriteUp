# extended-eBPF — Write up (35 solves)

## 0) What this challenge is about (what it’s “hiding”)

This is a Linux **kernel** exploitation challenge wrapped in an “eBPF is cool” theme.

- The service boots a **custom Linux kernel** inside QEMU.
- You can log in as the unprivileged user `ctf`, but the real flag is stored at `/flag` with permissions that prevent `ctf` from reading it.
- The “extension” is a **patch to the eBPF verifier** that accidentally (intentionally, for the CTF) makes the verifier **unsound**.

The hidden trick:

> The verifier thinks a pointer arithmetic is safe, but at runtime it becomes out-of-bounds.  
> That gives you kernel memory read/write, which you can use to become root and read `/flag`.

---

## 1) Quick background: eBPF in 2 minutes

**eBPF programs** run in the kernel (for example, as a socket filter). Because running attacker-controlled code in the kernel is dangerous, Linux uses a **verifier**:

- It checks every possible path in the program.
- It tracks **types** (pointer vs scalar), **ranges**, and **bounds**.
- It rejects programs that might do unsafe memory access.

**BPF maps** are shared memory objects between userland and eBPF programs.

Important detail used by many eBPF exploits:

- `bpf_map_lookup_elem(map, key)` returns a **kernel pointer** to the map value.
- The verifier allows pointer arithmetic on that pointer **as long as the offset is proven in-bounds**.

So if we can trick the verifier’s range tracking, we can turn “safe” access into out-of-bounds access.

---

## 2) Finding the bug: what the patch changes

The challenge ships a patch at `eebpf/chall.patch`.

The key verifier change is (conceptually):

- Upstream Linux requires the **shift amount** to be a constant in some situations when it needs to compute/track the destination register range precisely.
- This patch relaxes that requirement for shift operations, allowing **non-constant shifts** in a range-computation path.

Why that matters:

- If the verifier cannot correctly compute how a shift changes a value’s range, it may keep an old/smaller range.
- Then you can construct a value that is *runtime huge* but *verifier-small*.

There is also a change that effectively disables ALU sanitation (`can_skip_alu_sanitation()` always true). That’s about speculation/masking; the core memory-safety break we exploit is the **non-constant shift range bug**.

---

## 3) Exploit plan (high level)

Goal: read `/flag` (root-only).

To do that, we:

1. Load an unprivileged eBPF program (a **socket filter**).
2. Use the verifier bug to create an out-of-bounds pointer from a map value pointer.
3. Turn that into two primitives:
   - **Read** arbitrary kernel memory (relative to the map value allocation).
   - **Write** 8 bytes to arbitrary kernel memory (relative to the map value allocation).
4. Scan kernel memory to find our current process’s `struct cred`.
5. Patch `cred` to set UID/GID to 0 and give ourselves full capabilities.
6. Read `/flag`.

The flag for the remote service is:

`uoftctf{n0n_c0ns74n7_shif7_is_700_big_0f_4n_3x73nsi0n}`

---

## 4) The verifier bypass: “small to the verifier, huge at runtime”

### 4.1 The trick

We build an offset using attacker-controlled bytes from the “packet” seen by the socket filter:

- `off_byte` is 0..255 (read from packet)
- `sh` is 0..31 (read from packet, masked to 31)
- We compute `term = off_byte << sh`

**Correct runtime behavior:** if `sh = 24` and `off_byte = 0xff`, then `term = 0xff000000`.

**Verifier’s (bugged) view:** due to the patched verifier logic, the range analysis can fail to apply the shift effect, and it keeps `term` in the small range `0..255`.

We do this several times and add them together:

- Verifier thinks: `offset <= 4 * 255 = 1020`
- Runtime can reach ~`0xffffffff` (big enough to go far out-of-bounds)

### 4.2 Turning it into an OOB pointer

From `map_lookup_elem`, we obtain:

- `base = pointer_to_out_map_value`

We compute:

- `target = base + offset`

The verifier allows it because it believes `offset` is at most ~1020 (inside the map value).
At runtime, `offset` can be huge, so `target` can point outside the map value into arbitrary kernel memory.

---

## 5) Building read/write primitives with a socket filter

All code lives in `exploit.c`.

### 5.1 Maps

We create two array maps:

- `out_map` (value size 4096): used as a “return buffer” from BPF to userland
- `ctrl_map` (value size 8): used to pass a 64-bit write value into BPF

### 5.2 eBPF program behavior

The socket filter:

1. Looks up `out_map[0]` → `base` pointer.
2. Parses a small packet:
   - `pkt[0]`: operation (0 = read, 1 = write)
   - `pkt[1..]`: bytes used to compute the offset (via the buggy shift logic)
   - `pkt[5]`: sign flag for backward scanning (optional helper)
3. Builds the buggy `offset`.
4. Computes `target`.
5. If `op == 0` (read):
   - Copies a fixed number of bytes from `target` into `out_map[0]`.
6. If `op == 1` (write):
   - Reads 8 bytes from `ctrl_map[0]` and writes them to `*(u64*)target`.

### 5.3 Triggering it

We attach the program to one end of a Unix `socketpair()` with `SO_ATTACH_BPF`.
Then sending a packet on the other end triggers the eBPF program in the kernel.

After the trigger:

- For reads, userland calls `bpf_lookup_elem(out_map, key=0)` to fetch the copied bytes.
- For writes, userland first updates `ctrl_map[0]` to the desired 8-byte value.

---

## 6) Privilege escalation: finding and patching `struct cred`

### 6.1 Why `cred`?

Linux stores process identity and privileges in `struct cred`.
If we can modify our process’s `cred`, we can become root.

From the kernel headers (`/tmp/linux/include/linux/cred.h`) on this kernel version:

On x86_64, the relevant part is:

- `cred + 0x00`: `usage` (8 bytes)
- `cred + 0x08`: 8× 32-bit IDs:
  - `uid,gid,suid,sgid,euid,egid,fsuid,fsgid`
- then capabilities fields (each is a `u64` on this kernel):
  - `cap_inheritable`, `cap_permitted`, `cap_effective`, `cap_bset`, `cap_ambient`

### 6.2 Locating `cred` without symbols

We don’t rely on `kallsyms` or kernel symbols.
Instead we scan memory near our map value allocation and search for a structure-shaped pattern:

1. Read our `uid/gid` from userland (`getuid()/getgid()`).
2. Read `CapBnd` from `/proc/self/status` (this is a stable value we can use to validate a candidate).
3. During scanning, look for the sequence:

`{uid,gid,suid,sgid,euid,egid,fsuid,fsgid}`

Then validate it further by checking capability fields:

- `cap_inheritable == 0`
- `cap_permitted == 0`
- `cap_effective == 0`
- `cap_ambient == 0`
- `cap_bset == CapBnd` (from `/proc/self/status`)

That combination drastically reduces false positives.

### 6.3 Patching it

Once we find the start of the ID block (`cred+8`), we write:

- Zero all eight ID fields:
  - 4 × `write_u64()` to cover 8 × 32-bit integers
- Set capabilities:
  - `cap_permitted = CapBnd`
  - `cap_effective = CapBnd`

After this, `/proc/self/status` shows UID/GID 0 and effective capabilities, and we can read `/flag`.

---

## 7) Running the solve (remote)

The automation script is `solve/run_remote.py`.
It does:

1. Compile `exploit.c` into a static binary using Zig.
2. Connect to `nc 34.26.243.6 5000`.
3. Solve the proof-of-work.
4. Log in as `ctf`.
5. Upload the exploit via base64.
6. Run it and print the flag.

Run:

```bash
python3 solve/run_remote.py
```

---

## 8) Files to read if you’re learning

- `eebpf/chall.patch` — the intentional verifier weakening (the vulnerability source)
- `exploit.c` — full exploit (BPF program + userspace driver + cred scan/patch)
- `solve/run_remote.py` — PoW + remote login + upload automation

