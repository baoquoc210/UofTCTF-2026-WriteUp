#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.elf.elffile import ELFFile


def rol8(x: int, n: int) -> int:
    n &= 7
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF


def ror8(x: int, n: int) -> int:
    n &= 7
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


@dataclass(frozen=True)
class Step:
    index: int
    inv: list[int]


class RegFile:
    def __init__(self) -> None:
        self.r: dict[str, int] = {k: 0 for k in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp")}

    @staticmethod
    def _base64(reg: str) -> str | None:
        reg = reg.lower()
        if reg in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
            return reg
        if reg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
            return "r" + reg[1:]
        if reg in ("al", "bl", "cl", "dl"):
            return {"al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx"}[reg]
        return None

    def read(self, reg: str) -> int:
        reg = reg.lower()
        base = self._base64(reg)
        if base is None:
            raise NotImplementedError(f"read unsupported reg: {reg}")
        val = self.r[base] & 0xFFFFFFFFFFFFFFFF
        if reg.startswith("e"):
            return val & 0xFFFFFFFF
        if reg in ("al", "bl", "cl", "dl"):
            return val & 0xFF
        return val

    def write(self, reg: str, val: int) -> None:
        reg = reg.lower()
        base = self._base64(reg)
        if base is None:
            raise NotImplementedError(f"write unsupported reg: {reg}")
        if reg.startswith("e"):
            self.r[base] = val & 0xFFFFFFFF
            return
        if reg in ("al", "bl", "cl", "dl"):
            self.r[base] = (self.r[base] & ~0xFF) | (val & 0xFF)
            return
        self.r[base] = val & 0xFFFFFFFFFFFFFFFF


def _is_reg64(reg: str) -> bool:
    return reg.lower() in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi")


def extract_index(insns) -> int:
    candidates: list[int] = []
    for ins in insns:
        if ins.mnemonic == "add" and len(ins.operands) == 2:
            dst, src = ins.operands
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                reg = ins.reg_name(dst.reg)
                imm = int(src.imm)
                if _is_reg64(reg) and 0 <= imm <= 0x29:
                    candidates.append(imm)
        elif ins.mnemonic == "lea" and len(ins.operands) == 2:
            dst, src = ins.operands
            if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                reg = ins.reg_name(dst.reg)
                disp = int(src.mem.disp)
                if _is_reg64(reg) and 0 <= disp <= 0x29:
                    candidates.append(disp)
    if not candidates:
        return 0
    return Counter(candidates).most_common(1)[0][0]


def apply_once(insns, cell: int, rol_addr: int, ror_addr: int, f_addrs: set[int]) -> int:
    regs = RegFile()
    cell &= 0xFF

    for ins in insns:
        m = ins.mnemonic
        if m in ("endbr64", "nop", "push", "leave", "ret"):
            continue

        if m == "movzx":
            dst, src = ins.operands
            if dst.type != X86_OP_REG:
                raise RuntimeError(f"movzx unexpected dst: {ins.op_str}")
            dst_reg = ins.reg_name(dst.reg)
            if src.type == X86_OP_MEM:
                regs.write(dst_reg, cell)
            elif src.type == X86_OP_REG:
                regs.write(dst_reg, regs.read(ins.reg_name(src.reg)))
            else:
                raise RuntimeError(f"movzx unexpected src: {ins.op_str}")
            continue

        if m == "mov":
            dst, src = ins.operands
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                regs.write(ins.reg_name(dst.reg), int(src.imm))
                continue
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                regs.write(ins.reg_name(dst.reg), regs.read(ins.reg_name(src.reg)))
                continue
            if dst.type == X86_OP_MEM and src.type == X86_OP_REG:
                base = ins.reg_name(dst.mem.base) if dst.mem.base != 0 else ""
                if base.lower() not in ("rbp", "rsp"):
                    cell = regs.read(ins.reg_name(src.reg)) & 0xFF
                continue
            continue

        if m in ("add", "sub", "xor", "or"):
            dst, src = ins.operands
            if dst.type != X86_OP_REG:
                continue
            dst_reg = ins.reg_name(dst.reg)
            a = regs.read(dst_reg)
            if src.type == X86_OP_IMM:
                b = int(src.imm) & 0xFFFFFFFFFFFFFFFF
            elif src.type == X86_OP_REG:
                b = regs.read(ins.reg_name(src.reg))
            else:
                continue
            if m == "add":
                out = a + b
            elif m == "sub":
                out = a - b
            elif m == "xor":
                out = a ^ b
            else:
                out = a | b
            if dst_reg.lower().startswith("e"):
                out &= 0xFFFFFFFF
            regs.write(dst_reg, out)
            continue

        if m == "imul":
            dst, src = ins.operands
            if dst.type != X86_OP_REG or src.type != X86_OP_REG:
                raise RuntimeError(f"imul unexpected form: {ins.op_str}")
            dst_reg = ins.reg_name(dst.reg)
            src_reg = ins.reg_name(src.reg)
            regs.write(dst_reg, (regs.read(dst_reg) * regs.read(src_reg)) & 0xFFFFFFFF)
            continue

        if m in ("not", "neg"):
            op = ins.operands[0]
            if op.type != X86_OP_REG:
                continue
            reg = ins.reg_name(op.reg)
            val = regs.read(reg)
            out = (~val) if m == "not" else (-val)
            if reg.lower().startswith("e"):
                out &= 0xFFFFFFFF
            regs.write(reg, out)
            continue

        if m in ("shl", "shr"):
            dst, src = ins.operands
            if dst.type != X86_OP_REG or src.type != X86_OP_IMM:
                continue
            reg = ins.reg_name(dst.reg)
            cnt = int(src.imm) & 0xFF
            val = regs.read(reg)
            if reg.lower() in ("al", "bl", "cl", "dl"):
                val &= 0xFF
                out = ((val << cnt) if m == "shl" else (val >> cnt)) & 0xFF
            else:
                out = ((val << cnt) if m == "shl" else (val >> cnt)) & 0xFFFFFFFF
            regs.write(reg, out)
            continue

        if m == "lea":
            dst, src = ins.operands
            if dst.type != X86_OP_REG or src.type != X86_OP_MEM:
                continue
            dst_reg = ins.reg_name(dst.reg)
            if not dst_reg.lower().startswith("e"):
                continue  # pointer LEA
            total = int(src.mem.disp)
            if src.mem.base != 0:
                total += regs.read(ins.reg_name(src.mem.base))
            if src.mem.index != 0:
                total += regs.read(ins.reg_name(src.mem.index)) * int(src.mem.scale)
            regs.write(dst_reg, total & 0xFFFFFFFF)
            continue

        if m == "call":
            op = ins.operands[0]
            if op.type != X86_OP_IMM:
                raise RuntimeError(f"call unexpected form: {ins.op_str}")
            target = int(op.imm)
            if target == rol_addr:
                regs.write("eax", rol8(regs.read("edi"), regs.read("esi")))
                continue
            if target == ror_addr:
                regs.write("eax", ror8(regs.read("edi"), regs.read("esi")))
                continue
            if target in f_addrs:
                break
            raise RuntimeError(f"unexpected call 0x{target:x} at 0x{ins.address:x}")

        raise RuntimeError(f"unhandled instruction: {m} {ins.op_str} @0x{ins.address:x}")

    return cell & 0xFF


def build_steps(elf_path: str) -> tuple[list[Step], bytes]:
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        text = elf.get_section_by_name(".text")
        rodata = elf.get_section_by_name(".rodata")
        if symtab is None or text is None or rodata is None:
            raise RuntimeError("missing .symtab/.text/.rodata")

        sym_by_name = {s.name: s for s in symtab.iter_symbols()}
        rol_addr = sym_by_name["rol8"]["st_value"]
        ror_addr = sym_by_name["ror8"]["st_value"]
        expected_addr = sym_by_name["expected"]["st_value"]

        expected_off = expected_addr - rodata["sh_addr"]
        expected = rodata.data()[expected_off : expected_off + 42]

        f_syms = [sym_by_name[f"f_{i}"] for i in range(0, 4201)]
        f_addrs = {s["st_value"] for s in f_syms}

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        text_data = text.data()
        text_addr = text["sh_addr"]

        steps: list[Step] = []
        for i in range(0, 4200):
            sym = f_syms[i]
            addr = sym["st_value"]
            size = sym["st_size"]
            insns = list(md.disasm(text_data[addr - text_addr : addr - text_addr + size], addr))
            idx = extract_index(insns)

            inv = [0] * 256
            used = [False] * 256
            for v in range(256):
                out = apply_once(insns, v, rol_addr, ror_addr, f_addrs)
                if used[out]:
                    raise RuntimeError(f"non-bijective step f_{i}: output {out:#x} repeats")
                used[out] = True
                inv[out] = v

            steps.append(Step(index=idx, inv=inv))

        return steps, expected


def main() -> None:
    steps, expected = build_steps("checker.unpacked")
    buf = list(expected)
    for step in reversed(steps):
        buf[step.index] = step.inv[buf[step.index]]
    print(bytes(buf).decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
