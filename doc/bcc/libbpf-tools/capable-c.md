Response:
### capable.c 程序功能
1. **跟踪能力检查**：通过内核函数 `cap_capable()` 监控进程的权限检查请求。
2. **过滤条件**：支持按 PID、cgroup 过滤事件。
3. **堆栈跟踪**：可捕获用户态和内核态堆栈，辅助定位调用路径。
4. **详细信息输出**：包括时间、UID、PID、进程名、能力名称、审计标志、检查结果。
5. **唯一性输出**：按 PID 或 cgroup 去重，减少重复信息。
6. **性能调优**：自定义堆栈存储大小和最大深度，平衡资源与精度。
7. **多维度分析**：支持输出线程 ID（TID）和 `insetid` 字段，用于复杂调试。

---

### 执行顺序（10 步）
1. **参数解析**：解析命令行参数（PID、cgroup、堆栈配置等）。
2. **初始化 BPF 对象**：打开并加载 `capable.bpf.o` 内核对象。
3. **配置过滤条件**：设置 PID/cgroup 过滤规则到 BPF map。
4. **加载符号信息**：加载内核符号表 (`ksyms`) 和用户符号缓存 (`syms_cache`)。
5. **挂载 BPF 程序**：将 eBPF 程序附加到 `cap_capable` 内核函数。
6. **初始化 Perf 缓冲区**：创建用于接收内核事件的环形缓冲区。
7. **注册信号处理**：捕获 `SIGINT` 以优雅退出。
8. **打印表头**：根据参数选择输出详细或简洁的表头。
9. **事件循环**：轮询 Perf 缓冲区，处理能力检查事件。
10. **资源清理**：退出时释放 BPF 对象、符号表和文件描述符。

---

### eBPF Hook 点与信息
- **Hook 点**: `kprobe:cap_capable`（挂载到内核函数 `cap_capable()`）
- **读取的有效信息**：
  - **进程 PID/TGID**：触发检查的进程 ID 和线程组 ID。
  - **能力号 (cap)**：整数形式的能力标识（如 `21` 对应 `CAP_SYS_ADMIN`）。
  - **审计标志 (audit)**：内核审计子系统是否记录此事件。
  - **返回值 (ret)**：检查结果（0=允许，非 0=拒绝）。
  - **进程名 (task)**：执行检查的进程名称（如 `bash`）。
  - **用户堆栈/内核堆栈**：通过 `bpf_get_stackid()` 捕获调用链。

---

### 假设输入与输出
**输入示例**：
```bash
sudo ./capable -p 1234 -K -x
```
- **含义**：跟踪 PID=1234 的进程，显示内核堆栈和额外字段（TID/INSETID）。

**输出示例**：
```
TIME     UID   PID    TID    COMM            CAP  NAME                 AUDIT  VERDICT  INSETID
14:32:01 1000  1234   5678   bash            21   CAP_SYS_ADMIN        1      allow    0
    #0  0xffffffff81234567 security_capable+0x17
    #1  0xffffffff8123abcd cap_vm_enough_memory+0x42
    ...
```
- **解读**：PID 1234 的 `bash` 进程成功获取了 `CAP_SYS_ADMIN` 权限，内核堆栈显示检查路径。

---

### 常见使用错误
1. **权限不足**：未以 root 运行，导致 BPF 程序加载失败。
   - **错误信息**: `Permission denied while opening BPF object`
2. **无效 PID**：指定不存在的 PID，无任何输出。
   - **示例**: `-p 99999`（PID 99999 不存在）
3. **cgroup 路径错误**：路径不存在或不可读，导致过滤失效。
   - **示例**: `-c /invalid/path`
4. **堆栈配置过大**：超过内核限制，导致事件丢失。
   - **现象**: `lost X events on CPU #N` 频繁出现。

---

### Syscall 到达 Hook 的调试线索
1. **用户层系统调用**：如 `setuid()`、`mount()` 触发权限检查。
2. **内核执行路径**：
   - **系统调用入口**：如 `sys_setuid()` → `prepare_creds()` → `cap_capable()`
   - **能力检查逻辑**：`cap_capable()` 调用安全模块（如 SELinux）验证权限。
3. **eBPF 捕获**：在 `cap_capable()` 入口插入 kprobe，捕获参数和上下文。
4. **数据传递**：通过 Perf 缓冲区将事件发送到用户态，格式化输出。

---

### 调试技巧
- **内核日志**：结合 `dmesg` 查看 `cap_capable` 相关错误。
- **堆栈符号**：若堆栈显示 `[unknown]`，检查内核符号表或调试信息是否完整。
- **动态过滤**：运行时调整 PID/cgroup 过滤条件，缩小问题范围。
Prompt: 
```
这是目录为bcc/libbpf-tools/capable.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on capable(8) from BCC by Brendan Gregg.
//
// Copyright 2022 Sony Group Corporation

#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <bpf/bpf.h>
#include "capable.h"
#include "capable.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static struct env {
	bool	verbose;
	char	*cgroupspath;
	bool	cg;
	bool	extra_fields;
	bool	user_stack;
	bool	kernel_stack;
	bool	unique;
	char	*unique_type;
	int	stack_storage_size;
	int	perf_max_stack_depth;
	pid_t	pid;
} env = {
	.pid = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.unique = false,
};

const char *cap_name[] = {
	[0] = "CAP_CHOWN",
	[1] = "CAP_DAC_OVERRIDE",
	[2] = "CAP_DAC_READ_SEARCH",
	[3] = "CAP_FOWNER",
	[4] = "CAP_FSETID",
	[5] = "CAP_KILL",
	[6] = "CAP_SETGID",
	[7] = "CAP_SETUID",
	[8] = "CAP_SETPCAP",
	[9] = "CAP_LINUX_IMMUTABLE",
	[10] = "CAP_NET_BIND_SERVICE",
	[11] = "CAP_NET_BROADCAST",
	[12] = "CAP_NET_ADMIN",
	[13] = "CAP_NET_RAW",
	[14] = "CAP_IPC_LOCK",
	[15] = "CAP_IPC_OWNER",
	[16] = "CAP_SYS_MODULE",
	[17] = "CAP_SYS_RAWIO",
	[18] = "CAP_SYS_CHROOT",
	[19] = "CAP_SYS_PTRACE",
	[20] = "CAP_SYS_PACCT",
	[21] = "CAP_SYS_ADMIN",
	[22] = "CAP_SYS_BOOT",
	[23] = "CAP_SYS_NICE",
	[24] = "CAP_SYS_RESOURCE",
	[25] = "CAP_SYS_TIME",
	[26] = "CAP_SYS_TTY_CONFIG",
	[27] = "CAP_MKNOD",
	[28] = "CAP_LEASE",
	[29] = "CAP_AUDIT_WRITE",
	[30] = "CAP_AUDIT_CONTROL",
	[31] = "CAP_SETFCAP",
	[32] = "CAP_MAC_OVERRIDE",
	[33] = "CAP_MAC_ADMIN",
	[34] = "CAP_SYSLOG",
	[35] = "CAP_WAKE_ALARM",
	[36] = "CAP_BLOCK_SUSPEND",
	[37] = "CAP_AUDIT_READ",
	[38] = "CAP_PERFMON",
	[39] = "CAP_BPF",
	[40] = "CAP_CHECKPOINT_RESTORE"
};

static volatile sig_atomic_t exiting = 0;
struct syms_cache *syms_cache = NULL;
struct ksyms *ksyms = NULL;
int ifd, sfd;

const char *argp_program_version = "capable 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace security capability checks (cap_capable()).\n"
"\n"
"USAGE: capable [--help] [-p PID | -c CG | -K | -U | -x] [-u TYPE]\n"
"[--perf-max-stack-depth] [--stack-storage-size]\n"
"\n"
"EXAMPLES:\n"
"    capable                  # Trace capability checks\n"
"    capable -p 185           # Trace this PID only\n"
"    capable -c CG            # Trace process under cgroupsPath CG\n"
"    capable -K               # Add kernel stacks to trace\n"
"    capable -x               # Extra fields: show TID and INSETID columns\n"
"    capable -U               # Add user-space stacks to trace\n"
"    capable -u TYPE          # Print unique output for TYPE=[pid | cgroup] (default:off)\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ "kernel-stack", 'K', NULL, 0, "output kernel stack trace", 0 },
	{ "user-stack", 'U', NULL, 0, "output user stack trace", 0 },
	{ "extra-fields", 'x', NULL, 0, "extra fields: show TID and INSETID columns", 0 },
	{ "unique", 'u', "off", 0, "Print unique output for <pid> or <cgroup> (default:off)", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid == 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'U':
		env.user_stack = true;
		break;
	case 'K':
		env.kernel_stack = true;
		break;
	case 'x':
		env.extra_fields = true;
		break;
	case 'u':
		env.unique_type = arg;
		env.unique = true;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno || env.perf_max_stack_depth == 0) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno || env.stack_storage_size == 0) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void print_map(struct ksyms *ksyms, struct syms_cache *syms_cache)
{
	struct key_t lookup_key = {}, next_key;
	const struct ksym *ksym;
	const struct syms *syms;
	const struct sym *sym;
	struct sym_info sinfo;
	int idx;
	int err, i;
	unsigned long *ip;
	struct cap_event val;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
		idx = 0;

		err = bpf_map_lookup_elem(ifd, &next_key, &val);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			goto cleanup;
		}
		lookup_key = next_key;

		if (env.kernel_stack) {
			if (bpf_map_lookup_elem(sfd, &next_key.kern_stack_id, ip) != 0)
				fprintf(stderr, "    [Missed Kernel Stack]\n");
			for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
				ksym = ksyms__map_addr(ksyms, ip[i]);
				if (!env.verbose) {
					printf("    %s\n", ksym ? ksym->name : "Unknown");
				} else {
					if (ksym)
						printf("    #%-2d 0x%lx %s+0x%lx\n", idx++, ip[i], ksym->name, ip[i] - ksym->addr);
					else
						printf("    #%-2d 0x%lx [unknown]\n", idx++, ip[i]);
				}
			}
		}

		if (env.user_stack) {
			if (next_key.user_stack_id == -1)
				goto skip_ustack;

			if (bpf_map_lookup_elem(sfd, &next_key.user_stack_id, ip) != 0) {
				fprintf(stderr, "    [Missed User Stack]\n");
				continue;
			}

			syms = syms_cache__get_syms(syms_cache, next_key.tgid);
			if (!syms) {
				fprintf(stderr, "failed to get syms\n");
				goto skip_ustack;
			}
			for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
				if (!env.verbose) {
					sym = syms__map_addr(syms, ip[i]);
					if (sym)
						printf("    %s\n", sym->name);
					else
						printf("    [unknown]\n");
				} else {
					err = syms__map_addr_dso(syms, ip[i], &sinfo);
					printf("    #%-2d 0x%016lx", idx++, ip[i]);
					if (err == 0) {
						if (sinfo.sym_name)
							printf(" %s+0x%lx", sinfo.sym_name, sinfo.sym_offset);
						printf(" (%s+0x%lx)", sinfo.dso_name, sinfo.dso_offset);
					}
					printf("\n");
				}
			}
		}

	skip_ustack:
		printf("    %-16s %s (%d)\n", "-", val.task, next_key.pid);
	}

cleanup:
	free(ip);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct cap_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	char *verdict = "deny";
	if (!e->ret)
		verdict = "allow";

	if (env.extra_fields)
		printf("%-8s %-5d %-7d %-7d %-16s %-7d %-20s %-7d %-7s %-7d\n", ts, e->uid, e->pid, e->tgid, e->task, e->cap, cap_name[e->cap], e->audit, verdict, e->insetid);
	else
		printf("%-8s %-5d %-7d %-16s %-7d %-20s %-7d %-7s\n", ts, e->uid, e->pid, e->task, e->cap, cap_name[e->cap], e->audit, verdict);

	print_map(ksyms, syms_cache);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct capable_bpf *obj;
	struct perf_buffer *pb = NULL;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;
	enum uniqueness uniqueness_type = UNQ_OFF;
	pid_t my_pid = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.unique) {
		if (strcmp(env.unique_type, "pid") == 0) {
			uniqueness_type = UNQ_PID;
		} else if (strcmp(env.unique_type, "cgroup") == 0) {
			uniqueness_type = UNQ_CGROUP;
		} else {
			fprintf(stderr, "Unknown unique type %s\n", env.unique_type);
			return -1;
		}
	}

	libbpf_set_print(libbpf_print_fn);

	obj = capable_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->filter_cg = env.cg;
	obj->rodata->user_stack = env.user_stack;
	obj->rodata->kernel_stack = env.kernel_stack;
	obj->rodata->unique_type = uniqueness_type;

	my_pid = getpid();
	obj->rodata->my_pid = my_pid;

	bpf_map__set_value_size(obj->maps.stackmap, env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = capable_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}

	ifd = bpf_map__fd(obj->maps.info);
	sfd = bpf_map__fd(obj->maps.stackmap);

	err = capable_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
					handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.extra_fields)
		printf("%-8s %-5s %-7s %-7s %-16s %-7s %-20s %-7s %-7s %-7s\n", "TIME", "UID", "PID", "TID", "COMM", "CAP", "NAME", "AUDIT", "VERDICT", "INSETID");
	else
		printf("%-8s %-5s %-7s %-16s %-7s %-20s %-7s %-7s\n", "TIME", "UID", "PID", "COMM", "CAP", "NAME", "AUDIT", "VERDICT");

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	capable_bpf__destroy(obj);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}

"""

```