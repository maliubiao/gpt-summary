Response:
### 功能说明
该工具用于跟踪 `futex` 锁的争用情况，生成延迟直方图和堆栈跟踪。主要功能包括：
1. 统计 `futex` 锁的竞争次数、平均延迟、最大/最小延迟。
2. 支持按进程 PID、线程 TID、锁地址过滤跟踪目标。
3. 可选择显示时间戳、毫秒级直方图、简化摘要模式。
4. 捕获用户态堆栈信息，定位锁争用代码路径。

---

### 执行顺序（10 步）
1. **解析命令行参数**：读取过滤条件（PID/TID/锁地址）、输出格式（时间戳/毫秒）、堆栈存储配置。
2. **初始化 libbpf**：设置调试打印回调函数。
3. **加载 eBPF 程序**：打开并验证 `futexctn.bpf.o` 对象文件。
4. **配置全局参数**：将过滤条件（PID/TID/锁地址）注入 eBPF 程序的只读数据区。
5. **调整 eBPF Maps**：设置堆栈存储大小和最大堆栈深度。
6. **附加 eBPF 程序**：将 eBPF 程序挂载到内核函数（如 `futex_wait` 相关钩子）。
7. **初始化符号解析器**：准备解析用户态堆栈符号（使用 `blazesym` 或 `syms_cache`）。
8. **注册信号处理**：捕获 `SIGINT` 以优雅退出。
9. **轮询并打印结果**：按指定间隔从 eBPF Maps 读取数据，生成直方图和堆栈跟踪。
10. **清理资源**：销毁 eBPF 对象和符号解析器。

---

### eBPF Hook 点与数据
假设 eBPF 程序挂载以下内核函数（需参考 `futexctn.bpf.c` 确认）：
1. **钩子函数**：
   - `futex_wait`（进入等待时记录开始时间戳）
   - `futex_wake`（唤醒时记录结束时间戳）

2. **读取的有效信息**：
   - **进程 PID**：`bpf_get_current_pid_tgid() >> 32`
   - **线程 TID**：`bpf_get_current_pid_tgid() & 0xFFFFFFFF`
   - **锁地址**：`uaddr`（用户空间传入的 `futex` 地址）
   - **时间差**：`结束时间 - 开始时间`（计算延迟）
   - **用户态堆栈**：通过 `bpf_get_stackid()` 捕获调用链。

---

### 输入与输出示例
**输入命令**：
```bash
futexctn -p 123 -mT 1 5
```
- **过滤**：仅跟踪 PID 123 的进程。
- **输出**：每秒打印一次毫秒级直方图，包含时间戳，共打印 5 次。

**假设输出**：
```
[15:30:00]
process1[123] lock 0x7ff8e1a4 contended 42 times, 15 avg msecs [max: 200 msecs, min 1 msecs]
    -
    futex_lock_pi
    do_syscall_64
    entry_SYSCALL_64_after_hwframe
    -
     msecs           : count    distribution
         1 -> 2      : 10      **********
         2 -> 4      : 5       *****
         4 -> 8      : 12      ************
...
```

---

### 常见使用错误
1. **无效 PID/TID**：
   ```bash
   futexctn -p invalid_pid
   ```
   **错误**：`invalid PID: invalid_pid`

2. **权限不足**：
   ```bash
   ./futexctn
   ```
   **错误**：`failed to load BPF programs`（需 CAP_BPF 权限）

3. **堆栈存储不足**：
   ```bash
   futexctn --stack-storage-size 10
   ```
   **现象**：部分堆栈显示 `[Missed User Stack]`。

---

### Syscall 调试线索
1. **用户态调用**：应用调用 `futex(FUTEX_WAIT, uaddr, ...)`。
2. **内核路径**：
   - `sys_futex` → `futex_wait` → 加入等待队列。
   - 另一线程调用 `futex(FUTEX_WAKE, uaddr, ...)` 唤醒。
3. **eBPF 跟踪点**：
   - `kprobe:futex_wait`：记录开始时间、PID/TID、锁地址。
   - `kretprobe:futex_wait`：计算延迟并写入直方图 Map。
4. **数据流**：用户空间工具通过 `bpf_map_lookup_elem` 读取 Map 数据，聚合后输出。

---

### 总结
该工具通过 eBPF 高效跟踪 `futex` 锁竞争，结合用户态符号解析，帮助开发者定位锁争用热点。调试时需关注权限、内核版本兼容性及 Map 容量配置。
### 提示词
```
这是目录为bcc/libbpf-tools/futexctn.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Wenbo Zhang
//
// Based on https://sourceware.org/systemtap/wiki/WSFutexContention
// 10-Jul-2023   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include "futexctn.h"
#include "futexctn.skel.h"
#include "trace_helpers.h"
#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#else
static struct syms_cache *syms_cache;
#endif

static struct env {
	pid_t pid;
	pid_t tid;
	__u64 lock;
	time_t interval;
	int times;
	int stack_storage_size;
	int perf_max_stack_depth;
	bool summary;
	bool timestamp;
	bool milliseconds;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
};

static volatile sig_atomic_t exiting = 0;

const char *argp_program_version = "futexctn 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize futex contention latency as a histogram.\n"
"\n"
"USAGE: futexctn [--help] [-T] [-m] [-s] [-p pid] [-t tid] [-l lock] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    futexctn              # summarize futex contention latency as a histogram\n"
"    futexctn 1 10         # print 1 second summaries, 10 times\n"
"    futexctn -mT 1        # 1s summaries, milliseconds, and timestamps\n"
"    futexctn -s 1         # 1s summaries, without stack traces\n"
"    futexctn -l 0x8187bb8 # only trace lock 0x8187bb8\n"
"    futexctn -p 123       # only trace threads for PID 123\n"
"    futexctn -t 125       # only trace thread 125\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --pef-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "tid", 't', "TID", 0, "Trace this TID only", 0 },
	{ "lock", 'l', "LOCK", 0, "Trace this lock only", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for the stack traces (default 127)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)", 0 },
	{ "summary", 's', NULL, 0, "Summary futex contention latency", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 's':
		env.summary = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		errno = 0;
		env.tid = strtol(arg, NULL, 10);
		if (errno || env.tid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'l':
		errno = 0;
		env.lock = strtol(arg, NULL, 16);
		if (errno || env.lock <= 0) {
			fprintf(stderr, "Invalid lock: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
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

static void sig_handler(int sig)
{
	exiting = true;
}

static int print_stack(struct futexctn_bpf *obj, struct hist_key *info)
{
#ifdef USE_BLAZESYM
	sym_src_cfg cfgs[] = {
		{ .src_type = SRC_T_PROCESS, .params = { .process = { .pid = info->pid_tgid >> 32 }}},
	};
	const blazesym_result *result = NULL;
	const blazesym_csym *sym;
#else
	const struct syms *syms;
	const struct sym *sym;
	struct sym_info sinfo;
	int idx = 0;
#endif
	int i, err = 0, fd;
	uint64_t *ip;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return -1;
	}

	fd = bpf_map__fd(obj->maps.stackmap);
	err = bpf_map_lookup_elem(fd, &info->user_stack_id, ip);
	if (err != 0) {
		fprintf(stderr, "    [Missed User Stack]\n");
		goto cleanup;
	}

#ifdef USE_BLAZESYM
	result = blazesym_symbolize(symbolizer, cfgs, 1, ip, env.perf_max_stack_depth);

	for (i = 0; result && i < result->size; i++) {
		if (result->entries[i].size == 0)
			continue;
		sym = &result->entries[i].syms[0];
		if (sym->line_no)
			printf("    %s:%lu\n", sym->symbol, sym->line_no);
		else
			printf("    %s\n", sym->symbol);
	}
#else
	syms = syms_cache__get_syms(syms_cache, info->pid_tgid >> 32);
	if (!syms) {
		if (!env.verbose) {
			fprintf(stderr, "failed to get syms\n");
		} else {
			for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++)
				printf("    #%-2d 0x%016lx [unknown]\n", idx++, ip[i]);
		}
		goto cleanup;
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
#endif

cleanup:
#ifdef USE_BLAZESYM
	blazesym_result_free(result);
#endif

	free(ip);

	return 0;
}

static int print_map(struct futexctn_bpf *obj)
{
	struct hist_key lookup_key = { .pid_tgid = -1 }, next_key;
	const char *units = env.milliseconds ? "msecs" : "usecs";
	int err,fd = bpf_map__fd(obj->maps.hists);
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		printf("\n\n");
		printf(
		    "%s[%u] lock 0x%llx contended %llu times, %llu avg %s "
		    "[max: %llu %s, min %llu %s]\n",
		    hist.comm, (__u32)next_key.pid_tgid, next_key.uaddr,
		    hist.contended, hist.total_elapsed / hist.contended, units,
		    hist.max, units, hist.min, units);
		if (!env.summary) {
			printf("    -\n");
			print_stack(obj, &next_key);
			printf("    -\n");
		}
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key.pid_tgid = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct futexctn_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = futexctn_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_pid = env.pid;
	obj->rodata->targ_tid = env.tid;
	obj->rodata->targ_lock = env.lock;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_summary = env.summary;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = futexctn_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}
	err = futexctn_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

#ifdef USE_BLAZESYM
	symbolizer = blazesym_new();
#else
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}
#endif

	signal(SIGINT, sig_handler);

	fprintf(stderr, "Summarize futex contention latency, hit ctrl-c to exit\n");

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		print_map(obj);

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	futexctn_bpf__destroy(obj);
#ifdef USE_BLAZESYM
	blazesym_free(symbolizer);
#else
	syms_cache__free(syms_cache);
#endif
	return err != 0;
}
```