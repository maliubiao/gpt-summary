Response:
### 功能概述
`memleak` 用于跟踪内存泄漏，通过 eBPF 监控用户空间或内核的内存分配/释放事件，检测未释放的内存块，并显示相关调用堆栈。支持过滤条件（如内存大小、采样率）和多种内存分配器（如 `malloc`、`kmalloc`）。

---

### 执行顺序（10步）
1. **解析命令行参数**  
   通过 `argp` 解析参数（如 `-p PID`、`-s 采样率`），设置环境变量 `env`。

2. **初始化信号处理**  
   注册 `SIGINT` 和 `SIGCHLD` 信号处理器，处理退出和子进程终止。

3. **参数验证与预处理**  
   检查参数冲突（如 `-c` 与 `-p`），设置默认对象（如 `libc.so.6`）、页大小，确定是否跟踪内核。

4. **创建子进程（若指定命令）**  
   使用 `fork_sync_exec` 创建子进程，通过 `eventfd` 同步 `exec` 调用。

5. **初始化符号解析器**  
   根据环境选择 `blazesym`（用户/内核符号）或 `ksyms`/`syms_cache`（传统方式）。

6. **加载并配置 eBPF 程序**  
   打开并加载 `memleak.skel`，设置 `min_size`、`max_size` 等参数，根据配置禁用不必要的内核 tracepoint。

7. **附加探针（Hook 点）**  
   根据目标（用户/内核）附加 uprobes 或内核 tracepoint，监控内存分配/释放函数。

8. **启动主循环**  
   按 `interval` 定期轮询，通过 `print_outstanding_allocs` 输出未释放内存的调用栈。

9. **处理子进程退出**  
   若跟踪的是命令，在循环结束后终止子进程并回收资源。

10. **清理资源**  
    释放符号解析器、eBPF skel、堆栈数组等资源。

---

### eBPF Hook 点与信息
#### 用户空间 Hook（附加到 `libc.so`）
- **入口点（uprobe）**  
  - 函数名: `malloc_enter`, `calloc_enter`, `realloc_enter` 等  
  - 信息: 分配大小（通过寄存器或参数读取），进程 PID。
- **返回点（uretprobe）**  
  - 函数名: `malloc_exit`, `calloc_exit` 等  
  - 信息: 分配的内存地址（返回值）、时间戳。

#### 内核空间 Hook（tracepoint）
- **分配事件**  
  - Tracepoint: `kmem:kmalloc`, `kmem:kmem_cache_alloc`  
  - 信息: 分配地址、大小、CPU 编号、调用栈。
- **释放事件**  
  - Tracepoint: `kmem:kfree`, `kmem:kmem_cache_free`  
  - 信息: 释放的地址。

---

### 逻辑推理示例
**假设输入**: `./memleak -p 1234 -a -o 1000`  
- **输入解析**: 跟踪 PID 1234，显示分配地址，过滤 1 秒内的分配。
- **预期输出**:  
  ```text
  [HH:MM:SS] Top N stacks with outstanding allocations:
  8192 bytes in 2 allocations from stack
      addr = 0x7f8a1a000 size = 4096
      addr = 0x7f8a1b000 size = 4096
      [堆栈跟踪...]
  ```

---

### 常见错误示例
1. **权限不足**  
   ```bash
   $ ./memleak -p 1
   ERROR: failed to attach uprobes (权限不够)
   ```
   **解决**: 使用 `sudo` 或授予 `CAP_BPF` 权限。

2. **符号前缀错误**  
   ```bash
   $ ./memleak -p 1234 -S jemalloc_
   ERROR: no program attached for malloc_enter
   ```
   **原因**: 目标进程使用 `jemalloc`，但符号前缀未正确匹配。

3. **内核不支持 Tracepoint**  
   ```text
   WARNING: kmem:kmalloc_node tracepoint not found, disabling.
   ```
   **处理**: 自动禁用相关探针，仅监控基础分配事件。

---

### Syscall 到 eBPF 的调试线索
1. **用户进程调用 `malloc`**  
   - 触发 `uprobe`，执行 eBPF 处理函数 `malloc_enter`，记录大小和 PID。
2. **内核分配内存（如 `kmalloc`）**  
   - 触发 `tracepoint`，执行 eBPF 处理函数 `memleak__kmalloc`，记录地址和大小。
3. **返回用户空间**  
   - `uretprobe` 触发 `malloc_exit`，记录地址和时间戳到 `allocs` map。
4. **内存释放**  
   - `free` 触发 `free_enter`，从 `allocs` 中删除对应条目。
5. **定期输出**  
   主循环遍历 `allocs` map，过滤未释放的内存，解析堆栈并排序输出。

---

### 关键数据结构
- **`allocs` Map**  
  Key: 内存地址，Value: `alloc_info`（大小、时间戳、堆栈 ID）。
- **`stack_traces` Map**  
  Key: 堆栈 ID，Value: 调用栈地址数组。
- **`combined_allocs` Map**  
  Key: 堆栈 ID，Value: 总大小和分配次数（聚合统计）。

---

### 符号解析流程
1. **用户空间地址**  
   使用 `blazesym` 或 `syms_cache` 解析进程符号。
2. **内核地址**  
   通过 `ksyms` 或 `blazesym` 解析内核符号。
3. **输出堆栈**  
   遍历堆栈地址，查找符号名和源码位置。

---

### 性能优化
- **采样率 (`-s`)**  
  仅跟踪每 N 次分配，降低开销。
- **堆栈深度限制 (`perf_max_stack_depth`)**  
  默认 127 层，避免 map 溢出。
- **过滤条件 (`min_size`, `max_size`)**  
  忽略过小/过大的分配。
### 提示词
```
这是目录为bcc/libbpf-tools/memleak.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
// Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
//
// Based on memleak(8) from BCC by Sasha Goldshtein and others.
// 1-Mar-2023   JP Kobryn   Created this.
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "memleak.h"
#include "memleak.skel.h"
#include "trace_helpers.h"

#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

static struct env {
	int interval;
	int nr_intervals;
	pid_t pid;
	bool trace_all;
	bool show_allocs;
	bool combined_only;
	long min_age_ns;
	uint64_t sample_rate;
	int top_stacks;
	size_t min_size;
	size_t max_size;
	char object[32];

	bool wa_missing_free;
	bool percpu;
	int perf_max_stack_depth;
	int stack_map_max_entries;
	long page_size;
	bool kernel_trace;
	bool verbose;
	char command[32];
	char symbols_prefix[16];
} env = {
	.interval = 5, // posarg 1
	.nr_intervals = -1, // posarg 2
	.pid = -1, // -p --pid
	.trace_all = false, // -t --trace
	.show_allocs = false, // -a --show-allocs
	.combined_only = false, // --combined-only
	.min_age_ns = 500, // -o --older (arg * 1e6)
	.wa_missing_free = false, // --wa-missing-free
	.sample_rate = 1, // -s --sample-rate
	.top_stacks = 10, // -T --top
	.min_size = 0, // -z --min-size
	.max_size = -1, // -Z --max-size
	.object = {0}, // -O --obj
	.percpu = false, // --percpu
	.perf_max_stack_depth = 127,
	.stack_map_max_entries = 10240,
	.page_size = 1,
	.kernel_trace = true,
	.verbose = false,
	.command = {0}, // -c --command
	.symbols_prefix = {0},
};

struct allocation_node {
	uint64_t address;
	size_t size;
	struct allocation_node* next;
};

struct allocation {
	uint64_t stack_id;
	size_t size;
	size_t count;
	struct allocation_node* allocations;
};

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
	do { \
		char sym[32]; \
		sprintf(sym, "%s%s", env.symbols_prefix, #sym_name); \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, \
				.func_name = sym, \
				.retprobe = is_retprobe); \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
				skel->progs.prog_name, \
				env.pid, \
				env.object, \
				0, \
				&uprobe_opts); \
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name) \
	do { \
		if (!skel->links.prog_name) { \
			perror("no program attached for " #prog_name); \
			return -errno; \
		} \
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
	do { \
		__ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe); \
		__CHECK_PROGRAM(skel, prog_name); \
	} while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

static void sig_handler(int signo);

static long argp_parse_long(int key, const char *arg, struct argp_state *state);
static error_t argp_parse_arg(int key, char *arg, struct argp_state *state);

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

static int event_init(int *fd);
static int event_wait(int fd, uint64_t expected_event);
static int event_notify(int fd, uint64_t event);

static pid_t fork_sync_exec(const char *command, int fd);

#ifdef USE_BLAZESYM
static void print_stack_frame_by_blazesym(size_t frame, uint64_t addr, const blazesym_csym *sym);
static void print_stack_frames_by_blazesym();
#else
static void print_stack_frames_by_ksyms();
static void print_stack_frames_by_syms_cache();
#endif
static int print_stack_frames(struct allocation *allocs, size_t nr_allocs, int stack_traces_fd);

static int alloc_size_compare(const void *a, const void *b);

static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd);
static int print_outstanding_combined_allocs(int combined_allocs_fd, int stack_traces_fd);

static bool has_kernel_node_tracepoints();
static void disable_kernel_node_tracepoints(struct memleak_bpf *skel);
static void disable_kernel_percpu_tracepoints(struct memleak_bpf *skel);
static void disable_kernel_tracepoints(struct memleak_bpf *skel);

static int attach_uprobes(struct memleak_bpf *skel);

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] =
"Trace outstanding memory allocations\n"
"\n"
"USAGE: memleak [-h] [-c COMMAND] [-p PID] [-t] [-n] [-a] [-o AGE_MS] [-C] [-F] [-s SAMPLE_RATE] [-T TOP_STACKS] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJECT] [-P] [INTERVAL] [INTERVALS]\n"
"\n"
"EXAMPLES:\n"
"./memleak -p $(pidof allocs)\n"
"        Trace allocations and display a summary of 'leaked' (outstanding)\n"
"        allocations every 5 seconds\n"
"./memleak -p $(pidof allocs) -t\n"
"        Trace allocations and display each individual allocator function call\n"
"./memleak -ap $(pidof allocs) 10\n"
"        Trace allocations and display allocated addresses, sizes, and stacks\n"
"        every 10 seconds for outstanding allocations\n"
"./memleak -c './allocs'\n"
"        Run the specified command and trace its allocations\n"
"./memleak\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations every 5 seconds\n"
"./memleak -o 60000\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations that are at least one minute (60 seconds) old\n"
"./memleak -s 5\n"
"        Trace roughly every 5th allocation, to reduce overhead\n"
"./memleak -p $(pidof allocs) -S je_\n"
"        Trace task who sue jemalloc\n"
"";

static const struct argp_option argp_options[] = {
	// name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
	{"pid", 'p', "PID", 0, "process ID to trace. if not specified, trace kernel allocs", 0 },
	{"trace", 't', 0, 0, "print trace messages for each alloc/free call", 0 },
	{"show-allocs", 'a', 0, 0, "show allocation addresses and sizes as well as call stacks", 0 },
	{"older", 'o', "AGE_MS", 0, "prune allocations younger than this age in milliseconds", 0 },
	{"command", 'c', "COMMAND", 0, "execute and trace the specified command", 0 },
	{"combined-only", 'C', 0, 0, "show combined allocation statistics only", 0 },
	{"wa-missing-free", 'F', 0, 0, "workaround to alleviate misjudgments when free is missing", 0 },
	{"sample-rate", 's', "SAMPLE_RATE", 0, "sample every N-th allocation to decrease the overhead", 0 },
	{"top", 'T', "TOP_STACKS", 0, "display only this many top allocating stacks (by size)", 0 },
	{"min-size", 'z', "MIN_SIZE", 0, "capture only allocations larger than or equal to this size", 0 },
	{"max-size", 'Z', "MAX_SIZE", 0, "capture only allocations smaller than or equal to this size", 0 },
	{"obj", 'O', "OBJECT", 0, "attach to allocator functions in the specified object", 0 },
	{"percpu", 'P', NULL, 0, "trace percpu allocations", 0 },
	{"symbols-prefix", 'S', "SYMBOLS_PREFIX", 0, "memory allocator symbols prefix", 0 },
	{"verbose", 'v', NULL, 0, "verbose debug output", 0 },
	{},
};

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t child_exited;

static struct sigaction sig_action = {
	.sa_handler = sig_handler
};

static int child_exec_event_fd = -1;

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
static sym_src_cfg src_cfg;
#else
struct syms_cache *syms_cache;
struct ksyms *ksyms;
#endif
static void (*print_stack_frames_func)();

static uint64_t *stack;

static struct allocation *allocs;

static const char default_object[] = "libc.so.6";

int main(int argc, char *argv[])
{
	int ret = 0;
	struct memleak_bpf *skel = NULL;

	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

	// parse command line args to env settings
	if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
		fprintf(stderr, "failed to parse args\n");

		goto cleanup;
	}

	// install signal handler
	if (sigaction(SIGINT, &sig_action, NULL) || sigaction(SIGCHLD, &sig_action, NULL)) {
		perror("failed to set up signal handling");
		ret = -errno;

		goto cleanup;
	}

	// post-processing and validation of env settings
	if (env.min_size > env.max_size) {
		fprintf(stderr, "min size (-z) can't be greater than max_size (-Z)\n");
		return 1;
	}

	if (!strlen(env.object)) {
		printf("using default object: %s\n", default_object);
		strncpy(env.object, default_object, sizeof(env.object) - 1);
	}

	env.page_size = sysconf(_SC_PAGE_SIZE);
	printf("using page size: %ld\n", env.page_size);

	env.kernel_trace = env.pid < 0 && !strlen(env.command);
	printf("tracing kernel: %s\n", env.kernel_trace ? "true" : "false");

	// if specific userspace program was specified,
	// create the child process and use an eventfd to synchronize the call to exec()
	if (strlen(env.command)) {
		if (env.pid >= 0) {
			fprintf(stderr, "cannot specify both command and pid\n");
			ret = 1;

			goto cleanup;
		}

		if (event_init(&child_exec_event_fd)) {
			fprintf(stderr, "failed to init child event\n");

			goto cleanup;
		}

		const pid_t child_pid = fork_sync_exec(env.command, child_exec_event_fd);
		if (child_pid < 0) {
			perror("failed to spawn child process");
			ret = -errno;

			goto cleanup;
		}

		env.pid = child_pid;
	}

	// allocate space for storing a stack trace
	stack = calloc(env.perf_max_stack_depth, sizeof(*stack));
	if (!stack) {
		fprintf(stderr, "failed to allocate stack array\n");
		ret = -ENOMEM;

		goto cleanup;
	}

#ifdef USE_BLAZESYM
	if (env.pid < 0) {
		src_cfg.src_type = SRC_T_KERNEL;
		src_cfg.params.kernel.kallsyms = NULL;
		src_cfg.params.kernel.kernel_image = NULL;
	} else {
		src_cfg.src_type = SRC_T_PROCESS;
		src_cfg.params.process.pid = env.pid;
	}
#endif

	// allocate space for storing "allocation" structs
	if (env.combined_only)
		allocs = calloc(COMBINED_ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	else
		allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));

	if (!allocs) {
		fprintf(stderr, "failed to allocate array\n");
		ret = -ENOMEM;

		goto cleanup;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = memleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		ret = 1;

		goto cleanup;
	}

	skel->rodata->min_size = env.min_size;
	skel->rodata->max_size = env.max_size;
	skel->rodata->page_size = env.page_size;
	skel->rodata->sample_rate = env.sample_rate;
	skel->rodata->trace_all = env.trace_all;
	skel->rodata->stack_flags = env.kernel_trace ? 0 : BPF_F_USER_STACK;
	skel->rodata->wa_missing_free = env.wa_missing_free;

	bpf_map__set_value_size(skel->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_map_max_entries);

	// disable kernel tracepoints based on settings or availability
	if (env.kernel_trace) {
		if (!has_kernel_node_tracepoints())
			disable_kernel_node_tracepoints(skel);

		if (!env.percpu)
			disable_kernel_percpu_tracepoints(skel);
	} else {
		disable_kernel_tracepoints(skel);
	}

	ret = memleak_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load bpf object\n");

		goto cleanup;
	}

	const int allocs_fd = bpf_map__fd(skel->maps.allocs);
	const int combined_allocs_fd = bpf_map__fd(skel->maps.combined_allocs);
	const int stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);

	// if userspace oriented, attach uprobes
	if (!env.kernel_trace) {
		ret = attach_uprobes(skel);
		if (ret) {
			fprintf(stderr, "failed to attach uprobes\n");

			goto cleanup;
		}
	}

	ret = memleak_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "failed to attach bpf program(s)\n");

		goto cleanup;
	}

	// if running a specific userspace program,
	// notify the child process that it can exec its program
	if (strlen(env.command)) {
		ret = event_notify(child_exec_event_fd, 1);
		if (ret) {
			fprintf(stderr, "failed to notify child to perform exec\n");

			goto cleanup;
		}
	}

#ifdef USE_BLAZESYM
	symbolizer = blazesym_new();
	if (!symbolizer) {
		fprintf(stderr, "Failed to load blazesym\n");
		ret = -ENOMEM;

		goto cleanup;
	}
	print_stack_frames_func = print_stack_frames_by_blazesym;
#else
	if (env.kernel_trace) {
		ksyms = ksyms__load();
		if (!ksyms) {
			fprintf(stderr, "Failed to load ksyms\n");
			ret = -ENOMEM;

			goto cleanup;
		}
		print_stack_frames_func = print_stack_frames_by_ksyms;
	} else {
		syms_cache = syms_cache__new(0);
		if (!syms_cache) {
			fprintf(stderr, "Failed to create syms_cache\n");
			ret = -ENOMEM;

			goto cleanup;
		}
		print_stack_frames_func = print_stack_frames_by_syms_cache;
	}
#endif

	printf("Tracing outstanding memory allocs...  Hit Ctrl-C to end\n");

	// main loop
	while (!exiting && env.nr_intervals) {
		env.nr_intervals--;

		sleep(env.interval);

		if (env.combined_only)
			print_outstanding_combined_allocs(combined_allocs_fd, stack_traces_fd);
		else
			print_outstanding_allocs(allocs_fd, stack_traces_fd);
	}

	// after loop ends, check for child process and cleanup accordingly
	if (env.pid > 0 && strlen(env.command)) {
		if (!child_exited) {
			if (kill(env.pid, SIGTERM)) {
				perror("failed to signal child process");
				ret = -errno;

				goto cleanup;
			}
			printf("signaled child process\n");
		}

		if (waitpid(env.pid, NULL, 0) < 0) {
			perror("failed to reap child process");
			ret = -errno;

			goto cleanup;
		}
		printf("reaped child process\n");
	}

cleanup:
#ifdef USE_BLAZESYM
	blazesym_free(symbolizer);
#else
	if (syms_cache)
		syms_cache__free(syms_cache);
	if (ksyms)
		ksyms__free(ksyms);
#endif
	memleak_bpf__destroy(skel);

	free(allocs);
	free(stack);

	printf("done\n");

	return ret;
}

long argp_parse_long(int key, const char *arg, struct argp_state *state)
{
	errno = 0;
	const long temp = strtol(arg, NULL, 10);
	if (errno || temp <= 0) {
		fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

error_t argp_parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args = 0;
	long age_ms;

	switch (key) {
	case 'p':
		env.pid = argp_parse_long(key, arg, state);
		break;
	case 't':
		env.trace_all = true;
		break;
	case 'a':
		env.show_allocs = true;
		break;
	case 'o':
		age_ms = argp_parse_long(key, arg, state);
		if (age_ms > (LONG_MAX / 1e6) || age_ms < (LONG_MIN / 1e6)) {
			fprintf(stderr, "invalid AGE_MS: %s\n", arg);
			argp_usage(state);
		}
		env.min_age_ns = age_ms * 1e6;
		break;
	case 'c':
		strncpy(env.command, arg, sizeof(env.command) - 1);
		break;
	case 'C':
		env.combined_only = true;
		break;
	case 'F':
		env.wa_missing_free = true;
		break;
	case 's':
		env.sample_rate = argp_parse_long(key, arg, state);
		break;
	case 'S':
		strncpy(env.symbols_prefix, arg, sizeof(env.symbols_prefix) - 1);
		break;
	case 'T':
		env.top_stacks = argp_parse_long(key, arg, state);
		break;
	case 'z':
		env.min_size = argp_parse_long(key, arg, state);
		break;
	case 'Z':
		env.max_size = argp_parse_long(key, arg, state);
		break;
	case 'O':
		strncpy(env.object, arg, sizeof(env.object) - 1);
		break;
	case 'P':
		env.percpu = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		pos_args++;

		if (pos_args == 1) {
			env.interval = argp_parse_long(key, arg, state);
		}
		else if (pos_args == 2) {
			env.nr_intervals = argp_parse_long(key, arg, state);
		} else {
			fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

void sig_handler(int signo)
{
	if (signo == SIGCHLD)
		child_exited = 1;

	exiting = 1;
}

int event_init(int *fd)
{
	if (!fd) {
		fprintf(stderr, "pointer to fd is null\n");

		return 1;
	}

	const int tmp_fd = eventfd(0, EFD_CLOEXEC);
	if (tmp_fd < 0) {
		perror("failed to create event fd");

		return -errno;
	}

	*fd = tmp_fd;

	return 0;
}

int event_wait(int fd, uint64_t expected_event)
{
	uint64_t event = 0;
	const ssize_t bytes = read(fd, &event, sizeof(event));
	if (bytes < 0) {
		perror("failed to read from fd");

		return -errno;
	} else if (bytes != sizeof(event)) {
		fprintf(stderr, "read unexpected size\n");

		return 1;
	}

	if (event != expected_event) {
		fprintf(stderr, "read event %lu, expected %lu\n", event, expected_event);

		return 1;
	}

	return 0;
}

int event_notify(int fd, uint64_t event)
{
	const ssize_t bytes = write(fd, &event, sizeof(event));
	if (bytes < 0) {
		perror("failed to write to fd");

		return -errno;
	} else if (bytes != sizeof(event)) {
		fprintf(stderr, "attempted to write %zu bytes, wrote %zd bytes\n", sizeof(event), bytes);

		return 1;
	}

	return 0;
}

pid_t fork_sync_exec(const char *command, int fd)
{
	const pid_t pid = fork();

	switch (pid) {
	case -1:
		perror("failed to create child process");
		break;
	case 0: {
		const uint64_t event = 1;
		if (event_wait(fd, event)) {
			fprintf(stderr, "failed to wait on event");
			exit(EXIT_FAILURE);
		}

		printf("received go event. executing child command\n");

		const int err = execl(command, command, NULL);
		if (err) {
			perror("failed to execute child command");
			return -1;
		}

		break;
	}
	default:
		printf("child created with pid: %d\n", pid);

		break;
	}

	return pid;
}

#ifdef USE_BLAZESYM
void print_stack_frame_by_blazesym(size_t frame, uint64_t addr, const blazesym_csym *sym)
{
	if (!sym)
		printf("\t%zu [<%016lx>] <%s>\n", frame, addr, "null sym");
	else if (sym->path && strlen(sym->path))
		printf("\t%zu [<%016lx>] %s+0x%lx %s:%ld\n", frame, addr, sym->symbol, addr - sym->start_address, sym->path, sym->line_no);
	else
		printf("\t%zu [<%016lx>] %s+0x%lx\n", frame, addr, sym->symbol, addr - sym->start_address);
}

void print_stack_frames_by_blazesym()
{
	const blazesym_result *result = blazesym_symbolize(symbolizer, &src_cfg, 1, stack, env.perf_max_stack_depth);

	for (size_t j = 0; j < result->size; ++j) {
		const uint64_t addr = stack[j];

		if (addr == 0)
			break;

		// no symbol found
		if (!result || j >= result->size || result->entries[j].size == 0) {
			print_stack_frame_by_blazesym(j, addr, NULL);

			continue;
		}

		// single symbol found
		if (result->entries[j].size == 1) {
			const blazesym_csym *sym = &result->entries[j].syms[0];
			print_stack_frame_by_blazesym(j, addr, sym);

			continue;
		}

		// multi symbol found
		printf("\t%zu [<%016lx>] (%lu entries)\n", j, addr, result->entries[j].size);

		for (size_t k = 0; k < result->entries[j].size; ++k) {
			const blazesym_csym *sym = &result->entries[j].syms[k];
			if (sym->path && strlen(sym->path))
				printf("\t\t%s@0x%lx %s:%ld\n", sym->symbol, sym->start_address, sym->path, sym->line_no);
			else
				printf("\t\t%s@0x%lx\n", sym->symbol, sym->start_address);
		}
	}

	blazesym_result_free(result);
}
#else
void print_stack_frames_by_ksyms()
{
	for (size_t i = 0; i < env.perf_max_stack_depth; ++i) {
		const uint64_t addr = stack[i];

		if (addr == 0)
			break;

		const struct ksym *ksym = ksyms__map_addr(ksyms, addr);
		if (ksym)
			printf("\t%zu [<%016lx>] %s+0x%lx\n", i, addr, ksym->name, addr - ksym->addr);
		else
			printf("\t%zu [<%016lx>] <%s>\n", i, addr, "null sym");
	}
}

void print_stack_frames_by_syms_cache()
{
	const struct syms *syms = syms_cache__get_syms(syms_cache, env.pid);
	if (!syms) {
		fprintf(stderr, "Failed to get syms\n");
		return;
	}

	for (size_t i = 0; i < env.perf_max_stack_depth; ++i) {
		const uint64_t addr = stack[i];

		if (addr == 0)
			break;

		struct sym_info sinfo;
		int ret = syms__map_addr_dso(syms, addr, &sinfo);
		if (ret == 0) {
			printf("\t%zu [<%016lx>]", i, addr);
			if (sinfo.sym_name)
				printf(" %s+0x%lx", sinfo.sym_name, sinfo.sym_offset);
			printf(" [%s]\n", sinfo.dso_name);
		} else {
			printf("\t%zu [<%016lx>] <%s>\n", i, addr, "null sym");
		}
	}
}
#endif

int print_stack_frames(struct allocation *allocs, size_t nr_allocs, int stack_traces_fd)
{
	for (size_t i = 0; i < nr_allocs; ++i) {
		const struct allocation *alloc = &allocs[i];

		printf("%zu bytes in %zu allocations from stack\n", alloc->size, alloc->count);

		if (env.show_allocs) {
			struct allocation_node* it = alloc->allocations;
			while (it != NULL) {
				printf("\taddr = %#lx size = %zu\n", it->address, it->size);
				it = it->next;
			}
		}

		if (bpf_map_lookup_elem(stack_traces_fd, &alloc->stack_id, stack)) {
			if (errno == ENOENT)
				continue;

			perror("failed to lookup stack trace");

			return -errno;
		}

		(*print_stack_frames_func)();
	}

	return 0;
}

int alloc_size_compare(const void *a, const void *b)
{
	const struct allocation *x = (struct allocation *)a;
	const struct allocation *y = (struct allocation *)b;

	// descending order

	if (x->size > y->size)
		return -1;

	if (x->size < y->size)
		return 1;

	return 0;
}

int print_outstanding_allocs(int allocs_fd, int stack_traces_fd)
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	size_t nr_allocs = 0;

	// for each struct alloc_info "alloc_info" in the bpf map "allocs"
	for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key) {
		struct alloc_info alloc_info = {};
		memset(&alloc_info, 0, sizeof(alloc_info));

		if (bpf_map_get_next_key(allocs_fd, &prev_key, &curr_key)) {
			if (errno == ENOENT) {
				break; // no more keys, done
			}

			perror("map get next key error");

			return -errno;
		}

		if (bpf_map_lookup_elem(allocs_fd, &curr_key, &alloc_info)) {
			if (errno == ENOENT)
				continue;

			perror("map lookup error");

			return -errno;
		}

		// filter by age
		if (get_ktime_ns() - env.min_age_ns < alloc_info.timestamp_ns) {
			continue;
		}

		// filter invalid stacks
		if (alloc_info.stack_id < 0) {
			continue;
		}

		// when the stack_id exists in the allocs array,
		//   increment size with alloc_info.size
		bool stack_exists = false;

		for (size_t i = 0; !stack_exists && i < nr_allocs; ++i) {
			struct allocation *alloc = &allocs[i];

			if (alloc->stack_id == alloc_info.stack_id) {
				alloc->size += alloc_info.size;
				alloc->count++;

				if (env.show_allocs) {
					struct allocation_node* node = malloc(sizeof(struct allocation_node));
					if (!node) {
						perror("malloc failed");
						return -errno;
					}
					node->address = curr_key;
					node->size = alloc_info.size;
					node->next = alloc->allocations;
					alloc->allocations = node;
				}

				stack_exists = true;
				break;
			}
		}

		if (stack_exists)
			continue;

		// when the stack_id does not exist in the allocs array,
		//   create a new entry in the array
		struct allocation alloc = {
			.stack_id = alloc_info.stack_id,
			.size = alloc_info.size,
			.count = 1,
			.allocations = NULL
		};

		if (env.show_allocs) {
			struct allocation_node* node = malloc(sizeof(struct allocation_node));
			if (!node) {
				perror("malloc failed");
				return -errno;
			}
			node->address = curr_key;
			node->size = alloc_info.size;
			node->next = NULL;
			alloc.allocations = node;
		}

		memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
	}

	// sort the allocs array in descending order
	qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	// get min of allocs we stored vs the top N requested stacks
	size_t nr_allocs_to_show = nr_allocs < env.top_stacks ? nr_allocs : env.top_stacks;

	printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs_to_show);

	print_stack_frames(allocs, nr_allocs_to_show, stack_traces_fd);

	// Reset allocs list so that we dont accidentaly reuse data the next time we call this function
	for (size_t i = 0; i < nr_allocs; i++) {
		allocs[i].stack_id = 0;
		if (env.show_allocs) {
			struct allocation_node *it = allocs[i].allocations;
			while (it != NULL) {
				struct allocation_node *this = it;
				it = it->next;
				free(this);
			}
			allocs[i].allocations = NULL;
		}
	}

	return 0;
}

int print_outstanding_combined_allocs(int combined_allocs_fd, int stack_traces_fd)
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	size_t nr_allocs = 0;

	// for each stack_id "curr_key" and union combined_alloc_info "alloc"
	// in bpf_map "combined_allocs"
	for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key) {
		union combined_alloc_info combined_alloc_info;
		memset(&combined_alloc_info, 0, sizeof(combined_alloc_info));

		if (bpf_map_get_next_key(combined_allocs_fd, &prev_key, &curr_key)) {
			if (errno == ENOENT) {
				break; // no more keys, done
			}

			perror("map get next key error");

			return -errno;
		}

		if (bpf_map_lookup_elem(combined_allocs_fd, &curr_key, &combined_alloc_info)) {
			if (errno == ENOENT)
				continue;

			perror("map lookup error");

			return -errno;
		}

		const struct allocation alloc = {
			.stack_id = curr_key,
			.size = combined_alloc_info.total_size,
			.count = combined_alloc_info.number_of_allocs,
			.allocations = NULL
		};

		memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
	}

	qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	// get min of allocs we stored vs the top N requested stacks
	nr_allocs = nr_allocs < env.top_stacks ? nr_allocs : env.top_stacks;

	printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs);

	print_stack_frames(allocs, nr_allocs, stack_traces_fd);

	return 0;
}

bool has_kernel_node_tracepoints()
{
	return tracepoint_exists("kmem", "kmalloc_node") &&
		tracepoint_exists("kmem", "kmem_cache_alloc_node");
}

void disable_kernel_node_tracepoints(struct memleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
}

void disable_kernel_percpu_tracepoints(struct memleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.memleak__percpu_alloc_percpu, false);
	bpf_program__set_autoload(skel->progs.memleak__percpu_free_percpu, false);
}

void disable_kernel_tracepoints(struct memleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.memleak__kmalloc, false);
	bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
	bpf_program__set_autoload(skel->progs.memleak__kfree, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_free, false);
	bpf_program__set_autoload(skel->progs.memleak__mm_page_alloc, false);
	bpf_program__set_autoload(skel->progs.memleak__mm_page_free, false);
	bpf_program__set_autoload(skel->progs.memleak__percpu_alloc_percpu, false);
	bpf_program__set_autoload(skel->progs.memleak__percpu_free_percpu, false);
}

int attach_uprobes(struct memleak_bpf *skel)
{
	ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);

	ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

	ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

	/* third party allocator like jemallloc not support mmap, so remove the check. */
	if (strlen(env.symbols_prefix)) {
		ATTACH_UPROBE(skel, mmap, mmap_enter);
		ATTACH_URETPROBE(skel, mmap, mmap_exit);

		ATTACH_UPROBE(skel, mremap, mmap_enter);
		ATTACH_URETPROBE(skel, mremap, mmap_exit);
	} else {
		ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
		ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);

		ATTACH_UPROBE_CHECKED(skel, mremap, mremap_enter);
		ATTACH_URETPROBE_CHECKED(skel, mremap, mremap_exit);
	}

	ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, free, free_enter);
	if (strlen(env.symbols_prefix))
		ATTACH_UPROBE(skel, munmap, munmap_enter);
	else
		ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

	// the following probes are intentinally allowed to fail attachment

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, valloc, valloc_enter);
	ATTACH_URETPROBE(skel, valloc, valloc_exit);

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
	ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

	// added in C11
	ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
	ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);


	return 0;
}
```