Response:
### 功能列举
1. **统计进程阻塞时间**：测量进程从阻塞（如等待I/O、锁）到被唤醒的时间。
2. **按唤醒者内核栈聚合**：根据唤醒者的内核调用栈对阻塞时间分类统计。
3. **PID过滤**：支持仅跟踪指定进程的阻塞事件。
4. **用户线程过滤**：排除内核线程，仅统计用户线程。
5. **时间范围过滤**：仅统计超过`min`且低于`max`微秒的阻塞事件。
6. **内核栈解析**：将采集的栈地址转换为函数名+偏移。
7. **动态跟踪时长**：通过`duration`参数控制跟踪时间。
8. **性能调优参数**：可调整栈存储大小、最大栈深度等。

---

### 执行顺序（10步）
1. **解析命令行参数**：处理`-p`、`-u`、`-m`等选项，设置环境变量。
2. **校验参数逻辑**：如检查`min_block_time < max_block_time`。
3. **初始化BPF对象**：调用`wakeuptime_bpf__open()`打开BPF程序。
4. **配置BPF全局变量**：设置目标PID、时间范围过滤条件等。
5. **调整BPF Map参数**：设置栈存储大小和最大栈深度。
6. **加载并验证BPF程序**：`wakeuptime_bpf__load()`。
7. **加载内核符号表**：`ksyms__load()`用于栈地址解析。
8. **挂载BPF钩子到内核事件**：`wakeuptime_bpf__attach()`。
9. **等待信号或超时**：通过`sleep(env.duration)`持续采集数据。
10. **打印统计结果**：遍历BPF Map，输出聚合后的阻塞时间及对应栈。

---

### eBPF Hook点与数据
| Hook点类型 | 函数名              | 读取信息                          | 信息说明                     |
|------------|---------------------|-----------------------------------|------------------------------|
| **tracepoint** | `sched_wakeup`     | `struct task_struct *p`          | 被唤醒进程的PID、名称        |
| **tracepoint** | `sched_wakeup_new` | `struct task_struct *p`          | 新创建进程的唤醒信息         |
| **tracepoint** | `sched_switch`     | `prev_pid`, `next_pid`           | 上下文切换的前后进程PID      |

**关键数据**：
- **`w_k_stack_id`**：唤醒者的内核调用栈ID，用于关联栈数据。
- **`target`**：被唤醒进程的PID和名称。
- **`val`**：阻塞时间（纳秒级，打印时转为微秒）。

---

### 假设输入与输出
**输入示例**：
```bash
wakeuptime -p 185 -m 50 -M 1000 5
```
**输出逻辑**：
- 仅跟踪PID 185的进程。
- 统计阻塞时间在50~1000微秒的事件。
- 运行5秒后输出，按唤醒者内核栈聚合显示。

**输出示例**：
```
target: myapp         
waker: kworker/0:3
    0xffffffff810a0b0c schedule+0x2c
    0xffffffff810a1d1d schedule_timeout+0x1d
    300 us
```

---

### 常见使用错误
1. **冲突参数**：同时使用`-u`和`-p`，如`wakeuptime -u -p 123`。
   - **错误提示**：`use either -u or -p`。
2. **无效时间范围**：`-m 1000 -M 500`（min > max）。
   - **错误提示**：`min_block_time should be smaller...`。
3. **符号解析失败**：未以root运行或缺少调试符号，导致栈显示`Unknown`。
4. **栈存储溢出**：`--stack-storage-size`过小，部分栈未被记录。

---

### Syscall路径调试线索
1. **进程阻塞**：进程通过`read()`等系统调用进入睡眠。
2. **触发调度**：内核调用`schedule()`，记录`prev_pid`阻塞时间点。
3. **唤醒事件**：其他进程（如中断处理、kworker）调用`wake_up_process()`。
4. **捕获唤醒**：`sched_wakeup` tracepoint触发，记录唤醒者栈和当前时间。
5. **计算差值**：在`sched_switch`中计算`prev_pid`的阻塞时长，满足条件时存入Map。

**调试建议**：
- 使用`bpftool prog show`查看挂载的BPF程序。
- 检查`/sys/kernel/debug/tracing/trace_pipe`获取原始事件。
Prompt: 
```
这是目录为bcc/libbpf-tools/wakeuptime.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2022 Nicolas Sterchele
//
// Based on wakeuptime(8) from BCC by Brendan Gregg
// XX-Jul-2022 Nicolas Sterchele created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "wakeuptime.h"
#include "wakeuptime.skel.h"
#include "trace_helpers.h"
#include <unistd.h>

struct env {
	pid_t pid;
	bool user_threads_only;
	bool verbose;
	int stack_storage_size;
	int perf_max_stack_depth;
	__u64 min_block_time;
	__u64 max_block_time;
	int duration;
} env = {
	.verbose = false,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.min_block_time = 1,
	.max_block_time = -1,
	.duration = 99999999,
};

const char *argp_program_version = "wakeuptime 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize sleep to wakeup time by waker kernel stack.\n"
"\n"
"USAGE: wakeuptime [-h] [-p PID | -u] [-v] [-m MIN-BLOCK-TIME] "
"[-M MAX-BLOCK-TIME] ]--perf-max-stack-depth] [--stack-storage-size] [duration]\n"
"EXAMPLES:\n"
"	wakeuptime		# trace blocked time with waker stacks\n"
"	wakeuptime 5		# trace for 5 seconds only\n"
"	wakeuptime -u		# don't include kernel threads (user only)\n"
"	wakeuptime -p 185	# trace for PID 185 only\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --pef-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "trace this PID only", 0 },
	{ "verbose", 'v', NULL, 0, "show raw addresses", 0 },
	{ "user-threads-only", 'u', NULL, 0, "user threads only (no kernel threads)", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
		"PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
		"the number of unique stack traces that can be stored and displayed (default 1024)", 0 },
	{ "min-block-time", 'm', "MIN-BLOCK-TIME", 0,
		"the amount of time in microseconds over which we store traces (default 1)", 0 },
	{ "max-block-time", 'M', "MAX-BLOCK-TIME", 0,
		"the amount of time in microseconds under which we store traces (default U64_MAX)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'u':
		env.user_threads_only = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
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
	case 'm':
		errno = 0;
		env.min_block_time = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'M':
		errno = 0;
		env.max_block_time = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0){
			env.duration = strtol(arg, NULL, 10);
			if (errno || env.duration <= 0) {
				fprintf(stderr, "invalid duration (in s)\n");
				argp_usage(state);
			}
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
}

static void print_map(struct ksyms *ksyms, struct wakeuptime_bpf *obj)
{
	struct key_t lookup_key = {}, next_key;
	int err, i, counts_fd, stack_traces_fd;
	unsigned long *ip;
	const struct ksym *ksym;
	__u64 val;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	counts_fd = bpf_map__fd(obj->maps.counts);
	stack_traces_fd = bpf_map__fd(obj->maps.stackmap);

	while (!bpf_map_get_next_key(counts_fd, &lookup_key, &next_key)){
		err = bpf_map_lookup_elem(counts_fd, &next_key, &val);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			free(ip);
			return;
		}
		printf("\n	%-16s %s\n", "target:", next_key.target);
		lookup_key = next_key;

		err = bpf_map_lookup_elem(stack_traces_fd, &next_key.w_k_stack_id, ip);
		if (err < 0) {
			fprintf(stderr, "missed kernel stack: %d\n", err);
		}
		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			ksym = ksyms__map_addr(ksyms, ip[i]);
			if (ksym)
				printf("	%-16lx %s+0x%lx\n", ip[i], ksym->name, ip[i] - ksym->addr);
			else
				printf("	%-16lx Unknown\n", ip[i]);
		}
		printf("	%16s %s\n","waker:", next_key.waker);
		/*to convert val in microseconds*/
		val /= 1000;
		printf("	%lld\n", val);
	}

	free(ip);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct wakeuptime_bpf *obj;
	struct ksyms *ksyms = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.min_block_time >= env.max_block_time) {
		fprintf(stderr, "min_block_time should be smaller than max_block_time\n");
		return 1;
	}

	if (env.user_threads_only && env.pid > 0) {
		fprintf(stderr, "use either -u or -p");
	}

	libbpf_set_print(libbpf_print_fn);

	obj = wakeuptime_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->min_block_ns = env.min_block_time * 1000;
	obj->rodata->max_block_ns = env.max_block_time * 1000;
	obj->rodata->user_threads_only = env.user_threads_only;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = wakeuptime_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

	err = wakeuptime_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing blocked time (us) by kernel stack\n");
	sleep(env.duration);
	print_map(ksyms, obj);

cleanup:
	wakeuptime_bpf__destroy(obj);
	ksyms__free(ksyms);
	return err != 0;
}

"""

```