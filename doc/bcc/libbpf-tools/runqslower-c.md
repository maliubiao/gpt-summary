Response:
### **功能概述**
`runqslower` 用于追踪进程/线程在 **运行队列** 中的延迟（即被唤醒到实际获得 CPU 的时间差），当延迟超过设定的阈值（默认 10,000 微秒）时记录事件。支持按 PID/TID 过滤目标进程，可显示前一个任务信息。

---

### **执行顺序（10 步）**
1. **参数解析**  
   解析命令行参数（`-p PID`、`-t TID`、`-P` 等），设置过滤条件和阈值 `min_us`。

2. **初始化 libbpf**  
   设置 libbpf 的日志回调函数（根据 `-v` 控制调试输出）。

3. **加载 eBPF 程序**  
   通过 `runqslower_bpf__open()` 打开并初始化 BPF 对象，根据内核是否支持 BTF 决定加载传统 tracepoint 或 raw tracepoint 程序。

4. **配置全局过滤参数**  
   将用户输入的 `pid`、`tid`、`min_us` 写入 BPF 程序的只读全局变量（`obj->rodata`）。

5. **加载并验证 BPF 程序**  
   调用 `runqslower_bpf__load()` 将 BPF 程序加载到内核，验证字节码和映射（map）的正确性。

6. **挂载 eBPF 钩子**  
   通过 `runqslower_bpf__attach()` 将 eBPF 程序挂载到内核事件（如调度器 tracepoint）。

7. **创建 Perf 缓冲区**  
   初始化 Perf 缓冲区用于接收内核传递的事件数据，设置回调函数 `handle_event` 和 `handle_lost_events`。

8. **注册信号处理**  
   捕获 `SIGINT` 信号（Ctrl+C）以优雅退出循环。

9. **事件轮询循环**  
   持续轮询 Perf 缓冲区，处理事件或丢失事件，直到收到退出信号。

10. **资源清理**  
    释放 Perf 缓冲区和 BPF 对象资源。

---

### **eBPF Hook 点与信息捕获**
| Hook 点类型       | 内核函数/Tracepoint      | 捕获信息                                                                 |
|--------------------|--------------------------|--------------------------------------------------------------------------|
| **Tracepoint**     | `sched_wakeup`           | 目标进程的 PID/TID、任务名 (`task_struct->comm`)、唤醒时间戳             |
| **Tracepoint**     | `sched_wakeup_new`       | 新创建进程的唤醒事件（同上）                                             |
| **Tracepoint**     | `sched_switch`           | 切换前后的进程信息（当前任务 `prev_task` 和下一个任务 `next_task` 的 PID/TID、任务名） |

#### **关键数据**
- **`delta_us`**: 通过计算 `sched_wakeup` 和 `sched_switch` 时间戳差值得到延迟。
- **过滤条件**: 仅当延迟超过 `min_us` 且 PID/TID 匹配时触发事件。

---

### **假设输入与输出**
#### **输入示例**
```bash
sudo runqslower -p 1234 -P 5000
```
- **含义**: 监控 PID=1234 的进程，延迟超过 5000 微秒时输出，显示前一个任务信息。

#### **输出示例**
```
TIME     COMM             TID      LAT(us)    PREV COMM       PREV TID
14:30:01 my_process       1234      7500       kworker/0:3     45
```
- **逻辑推理**: 进程 `my_process` 在运行队列等待 7500 微秒后被调度，此前 CPU 由 `kworker/0:3` 占用。

---

### **常见使用错误**
1. **权限不足**  
   未以 root 权限运行，导致 eBPF 程序加载失败。

2. **无效 PID/TID**  
   输入非数字或不存在 PID（如 `-p abc`），触发参数解析错误。

3. **内核不支持 BTF**  
   在不支持 BTF 的内核中使用 raw tracepoint 导致程序无法挂载，需升级内核或使用传统 tracepoint。

---

### **Syscall 到 Hook 点的调试线索**
1. **进程唤醒**  
   进程通过 `sched_wakeup` 系统调用（如 `fork`、`nanosleep` 结束）进入就绪队列，触发 `sched_wakeup` tracepoint。

2. **上下文切换**  
   内核调用 `__schedule()` 函数切换任务时，触发 `sched_switch` tracepoint，记录当前和下一个任务的切换时间。

3. **延迟计算**  
   eBPF 程序在内核中记录唤醒时间戳，在 `sched_switch` 时计算时间差，若超过阈值则通过 Perf 缓冲区推送至用户态。

#### **调试技巧**
- 使用 `bpftool prog list` 查看加载的 eBPF 程序状态。
- 通过 `trace -K __schedule` 跟踪内核调度函数，验证 eBPF 是否触发。
Prompt: 
```
这是目录为bcc/libbpf-tools/runqslower.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
//
// Based on runqslower(8) from BCC by Ivan Babrou.
// 11-Feb-2020   Andrii Nakryiko   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "runqslower.h"
#include "runqslower.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting = 0;

struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	bool previous;
	bool verbose;
} env = {
	.min_us = 10000,
};

const char *argp_program_version = "runqslower 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace high run queue latency.\n"
"\n"
"USAGE: runqslower [--help] [-p PID] [-t TID] [-P] [min_us]\n"
"\n"
"EXAMPLES:\n"
"    runqslower         # trace latency higher than 10000 us (default)\n"
"    runqslower 1000    # trace latency higher than 1000 us\n"
"    runqslower -p 123  # trace pid 123\n"
"    runqslower -t 123  # trace tid 123 (use for threads only)\n"
"    runqslower -P      # also show previous task name and TID\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread TID to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "previous", 'P', NULL, 0, "also show previous task name and TID", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int pid;
	long long min_us;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'P':
		env.previous = true;
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
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		min_us = strtoll(arg, NULL, 10);
		if (errno || min_us <= 0) {
			fprintf(stderr, "Invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
		env.min_us = min_us;
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

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	struct tm *tm;
	char ts[32];
	time_t t;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (env.previous)
		printf("%-8s %-16s %-6d %14llu %-16s %-6d\n", ts, e.task, e.pid, e.delta_us, e.prev_task, e.prev_pid);
	else
		printf("%-8s %-16s %-6d %14llu\n", ts, e.task, e.pid, e.delta_us);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct runqslower_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = runqslower_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->min_us = env.min_us;

	if (probe_tp_btf("sched_wakeup")) {
		bpf_program__set_autoload(obj->progs.handle_sched_wakeup, false);
		bpf_program__set_autoload(obj->progs.handle_sched_wakeup_new, false);
		bpf_program__set_autoload(obj->progs.handle_sched_switch, false);
	} else {
		bpf_program__set_autoload(obj->progs.sched_wakeup, false);
		bpf_program__set_autoload(obj->progs.sched_wakeup_new, false);
		bpf_program__set_autoload(obj->progs.sched_switch, false);
	}

	err = runqslower_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = runqslower_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing run queue latency higher than %llu us\n", env.min_us);
	if (env.previous)
		printf("%-8s %-16s %-6s %14s %-16s %-6s\n", "TIME", "COMM", "TID", "LAT(us)", "PREV COMM", "PREV TID");
	else
		printf("%-8s %-16s %-6s %14s\n", "TIME", "COMM", "TID", "LAT(us)");

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 64,
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

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	runqslower_bpf__destroy(obj);

	return err != 0;
}

"""

```