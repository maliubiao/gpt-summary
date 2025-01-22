Response:
### 功能概述
`runqlat` 是一个基于 eBPF 的调度延迟分析工具，用于统计进程在运行队列中的等待时间并生成直方图。主要功能包括：
1. 按进程、线程、PID 命名空间或 Cgroup 分组统计延迟。
2. 支持毫秒或微秒精度。
3. 动态过滤指定 PID 或 Cgroup 的进程。
4. 输出带时间戳的周期性报告。

---

### 执行顺序（10 步）
1. **参数解析**：解析命令行参数，设置过滤条件（如 PID、Cgroup、时间间隔）。
2. **BPF 对象初始化**：打开并加载预编译的 BPF 程序 `runqlat.bpf.o`。
3. **全局数据配置**：设置过滤选项（如 `targ_per_process`）到 BPF 程序的只读数据区。
4. **探针动态选择**：根据内核支持性选择使用 `tracepoint` 或 `BTF` 挂载点。
5. **Cgroup 过滤配置**：若指定 Cgroup，将其路径映射到 BPF 的 Cgroup 过滤 Map。
6. **挂载 BPF 程序**：将处理函数附加到内核调度事件（如 `sched_wakeup`, `sched_switch`）。
7. **信号处理注册**：注册 `SIGINT` 处理函数以优雅退出。
8. **事件循环**：按指定间隔轮询并打印直方图。
9. **直方图生成**：从 BPF Map 中提取数据，按配置分组打印。
10. **资源清理**：销毁 BPF 对象并关闭文件描述符。

---

### eBPF Hook 点与信息
| Hook 点                | 挂载函数                   | 读取信息                                | 信息说明                     |
|------------------------|--------------------------|---------------------------------------|----------------------------|
| `sched_wakeup`         | `handle_sched_wakeup`    | 进程 PID、唤醒时间戳 (ts)                | 进程被唤醒加入运行队列的时间      |
| `sched_wakeup_new`     | `handle_sched_wakeup_new`| 新进程 PID、唤醒时间戳                   | 新进程创建时的唤醒时间           |
| `sched_switch`         | `handle_sched_switch`    | 前一进程 PID、切换时间戳 (prev_ts)        | 进程被切换出 CPU 的时间          |
| **逻辑推理**            | **计算延迟**              | `delta = switch_ts - wakeup_ts`       | 进程在运行队列中的等待时间        |

**输入输出示例**：
- **输入**：进程 A (PID=101) 在时间戳 1000 被唤醒，时间戳 1500 被调度。
- **输出**：记录 `delta=500` 到直方图，单位由 `-m` 决定。

---

### 常见使用错误
1. **选项冲突**：同时使用 `-P` (per-process) 和 `-L` (per-thread)。
   ```bash
   runqlat -P -L  # 错误：输出 "pidnss, pids, tids can't be used together."
   ```
2. **无效 Cgroup 路径**：指定不存在的 Cgroup 路径。
   ```bash
   runqlat -c /invalid/path  # 错误：Failed opening Cgroup path
   ```
3. **权限不足**：未以 root 运行或缺少 CAP_BPF 权限。
   ```bash
   sudo runqlat  # 正确：需要 root 权限加载 BPF 程序
   ```

---

### Syscall 到达 Hook 的调试线索
1. **进程创建**：用户调用 `fork()` → 内核创建任务 → 触发 `sched_wakeup_new`。
2. **进程唤醒**：调用 `wake_up()` 或 `sched_setaffinity()` → 触发 `sched_wakeup`。
3. **上下文切换**：时钟中断或主动调用 `sched_yield()` → 触发 `sched_switch`。
4. **数据记录**：eBPF 程序在 Hook 点捕获时间差，更新直方图 Map。
5. **用户空间轮询**：`main()` 循环从 Map 中读取数据并格式化输出。

---

### 关键调试技巧
1. **Verbose 模式**：添加 `-v` 参数显示 BPF 加载的详细日志。
2. **Map 检查**：通过 `bpftool map dump` 查看直方图 Map 内容。
3. **挂载点验证**：检查 `/sys/kernel/debug/tracing/events/sched` 确认事件存在。
Prompt: 
```
这是目录为bcc/libbpf-tools/runqlat.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on runqlat(8) from BCC by Bredan Gregg.
// 10-Aug-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "runqlat.h"
#include "runqlat.skel.h"
#include "trace_helpers.h"

struct env {
	time_t interval;
	pid_t pid;
	int times;
	bool milliseconds;
	bool per_process;
	bool per_thread;
	bool per_pidns;
	bool timestamp;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "runqlat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize run queue (scheduler) latency as a histogram.\n"
"\n"
"USAGE: runqlat [--help] [-T] [-m] [--pidnss] [-L] [-P] [-p PID] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    runqlat         # summarize run queue latency as a histogram\n"
"    runqlat 1 10    # print 1 second summaries, 10 times\n"
"    runqlat -mT 1   # 1s summaries, milliseconds, and timestamps\n"
"    runqlat -P      # show each PID separately\n"
"    runqlat -p 185  # trace PID 185 only\n"
"    runqlat -c CG   # Trace process under cgroupsPath CG\n";

#define OPT_PIDNSS	1	/* --pidnss */

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram", 0 },
	{ "pidnss", OPT_PIDNSS, NULL, 0, "Print a histogram per PID namespace", 0 },
	{ "pids", 'P', NULL, 0, "Print a histogram per process ID", 0 },
	{ "tids", 'L', NULL, 0, "Print a histogram per thread ID", 0 },
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
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
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'L':
		env.per_thread = true;
		break;
	case 'P':
		env.per_process = true;
		break;
	case OPT_PIDNSS:
		env.per_pidns = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
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

static int print_log2_hists(struct bpf_map *hists)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	int err, fd = bpf_map__fd(hists);
	__u32 lookup_key = -2, next_key;
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_process)
			printf("\npid = %d %s\n", next_key, hist.comm);
		else if (env.per_thread)
			printf("\ntid = %d %s\n", next_key, hist.comm);
		else if (env.per_pidns)
			printf("\npidns = %u %s\n", next_key, hist.comm);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key = -2;
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
	struct runqlat_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if ((env.per_thread && (env.per_process || env.per_pidns)) ||
		(env.per_process && env.per_pidns)) {
		fprintf(stderr, "pidnss, pids, tids cann't be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = runqlat_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_per_process = env.per_process;
	obj->rodata->targ_per_thread = env.per_thread;
	obj->rodata->targ_per_pidns = env.per_pidns;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->filter_cg = env.cg;

	if (probe_tp_btf("sched_wakeup")) {
		bpf_program__set_autoload(obj->progs.handle_sched_wakeup, false);
		bpf_program__set_autoload(obj->progs.handle_sched_wakeup_new, false);
		bpf_program__set_autoload(obj->progs.handle_sched_switch, false);
	} else {
		bpf_program__set_autoload(obj->progs.sched_wakeup, false);
		bpf_program__set_autoload(obj->progs.sched_wakeup_new, false);
		bpf_program__set_autoload(obj->progs.sched_switch, false);
	}

	err = runqlat_bpf__load(obj);
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

	err = runqlat_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing run queue latency... Hit Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);

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

		err = print_log2_hists(obj->maps.hists);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	runqlat_bpf__destroy(obj);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}

"""

```