Response:
### 功能概述
该 eBPF 程序用于统计内核调度器运行队列（run queue）长度的分布情况，支持以直方图或队列占用率形式展示。主要功能包括：
1. 按指定频率采样 CPU 运行队列长度。
2. 支持按 CPU 核心分别统计或全局汇总。
3. 可输出时间戳、队列占用率百分比。
4. 支持选择从 CFS 调度队列或全局运行队列读取数据。

---

### **执行顺序（10步）**
1. **参数解析**：解析命令行参数（如采样频率、输出模式、时间戳等）。
2. **初始化 Libbpf**：设置调试回调函数，检测系统 CPU 数量。
3. **加载 BTF 信息**：确保内核 BTF 数据可用（CO-RE 依赖）。
4. **打开并验证 BPF 对象**：加载 `runqlen.bpf.o` 并校验内存映射。
5. **配置全局变量**：设置目标参数（如 `per_cpu`、`host` 标志）。
6. **附加 Perf 事件**：为每个在线 CPU 注册 Perf 事件，触发 eBPF 采样。
7. **注册信号处理**：捕获 `SIGINT` 以优雅退出。
8. **主循环采样**：按间隔时间从 eBPF Map 读取数据。
9. **数据处理与输出**：根据模式打印直方图或队列占用率。
10. **资源清理**：销毁 BPF 链接、对象，释放 BTF 数据。

---

### **Hook 点与数据**
- **Hook 函数**：`do_sample`（eBPF 程序入口）。
- **触发方式**：通过 `PERF_COUNT_SW_CPU_CLOCK` 软中断定时触发。
- **有效信息**：
  - **CPU 编号**：区分不同核心的队列状态。
  - **运行队列长度**：从 `cfs_rq->nr_running` 或 `rq->nr_running` 读取（由 `env.host` 决定）。
  - **时间戳**：用于带时间标记的输出。

---

### **假设输入与输出**
- **输入示例**：`runqlen -C -T 1 5`
  - `-C`：按 CPU 分别显示。
  - `-T`：包含时间戳。
  - `1`：间隔 1 秒。
  - `5`：重复 5 次。
- **输出示例**：
  ```
  14:30:01
  cpu = 0
  runqlen     : count   distribution
  0           : 90      |****************************************|
  1           : 10      |*****                                   |
  ```

---

### **常见错误示例**
1. **权限不足**：未以 root 运行导致 BPF 加载失败。
   - 错误：`failed to load BPF object: Permission denied`
2. **内核版本过低**：缺少 CO-RE 支持。
   - 错误：`Memory-mapping BPF maps is supported starting from Linux 5.7`
3. **无效频率值**：`-f` 参数非正整数。
   - 错误：`Invalid freq (in hz): abc`
4. **CPU 核心过多**：超过编译时 `MAX_CPU_NR` 限制。
   - 错误：`increase MAX_CPU_NR's value and recompile`

---

### **Syscall 调试线索**
1. **`perf_event_open`**：注册性能事件，返回文件描述符。
   - **路径**：`syscall(__NR_perf_event_open, ...)`
   - **作用**：为每个 CPU 创建定时采样事件。
2. **`bpf_program__attach_perf_event`**：将 eBPF 程序附加到事件。
3. **`sleep`**：主循环中等待采样间隔。
4. **`bpf_map_lookup_elem`**（隐式）：用户态读取 eBPF Map 中的直方图数据。

---

### **关键代码路径**
1. **内核态**：
   - Perf 事件触发 → 调用 `do_sample` → 读取 `nr_running` → 更新直方图 Map。
2. **用户态**：
   - `main()` → 循环调用 `print_linear_hists()` → 从 Map 读取数据并重置统计。

通过此分析，开发者可快速定位采样逻辑、数据源及输出处理流程。
### 提示词
```
这是目录为bcc/libbpf-tools/runqlen.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
// Copyright (c) 2020 Wenbo Zhang
//
// Based on runqlen(8) from BCC by Brendan Gregg.
// 11-Sep-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "runqlen.h"
#include "runqlen.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define max(x, y) ({				 \
	typeof(x) _max1 = (x);			 \
	typeof(y) _max2 = (y);			 \
	(void) (&_max1 == &_max2);		 \
	_max1 > _max2 ? _max1 : _max2; })

struct env {
	bool per_cpu;
	bool runqocc;
	bool timestamp;
	bool host;
	time_t interval;
	int freq;
	int times;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
	.freq = 99,
};

static volatile bool exiting;

const char *argp_program_version = "runqlen 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize scheduler run queue length as a histogram.\n"
"\n"
"USAGE: runqlen [--help] [-C] [-O] [-T] [-f FREQUENCY] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    runqlen         # summarize run queue length as a histogram\n"
"    runqlen 1 10    # print 1 second summaries, 10 times\n"
"    runqlen -T 1    # 1s summaries and timestamps\n"
"    runqlen -O      # report run queue occupancy\n"
"    runqlen -C      # show each CPU separately\n"
"    runqlen -H      # show nr_running from host's rq instead of cfs_rq\n"
"    runqlen -f 199  # sample at 199HZ\n";

static const struct argp_option opts[] = {
	{ "cpus", 'C', NULL, 0, "Print output for each CPU separately", 0 },
	{ "frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency", 0 },
	{ "runqocc", 'O', NULL, 0, "Report run queue occupancy", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "host", 'H', NULL, 0, "Report nr_running from host's rq", 0 },
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
	case 'C':
		env.per_cpu = true;
		break;
	case 'O':
		env.runqocc = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'H':
		env.host = true;
		break;
	case 'f':
		errno = 0;
		env.freq = strtol(arg, NULL, 10);
		if (errno || env.freq <= 0) {
			fprintf(stderr, "Invalid freq (in hz): %s\n", arg);
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

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
			close(fd);
			return -1;
		}
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

static struct hist zero;

static void print_runq_occupancy(struct runqlen_bpf__bss *bss)
{
	struct hist hist;
	int slot, i = 0;
	float runqocc;

	do {
		__u64 samples, idle = 0, queued = 0;

		hist = bss->hists[i];
		bss->hists[i] = zero;
		for (slot = 0; slot < MAX_SLOTS; slot++) {
			__u64 val = hist.slots[slot];

			if (slot == 0)
				idle += val;
			else
				queued += val;
		}
		samples = idle + queued;
		runqocc = queued * 1.0 / max(1ULL, samples);
		if (env.per_cpu)
			printf("runqocc, CPU %-3d %6.2f%%\n", i,
				100 * runqocc);
		else
			printf("runqocc: %0.2f%%\n", 100 * runqocc);
	} while (env.per_cpu && ++i < nr_cpus);
}

static void print_linear_hists(struct runqlen_bpf__bss *bss)
{
	struct hist hist;
	int i = 0;

	do {
		hist = bss->hists[i];
		bss->hists[i] = zero;
		if (env.per_cpu)
			printf("cpu = %d\n", i);
		print_linear_hist(hist.slots, MAX_SLOTS, 0, 1, "runqlen");
	} while (env.per_cpu && ++i < nr_cpus);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct runqlen_bpf *obj;
	struct tm *tm;
	char ts[32];
	int err, i;
	time_t t;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		printf("failed to get # of possible cpus: '%s'!\n",
		       strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile");
		return 1;
	}

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = runqlen_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_per_cpu = env.per_cpu;
	obj->rodata->targ_host = env.host;

	err = runqlen_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (!obj->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = open_and_attach_perf_event(env.freq, obj->progs.do_sample, links);
	if (err)
		goto cleanup;

	printf("Sampling run queue length... Hit Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);

	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		if (env.runqocc)
			print_runq_occupancy(obj->bss);
		else
			print_linear_hists(obj->bss);

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	for (i = 0; i < nr_cpus; i++)
		bpf_link__destroy(links[i]);
	runqlen_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
```