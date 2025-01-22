Response:
### 功能列举
1. **测量 CPU 时间分布**：统计任务在 CPU 上的时间（`on-CPU`）或被调度离开的时间（`off-CPU`），生成直方图。
2. **多维度分类**：支持按进程（`-P`）、线程（`-L`）或全局汇总。
3. **过滤条件**：可指定 PID（`-p PID`）或 cgroup（`-c CG`）过滤任务。
4. **时间单位选择**：支持微秒（默认）或毫秒（`-m`）单位。
5. **动态追踪**：通过 eBPF 动态挂载内核函数，零性能损耗。
6. **时间戳输出**：`-T` 参数显示每次统计的时间戳。
7. **高频采样**：通过 `interval` 和 `count` 参数控制采样频率。
8. **调试支持**：`-v` 输出详细的 eBPF 加载日志。
9. **跨版本适配**：自动选择 `sched_switch` 的跟踪点类型（TP 或 BTF）。
10. **资源管理**：自动清理 eBPF 占用的内核资源。

---

### 执行顺序（10 步骤）
1. **参数解析**：解析命令行参数（如 `-O`, `-p`, `-c`），设置过滤条件。
2. **初始化 eBPF 对象**：调用 `cpudist_bpf__open()` 加载 eBPF 程序骨架。
3. **选择跟踪点**：通过 `probe_tp_btf()` 检测内核是否支持 BTF，动态选择 `sched_switch` 实现。
4. **配置过滤参数**：将用户输入的 PID/cgroup 等参数写入 eBPF 程序的只读数据区。
5. **加载 eBPF 程序**：`cpudist_bpf__load()` 将程序载入内核并验证。
6. **挂载 cgroup**：若指定 `-c`，将 cgroup 路径的文件描述符注入 eBPF map。
7. **挂载钩子**：`cpudist_bpf__attach()` 将 eBPF 程序挂载到内核事件。
8. **主循环采样**：按 `interval` 定期从 eBPF map 中拉取直方图数据。
9. **输出结果**：调用 `print_log2_hists()` 格式化打印直方图。
10. **清理资源**：销毁 eBPF 对象并关闭文件描述符。

---

### eBPF Hook 点与信息
| Hook 点                | 函数名                   | 有效信息                            | 信息说明                     |
|------------------------|--------------------------|-------------------------------------|------------------------------|
| `sched_switch` 跟踪点  | `sched_switch_btf`/`tp` | `prev_pid`, `next_pid`, 时间戳       | 切换前的进程 PID、切换后的 PID |
| **读取数据**           | `start` map              | `key=pid`, `value=start_time`       | 进程/线程的 CPU 时间起点      |
| **写入数据**           | `hists` map              | `key=pid/tid`, `value=hist`         | 时间区间的直方图统计          |

---

### 假设输入与输出
**输入示例**：
```bash
sudo ./cpudist -O -P -m 1 5
```
- **参数解析**：测量 `off-CPU` 时间（`-O`），按进程分类（`-P`），毫秒单位（`-m`），每 1 秒输出一次，共 5 次。

**输出示例**：
```
pid=1234 (bash)
     msecs     : count     distribution
     0 -> 1     : 12      |****                    |
     2 -> 3     : 28      |***********             |
     4 -> 7     : 5       |**                      |
```
- **逻辑推理**：进程 1234（bash）在 off-CPU 状态的时间集中在 0-3 毫秒。

---

### 用户常见错误
1. **权限不足**：未以 root 运行导致 eBPF 加载失败。
   ```bash
   $ ./cpudist
   ERROR: failed to load BPF object: Permission denied
   ```
2. **无效 PID**：指定不存在的 PID。
   ```bash
   $ ./cpudist -p 99999
   invalid PID: 99999
   ```
3. **冲突参数**：同时指定 `-P`（按进程）和 `-L`（按线程）导致直方图重复。
4. **cgroup 路径错误**：指定不存在的 cgroup 路径。
   ```bash
   $ ./cpudist -c /invalid/path
   Failed opening Cgroup path: /invalid/path
   ```

---

### Syscall 调试线索
1. **进程调度触发**：当内核执行 `sched_switch` 时，触发 eBPF 程序。
   - **调用路径**：`schedule() -> __schedule() -> sched_switch 跟踪点`。
2. **数据记录**：
   - **挂载点**：在 `sched_switch` 记录 `prev_pid` 离开 CPU 的时间（off-CPU 开始）。
   - **计算差值**：下次切换回该进程时，计算时间差并更新直方图。
3. **调试技巧**：
   - 检查 `/sys/kernel/debug/tracing/trace_pipe` 查看 eBPF 输出。
   - 使用 `bpftool map dump` 查看 `start` 和 `hists` map 的内容。
Prompt: 
```
这是目录为bcc/libbpf-tools/cpudist.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
// Based on cpudist(8) from BCC by Brendan Gregg & Dina Goldshtein.
// 8-May-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cpudist.h"
#include "cpudist.skel.h"
#include "trace_helpers.h"

static struct env {
	time_t interval;
	pid_t pid;
	char *cgroupspath;
	bool cg;
	int times;
	bool offcpu;
	bool timestamp;
	bool per_process;
	bool per_thread;
	bool milliseconds;
	bool verbose;
} env = {
	.interval = 99999999,
	.pid = -1,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "cpudist 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize on-CPU time per task as a histogram.\n"
"\n"
"USAGE: cpudist [--help] [-O] [-T] [-m] [-P] [-L] [-p PID] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    cpudist              # summarize on-CPU time as a histogram"
"    cpudist -O           # summarize off-CPU time as a histogram"
"    cpudist -c CG        # Trace process under cgroupsPath CG\n"
"    cpudist 1 10         # print 1 second summaries, 10 times"
"    cpudist -mT 1        # 1s summaries, milliseconds, and timestamps"
"    cpudist -P           # show each PID separately"
"    cpudist -p 185       # trace PID 185 only";

static const struct argp_option opts[] = {
	{ "offcpu", 'O', NULL, 0, "Measure off-CPU time", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ "pids", 'P', NULL, 0, "Print a histogram per process ID", 0 },
	{ "tids", 'L', NULL, 0, "Print a histogram per thread ID", 0 },
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
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
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'O':
		env.offcpu = true;
		break;
	case 'P':
		env.per_process = true;
		break;
	case 'L':
		env.per_thread = true;
		break;
	case 'T':
		env.timestamp = true;
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

static int get_pid_max(void)
{
	int pid_max;
	FILE *f;

	f = fopen("/proc/sys/kernel/pid_max", "r");
	if (!f)
		return -1;
	if (fscanf(f, "%d\n", &pid_max) != 1)
		pid_max = -1;
	fclose(f);
	return pid_max;
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int print_log2_hists(int fd)
{
	char *units = env.milliseconds ? "msecs" : "usecs";
	__u32 lookup_key = -2, next_key;
	struct hist hist;
	int err;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_process)
			printf("\npid = %d %s\n", next_key, hist.comm);
		if (env.per_thread)
			printf("\ntid = %d %s\n", next_key, hist.comm);
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
	struct cpudist_bpf *obj;
	int pid_max, fd, err;
	struct tm *tm;
	char ts[32];
	time_t t;
	int idx, cg_map_fd;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = cpudist_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("sched_switch"))
		bpf_program__set_autoload(obj->progs.sched_switch_tp, false);
	else
		bpf_program__set_autoload(obj->progs.sched_switch_btf, false);

	/* initialize global data (filtering options) */
	obj->rodata->filter_cg = env.cg;
	obj->rodata->targ_per_process = env.per_process;
	obj->rodata->targ_per_thread = env.per_thread;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_offcpu = env.offcpu;
	obj->rodata->targ_tgid = env.pid;

	pid_max = get_pid_max();
	if (pid_max < 0) {
		fprintf(stderr, "failed to get pid_max\n");
		return 1;
	}

	bpf_map__set_max_entries(obj->maps.start, pid_max);
	if (!env.per_process && !env.per_thread)
		bpf_map__set_max_entries(obj->maps.hists, 1);
	else
		bpf_map__set_max_entries(obj->maps.hists, pid_max);

	err = cpudist_bpf__load(obj);
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

	err = cpudist_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	fd = bpf_map__fd(obj->maps.hists);

	signal(SIGINT, sig_handler);

	printf("Tracing %s-CPU time... Hit Ctrl-C to end.\n", env.offcpu ? "off" : "on");

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

		err = print_log2_hists(fd);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	cpudist_bpf__destroy(obj);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}

"""

```