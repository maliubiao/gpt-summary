Response:
### 功能概述
`drsnoop.c` 是一个基于 eBPF 的工具，用于跟踪 Linux 内核中的 **直接内存回收（Direct Reclaim）事件**，记录其延迟、回收页数等关键指标，帮助分析内存性能问题。

---

### 执行顺序（10 步）
1. **解析命令行参数**  
   使用 `argp` 库处理 `-p` (PID)、`-t` (TID)、`-d` (持续时间)、`-e` (扩展输出) 等选项。

2. **初始化 eBPF 对象**  
   调用 `drsnoop_bpf__open()` 打开并解析 eBPF 程序骨架（skeleton），准备加载。

3. **配置过滤条件**  
   根据用户输入的 PID/TID 设置 `obj->rodata->targ_tgid` 和 `targ_pid`，用于内核端过滤事件。

4. **加载内核符号（可选）**  
   若启用 `-e` 扩展输出，加载 `vm_zone_stat` 内核符号地址，用于获取系统空闲内存信息。

5. **动态选择跟踪点**  
   通过 `probe_tp_btf()` 检测内核是否支持 `mm_vmscan_direct_reclaim_begin` 跟踪点，动态启用 BTF 或传统跟踪点程序。

6. **加载并附加 eBPF 程序**  
   调用 `drsnoop_bpf__load()` 和 `drsnoop_bpf__attach()` 将 eBPF 程序挂载到内核钩子点。

7. **初始化 Perf 缓冲区**  
   创建 Perf Buffer 用于接收内核发送的事件数据，设置回调函数 `handle_event` 和 `handle_lost_events`。

8. **设置信号处理与超时**  
   注册 `SIGINT` 信号处理函数，若指定 `-d` 参数则计算结束时间戳。

9. **事件轮询循环**  
   持续调用 `perf_buffer__poll()` 等待事件，超时或收到信号后退出循环。

10. **清理资源**  
    释放 Perf Buffer、销毁 eBPF 对象、卸载内核符号表。

---

### eBPF Hook 点与信息
| Hook 点                          | 类型           | 捕获信息                                  | 用途                          |
|----------------------------------|---------------|-----------------------------------------|-----------------------------|
| `mm_vmscan_direct_reclaim_begin` | Tracepoint    | 进程 PID/TID、任务名、开始时间戳              | 记录回收开始时间，计算延迟           |
| `mm_vmscan_direct_reclaim_end`   | Tracepoint    | 结束时间戳、回收页数 (`nr_reclaimed`)、空闲页数 | 计算延迟，统计回收效果，关联开始事件      |

**有效信息：**
- **进程信息**: PID、TID、进程名 (`e.task`)
- **延迟数据**: `delta_ns` (开始到结束的纳秒差)
- **内存指标**: `nr_reclaimed` (回收的页数), `nr_free_pages` (系统空闲页数，需 `-e` 选项)

---

### 逻辑推理示例
**假设输入**:  
```bash
sudo drsnoop -p 1234 -e
```

**假设输出**:  
```
TIME     COMM             TID    LAT(ms)  PAGES  FREE(KB)
14:30:01 process_A        1234   5.234    1024   20480
```

**推理过程**:  
1. 进程 1234 触发内存分配，但系统空闲内存不足。
2. 内核调用直接回收函数，`begin` 和 `end` 钩子捕获事件。
3. eBPF 程序计算时间差 (`5.234ms`) 并记录回收 1024 页。
4. 扩展模式 (`-e`) 读取 `vm_zone_stat` 得到系统空闲内存为 20480 KB。

---

### 常见使用错误
1. **权限不足**  
   错误: `failed to load BPF object: Permission denied`  
   解决: 使用 `sudo` 运行，或授予用户 CAP_BPF 权限。

2. **无效 PID/TID**  
   错误: `invalid PID: 99999` (PID 不存在)  
   解决: 使用 `ps` 确认目标进程/线程状态。

3. **内核不支持 BTF**  
   错误: `failed to attach BPF programs`  
   解决: 升级内核至 5.10+ 并启用 `CONFIG_DEBUG_INFO_BTF`。

---

### Syscall 调试线索
1. **用户进程调用内存分配函数**  
   如 `malloc() -> brk()` 或 `mmap()`，触发缺页异常。

2. **内核检测内存不足**  
   `__alloc_pages_slowpath()` 调用 `try_to_free_pages()` 触发直接回收。

3. **进入直接回收路径**  
   内核执行 `direct_reclaim()`，触发 `mm_vmscan_direct_reclaim_begin/end` 跟踪点。

4. **eBPF 程序捕获事件**  
   记录时间戳、PID 等数据，通过 Perf Buffer 发送到用户空间。

**调试建议**:  
- 使用 `strace -e brk,mmap` 跟踪目标进程的内存分配。
- 结合 `/proc/vmstat` 监控 `pgsteal_direct` 指标验证回收次数。
Prompt: 
```
这是目录为bcc/libbpf-tools/drsnoop.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
// Based on drsnoop(8) from BCC by Wenbo Zhang.
// 28-Feb-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "drsnoop.h"
#include "drsnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static struct env {
	pid_t pid;
	pid_t tid;
	time_t duration;
	bool extended;
	bool verbose;
} env = { };

const char *argp_program_version = "drsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace direct reclaim latency.\n"
"\n"
"USAGE: drsnoop [--help] [-p PID] [-t TID] [-d DURATION] [-e]\n"
"\n"
"EXAMPLES:\n"
"    drsnoop         # trace all direct reclaim events\n"
"    drsnoop -p 123  # trace pid 123\n"
"    drsnoop -t 123  # trace tid 123 (use for threads only)\n"
"    drsnoop -d 10   # trace for 10 seconds only\n"
"    drsnoop -e      # trace all direct reclaim events with extended faileds\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds", 0 },
	{ "extended", 'e', NULL, 0, "Extended fields output", 0 },
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread TID to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static int page_size;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	time_t duration;
	int pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			fprintf(stderr, "invalid DURATION: %s\n", arg);
			argp_usage(state);
		}
		env.duration = duration;
		break;
	case 'e':
		env.extended = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
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
	printf("%-8s %-16s %-6d %8.3f %5lld",
	       ts, e.task, e.pid, e.delta_ns / 1000000.0,
	       e.nr_reclaimed);
	if (env.extended)
		printf(" %8llu", e.nr_free_pages * page_size / 1024);
	printf("\n");
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
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
	struct perf_buffer *pb = NULL;
	struct ksyms *ksyms = NULL;
	const struct ksym *ksym;
	struct drsnoop_bpf *obj;
	__u64 time_end = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = drsnoop_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	if (env.extended) {
		ksyms = ksyms__load();
		if (!ksyms) {
			fprintf(stderr, "failed to load kallsyms\n");
			goto cleanup;
		}
		ksym = ksyms__get_symbol(ksyms, "vm_zone_stat");
		if (!ksym) {
			fprintf(stderr, "failed to get vm_zone_stat's addr\n");
			goto cleanup;
		}
		obj->rodata->vm_zone_stat_kaddr = ksym->addr;
		page_size = sysconf(_SC_PAGESIZE);
	}

	if (probe_tp_btf("mm_vmscan_direct_reclaim_begin")) {
		bpf_program__set_autoload(obj->progs.direct_reclaim_begin, false);
		bpf_program__set_autoload(obj->progs.direct_reclaim_end, false);
	} else {
		bpf_program__set_autoload(obj->progs.direct_reclaim_begin_btf, false);
		bpf_program__set_autoload(obj->progs.direct_reclaim_end_btf, false);
	}

	err = drsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = drsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing direct reclaim events");
	if (env.duration)
		printf(" for %ld secs.\n", env.duration);
	else
		printf("... Hit Ctrl-C to end.\n");
	printf("%-8s %-16s %-6s %8s %5s",
		"TIME", "COMM", "TID", "LAT(ms)", "PAGES");
	if (env.extended)
		printf(" %8s", "FREE(KB)");
	printf("\n");

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	drsnoop_bpf__destroy(obj);
	ksyms__free(ksyms);

	return err != 0;
}

"""

```