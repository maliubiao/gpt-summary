Response:
### 功能概述
`tcppktlat` 用于追踪 **TCP 数据包从内核接收（网络栈处理完成）到被用户态线程读取的延迟**，帮助诊断网络应用因内核-用户态数据传递导致的性能问题。

---

### 执行顺序（10 步）
1. **参数解析**：解析命令行参数（如 PID、TID、端口过滤、时间戳等）。
2. **BPF 对象初始化**：打开并配置 BPF 程序（`tcppktlat_bpf__open`）。
3. **条件过滤设置**：设置过滤条件（PID、TID、端口、最小延迟阈值）。
4. **内核兼容性检查**：检测是否支持 BTF，选择加载对应的 BPF 程序。
5. **加载 BPF 程序**：将 BPF 字节码加载到内核（`tcppktlat_bpf__load`）。
6. **挂载 BPF 钩子**：将 BPF 程序附加到内核事件（`tcppktlat_bpf__attach`）。
7. **事件缓冲区初始化**：创建环形缓冲区/Perf 缓冲区接收事件。
8. **信号处理**：注册 `SIGINT` 信号处理器，支持优雅退出。
9. **事件轮询循环**：持续从缓冲区读取事件并格式化输出。
10. **资源清理**：退出时释放缓冲区并销毁 BPF 对象。

---

### eBPF Hook 点与信息提取
| Hook 点                | 函数名                          | 有效信息                          | 信息说明                          |
|------------------------|-------------------------------|----------------------------------|---------------------------------|
| `tcp_probe` 跟踪点      | `tcp_probe` 或 `tcp_probe_btf` | TCP 数据包元数据（地址、端口、序列号） | 内核收到 TCP 数据包的时间戳（`tstamp`） |
| `tcp_rcv_space_adjust` | 同名函数或 BTF 版本             | Socket 接收缓冲区状态              | 用户态读取数据后的时间戳（`rcvq_space`）|
| `tcp_destroy_sock`     | 同名函数或 BTF 版本             | Socket 销毁事件                   | 清理关联的 BPF Map 条目           |

#### 关键数据：
- **IP 地址与端口**：`saddr`、`daddr`、`sport`、`dport`（网络字节序）。
- **进程信息**：`pid`（进程 ID）、`tid`（线程 ID）、`comm`（进程名）。
- **延迟计算**：`delta_us = rcvq_time - tstamp`（单位：微秒）。

---

### 逻辑推理示例
- **输入**：TCP 数据包到达内核（触发 `tcp_probe`），随后用户线程调用 `recvmsg()` 读取数据（触发 `tcp_rcv_space_adjust`）。
- **输出**：`delta_us = 用户读取时间 - 内核接收时间`，若超过 `env.min_us` 则记录事件。
- **假设**：若 `delta_us` 显著高于预期，可能表明用户态线程调度延迟或应用未及时读取数据。

---

### 常见使用错误
1. **权限不足**：未以 `root` 运行导致 BPF 加载失败。
   - 错误示例：`failed to load BPF object: Operation not permitted`。
   - 解决：使用 `sudo` 运行。
2. **无效过滤参数**：指定不存在的 PID 或端口。
   - 错误示例：`Invalid PID: 9999`（PID 不存在）。
3. **内核不支持 BTF**：未开启 `CONFIG_DEBUG_INFO_BTF` 导致兼容性回退失败。
   - 错误日志：`maybe your kernel doesn't support bpf_get_socket_cookie`。

---

### Syscall 到达 Hook 的调试线索
1. **用户调用 `recvmsg()`**：用户线程发起系统调用读取 TCP 数据。
2. **内核协议栈处理**：数据从内核接收队列复制到用户缓冲区。
3. **触发 `tcp_rcv_space_adjust`**：调整接收窗口时记录用户态读取时间。
4. **BPF 程序计算延迟**：通过 `tstamp`（内核接收时间）和 `rcvq_time`（用户读取时间）计算差值。
5. **事件上报用户态**：通过 Perf 缓冲区将 `struct event` 发送到 `tcppktlat` 进程。

---

### 调试建议
1. **启用详细日志**：添加 `-v` 参数查看 BPF 加载细节。
2. **检查内核版本**：确认内核支持 `bpf_get_socket_cookie`。
3. **过滤条件验证**：逐步添加 `-p`、`-t`、`-l` 等参数缩小问题范围。
### 提示词
```
这是目录为bcc/libbpf-tools/tcppktlat.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tcppktlat.h"
#include "tcppktlat.skel.h"
#include "compat.h"
#include "trace_helpers.h"

static struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	__u16 lport;
	__u16 rport;
	bool timestamp;
	bool verbose;
} env = {};

static volatile sig_atomic_t exiting = 0;
static int column_width = 15;

const char *argp_program_version = "tcppktlat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace latency between TCP received pkt and picked up by userspace thread.\n"
"\n"
"USAGE: tcppktlat [--help] [-T] [-p PID] [-t TID] [-l LPORT] [-r RPORT] [-w] [-v]\n"
"\n"
"EXAMPLES:\n"
"    tcppktlat             # Trace all TCP packet picked up latency\n"
"    tcppktlat -T          # summarize with timestamps\n"
"    tcppktlat -p          # filter for pid\n"
"    tcppktlat -t          # filter for tid\n"
"    tcppktlat -l          # filter for local port\n"
"    tcppktlat -r          # filter for remote port\n"
"    tcppktlat 1000        # filter for latency higher than 1000us";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread TID to trace", 0 },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "lport", 'l', "LPORT", 0, "filter for local port", 0 },
	{ "rport", 'r', "RPORT", 0, "filter for remote port", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	long long min_us;
	int pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.timestamp = true;
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
	case 'l':
		errno = 0;
		env.lport = strtoul(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid lport: %s\n", arg);
			argp_usage(state);
		}
		env.lport = htons(env.lport);
		break;
	case 'r':
		errno = 0;
		env.rport = strtoul(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid rport: %s\n", arg);
			argp_usage(state);
		}
		env.rport = htons(env.rport);
		break;
	case 'w':
		column_width = 26;
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char saddr[48], daddr[48];
	struct tm *tm;
	char ts[32];
	time_t t;

	if (env.timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s ", ts);
	}
	inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
	inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));

	printf("%-7d %-7d %-16s %-*s %-5d %-*s %-5d %-.2f\n",
		e->pid, e->tid, e->comm, column_width, saddr, ntohs(e->sport), column_width, daddr,
		ntohs(e->dport), e->delta_us / 1000.0);

	return 0;
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
	struct bpf_buffer *buf = NULL;
	struct tcppktlat_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = tcppktlat_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->targ_tid = env.tid;
	obj->rodata->targ_sport = env.lport;
	obj->rodata->targ_dport = env.rport;
	obj->rodata->targ_min_us = env.min_us;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		fprintf(stderr, "failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (probe_tp_btf("tcp_probe")) {
		bpf_program__set_autoload(obj->progs.tcp_probe, false);
		bpf_program__set_autoload(obj->progs.tcp_rcv_space_adjust, false);
		bpf_program__set_autoload(obj->progs.tcp_destroy_sock, false);
	} else {
		bpf_program__set_autoload(obj->progs.tcp_probe_btf, false);
		bpf_program__set_autoload(obj->progs.tcp_rcv_space_adjust_btf, false);
		bpf_program__set_autoload(obj->progs.tcp_destroy_sock_btf, false);
	}

	err = tcppktlat_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d, maybe your kernel doesn't support `bpf_get_socket_cookie`\n", err);
		goto cleanup;
	}

	err = tcppktlat_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		fprintf(stderr, "failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-7s %-16s %-*s %-5s %-*s %-5s %-s\n",
		"PID", "TID", "COMM", column_width, "LADDR", "LPORT", column_width, "RADDR", "RPORT", "MS");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling ring/perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}
cleanup:
	bpf_buffer__free(buf);
	tcppktlat_bpf__destroy(obj);

	return err != 0;
}
```