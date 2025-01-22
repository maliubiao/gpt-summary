Response:
### 功能概述
`tcpstates` 是一个基于 eBPF 的工具，用于追踪 TCP 会话状态变化及其持续时间。它能记录 TCP 连接从建立到关闭的所有状态跳变（如 `SYN_SENT` → `ESTABLISHED` → `FIN_WAIT1` 等），并输出状态切换的时间差、源/目的地址、端口、进程 PID 等关键信息。

---

### 执行顺序（分 10 步）
1. **参数解析**  
   解析命令行参数（如 `-T` 时间戳、`-L` 过滤本地端口、`-D` 过滤远程端口等），设置过滤条件。

2. **初始化 libbpf**  
   配置 libbpf 的日志输出函数，根据 `verbose` 参数控制调试信息。

3. **加载 BTF 信息**  
   调用 `ensure_core_btf` 确保内核 BTF 信息可用，支持 CO-RE（一次编译，到处运行）。

4. **打开并加载 BPF 对象**  
   通过 `tcpstates_bpf__open_opts` 打开 BPF 程序，设置过滤条件（地址族、端口），加载到内核。

5. **更新端口过滤映射**  
   若指定了 `-L` 或 `-D`，将目标端口写入 BPF 映射 `sports`/`dports`，供内核过滤使用。

6. **附加 BPF 程序到 Hook 点**  
   将 BPF 程序挂载到内核的 `tcp_set_state` 函数，监听 TCP 状态变化事件。

7. **初始化 Perf 缓冲区**  
   创建 Perf 缓冲区用于接收内核事件，设置回调函数 `handle_event` 处理数据。

8. **注册信号处理**  
   捕获 `SIGINT` 信号，优雅退出主循环。

9. **输出表头**  
   根据参数（如 `-T` 时间戳、`-w` 宽输出）打印输出表头。

10. **事件轮询与处理**  
    主循环调用 `perf_buffer__poll` 监听事件，触发回调函数输出详细信息，直到收到退出信号。

---

### eBPF Hook 点与数据
- **Hook 点**  
  **内核函数**: `tcp_set_state(struct sock *sk, int state)`  
  **类型**: Kprobe 或 Tracepoint（代码未直接展示，但通过 `tcpstates.skel.h` 推断）  
  **作用**: 当 TCP 连接状态变化时触发，记录旧状态 `oldstate` 和新状态 `newstate`。

- **读取的有效信息**  
  - **Socket 地址** (`skaddr`): 内核中 socket 结构体的内存地址，用于唯一标识连接。
  - **进程 PID** (`pid`): 发起 TCP 连接的进程 PID。
  - **源/目的 IP** (`saddr`, `daddr`): IPv4/IPv6 地址，格式化为字符串（如 `192.168.1.1`）。
  - **源/目的端口** (`sport`, `dport`): 本地和远程端口号。
  - **状态变化时间差** (`delta_us`): 状态持续时长（微秒），转换为毫秒输出。

---

### 逻辑推理示例
**假设输入**:  
用户执行 `tcpstates -L 80 -T`，监控本地端口 80 的 TCP 状态变化，并包含时间戳。

**输出示例**:  
```
TIME(s)  SKADDR           PID     COMM     IP  LADDR           LPORT  RADDR           RPORT  OLDSTATE    -> NEWSTATE     MS
08:30:15 ffff9a8e1a8e0000 1234    nginx    4   192.168.1.100   80     10.0.0.2        54321  ESTABLISHED -> CLOSE_WAIT   150.500
```
**推理**:  
一个 PID 为 1234 的 nginx 进程，本地端口 80 的连接在 150.5 毫秒前从 `ESTABLISHED` 变为 `CLOSE_WAIT`，可能因客户端主动关闭连接（发送 FIN）。

---

### 常见使用错误
1. **无效端口号**  
   **错误示例**: `tcpstates -L 99999`  
   **原因**: 端口号超出 1-65535 范围，触发参数解析错误。

2. **权限不足**  
   **错误示例**: 非 root 用户运行，导致 BPF 程序加载失败。  
   **解决**: 使用 `sudo` 执行。

3. **过滤条件冲突**  
   **错误示例**: 同时指定 `-4` 和 `-6`，后者覆盖前者，仅监控 IPv6。

4. **未处理的事件丢失**  
   **现象**: 高负载时部分事件丢失，需调整 `PERF_BUFFER_PAGES` 或优化过滤条件。

---

### Syscall 到达 Hook 点的路径
1. **应用层调用 Syscall**  
   如 `close()` 触发 TCP 连接关闭，或 `connect()` 发起连接。

2. **内核协议栈处理**  
   Syscall 进入内核后，TCP 协议栈更新连接状态，调用 `tcp_set_state`。

3. **触发 eBPF 程序**  
   `tcp_set_state` 被 Kprobe 拦截，执行附加的 BPF 代码，记录状态变化和时间戳。

4. **数据上报用户态**  
   BPF 程序通过 Perf 缓冲区将事件发送到用户态，`handle_event` 处理并输出。

---

### 调试线索
1. **检查 BPF 加载错误**  
   若 `tcpstates_bpf__load` 失败，启用 `verbose` 模式查看 libbpf 日志。

2. **确认 Hook 点有效性**  
   通过 `/proc/kallsyms` 查找 `tcp_set_state` 地址，确保函数存在。

3. **验证过滤条件**  
   检查 `sports`/`dports` 映射内容，确认端口过滤生效。

4. **分析事件丢失**  
   若 `handle_lost_events` 被频繁调用，增大 `PERF_BUFFER_PAGES` 或减少监控范围。
Prompt: 
```
这是目录为bcc/libbpf-tools/tcpstates.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * tcpstates    Trace TCP session state changes with durations.
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on tcpstates(8) from BCC by Brendan Gregg.
 * 18-Dec-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "btf_helpers.h"
#include "tcpstates.h"
#include "tcpstates.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static short target_family = 0;
static char *target_sports = NULL;
static char *target_dports = NULL;
static bool wide_output = false;
static bool verbose = false;
static const char *tcp_states[] = {
	[1] = "ESTABLISHED",
	[2] = "SYN_SENT",
	[3] = "SYN_RECV",
	[4] = "FIN_WAIT1",
	[5] = "FIN_WAIT2",
	[6] = "TIME_WAIT",
	[7] = "CLOSE",
	[8] = "CLOSE_WAIT",
	[9] = "LAST_ACK",
	[10] = "LISTEN",
	[11] = "CLOSING",
	[12] = "NEW_SYN_RECV",
	[13] = "UNKNOWN",
};

const char *argp_program_version = "tcpstates 1.0";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace TCP session state changes and durations.\n"
"\n"
"USAGE: tcpstates [-4] [-6] [-T] [-L lport] [-D dport]\n"
"\n"
"EXAMPLES:\n"
"    tcpstates                  # trace all TCP state changes\n"
"    tcpstates -T               # include timestamps\n"
"    tcpstates -L 80            # only trace local port 80\n"
"    tcpstates -D 80            # only trace remote port 80\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 family only", 0 },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 family only", 0 },
	{ "wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)", 0 },
	{ "localport", 'L', "LPORT", 0, "Comma-separated list of local ports to trace.", 0 },
	{ "remoteport", 'D', "DPORT", 0, "Comma-separated list of remote ports to trace.", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long port_num;
	char *port;

	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'T':
		emit_timestamp = true;
		break;
	case '4':
		target_family = AF_INET;
		break;
	case '6':
		target_family = AF_INET6;
		break;
	case 'w':
		wide_output = true;
		break;
	case 'L':
		if (!arg) {
			warn("No ports specified\n");
			argp_usage(state);
		}
		target_sports = strdup(arg);
		port = strtok(arg, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			if (errno || port_num <= 0 || port_num > 65536) {
				warn("Invalid ports: %s\n", arg);
				argp_usage(state);
			}
			port = strtok(NULL, ",");
		}
		break;
	case 'D':
		if (!arg) {
			warn("No ports specified\n");
			argp_usage(state);
		}
		target_dports = strdup(arg);
		port = strtok(arg, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			if (errno || port_num <= 0 || port_num > 65536) {
				warn("Invalid ports: %s\n", arg);
				argp_usage(state);
			}
			port = strtok(NULL, ",");
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	char ts[32], saddr[39], daddr[39];
	struct event e;
	struct tm *tm;
	int family;
	time_t t;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%8s ", ts);
	}

	inet_ntop(e.family, &e.saddr, saddr, sizeof(saddr));
	inet_ntop(e.family, &e.daddr, daddr, sizeof(daddr));
	if (wide_output) {
		family = e.family == AF_INET ? 4 : 6;
		printf("%-16llx %-7d %-16s %-2d %-39s %-5d %-39s %-5d %-11s -> %-11s %.3f\n",
		       e.skaddr, e.pid, e.task, family, saddr, e.sport, daddr, e.dport,
		       tcp_states[e.oldstate], tcp_states[e.newstate], (double)e.delta_us / 1000);
	} else {
		printf("%-16llx %-7d %-10.10s %-15s %-5d %-15s %-5d %-11s -> %-11s %.3f\n",
		       e.skaddr, e.pid, e.task, saddr, e.sport, daddr, e.dport,
		       tcp_states[e.oldstate], tcp_states[e.newstate], (double)e.delta_us / 1000);
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct tcpstates_bpf *obj;
	int err, port_map_fd;
	short port_num;
	char *port;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = tcpstates_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->filter_by_sport = target_sports != NULL;
	obj->rodata->filter_by_dport = target_dports != NULL;
	obj->rodata->target_family = target_family;

	err = tcpstates_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (target_sports) {
		port_map_fd = bpf_map__fd(obj->maps.sports);
		port = strtok(target_sports, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}
	if (target_dports) {
		port_map_fd = bpf_map__fd(obj->maps.dports);
		port = strtok(target_dports, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}

	err = tcpstates_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = - errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	if (wide_output)
		printf("%-16s %-7s %-16s %-2s %-39s %-5s %-39s %-5s %-11s -> %-11s %s\n",
		       "SKADDR", "PID", "COMM", "IP", "LADDR", "LPORT",
		       "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS");
	else
		printf("%-16s %-7s %-10s %-15s %-5s %-15s %-5s %-11s -> %-11s %s\n",
		       "SKADDR", "PID", "COMM", "LADDR", "LPORT",
		       "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	tcpstates_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}

"""

```