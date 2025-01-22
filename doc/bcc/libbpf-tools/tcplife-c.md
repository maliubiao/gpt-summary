Response:
### tcplife 功能
该 eBPF 程序用于追踪 TCP 会话的生命周期，记录连接建立和终止的时间、源/目的地址端口、数据传输量（发送和接收字节数）以及连接持续时间。支持按 PID、IPv4/IPv6、本地/远程端口过滤。

---

### **执行顺序（10 步）**
1. **参数解析**：解析命令行参数（如 PID、IP 版本、端口过滤等），设置过滤条件。
2. **BTF 验证**：确保内核支持 BTF（BPF Type Format），用于 CO-RE（Compile Once-Run Everywhere）。
3. **加载 BPF 对象**：打开并加载编译好的 `tcplife.bpf.o` eBPF 程序。
4. **配置过滤条件**：将用户输入的端口列表（如 `-L 80,443`）写入 eBPF 程序的全局变量。
5. **附加 BPF 程序**：将 eBPF 程序挂载到内核的 TCP 状态变更钩子（如 `tcp_set_state`）。
6. **初始化 Perf Buffer**：创建 Perf Buffer 用于接收内核发送的事件数据。
7. **注册信号处理**：捕获 `SIGINT` 信号以优雅退出。
8. **输出表头**：根据参数打印输出结果的标题行（如时间戳、PID、地址等）。
9. **事件循环**：持续轮询 Perf Buffer，处理 TCP 连接事件或丢失事件。
10. **清理资源**：收到退出信号后，释放 Perf Buffer 和 BPF 对象。

---

### **eBPF Hook 点与信息**
1. **Hook 函数**：
   - `tcp_set_state`（内核函数，TCP 状态变更时调用）
   
2. **读取的有效信息**：
   - `struct sock *sk`：TCP Socket 对象，包含地址、端口、PID 等。
   - `saddr`/`daddr`：源/目的 IP 地址（IPv4 或 IPv6）。
   - `sport`/`dport`：源/目的端口号。
   - `pid_t pid`：当前进程 PID。
   - `comm`：进程名称（如 `nginx`）。
   - `tx_bytes`/`rx_bytes`：发送/接收的字节数（通过 socket 统计）。

---

### **假设输入与输出**
- **输入**：`sudo tcplife -p 1234 -4 -L 80,443`
  - 含义：仅追踪 PID 1234 的 IPv4 TCP 连接，且本地端口为 80 或 443。
- **输出示例**：
  ```
  PID    COMM           LADDR           LPORT RADDR           RPORT TX_KB  RX_KB  MS
  1234   curl           192.168.1.2     80    93.184.216.34   443   12.34  56.78  105.00
  ```
  - 含义：PID 1234 的 `curl` 进程与 `93.184.216.34:443` 的 TCP 连接，传输 12.34 KB 发送、56.78 KB 接收，持续 105 毫秒。

---

### **常见使用错误**
1. **无效 PID**：
   ```bash
   tcplife -p invalid_pid  # 错误：PID 必须为数字。
   ```
2. **端口格式错误**：
   ```bash
   tcplife -L "80 443"    # 错误：应用逗号分隔，如 `-L 80,443`。
   ```
3. **冲突过滤条件**：
   ```bash
   tcplife -4 -6          # 错误：同时指定 IPv4/IPv6，后者覆盖前者。
   ```

---

### **Syscall 到达 Hook 的调试线索**
1. **应用层**：进程调用 `connect()` 或 `accept()` 发起 TCP 连接。
2. **内核协议栈**：
   - TCP 状态机变更（如 `SYN_SENT` → `ESTABLISHED` → `CLOSED`）。
   - 调用 `tcp_set_state()` 更新状态。
3. **eBPF 触发**：
   - `tcp_set_state` 被 eBPF 程序挂钩，记录连接开始（如 `ESTABLISHED`）和结束（如 `CLOSED`）时间。
   - 通过 `bpf_perf_event_output()` 将事件发送到用户空间。

**调试方法**：
- 使用 `bpftrace` 验证 `tcp_set_state` 是否被正确挂钩：
  ```bash
  bpftrace -e 'k:tcp_set_state { printf("PID %d: state=%d\n", pid, arg2); }'
  ```
- 检查 eBPF 程序的 Verifier 日志（需启用 `verbose` 模式）。
Prompt: 
```
这是目录为bcc/libbpf-tools/tcplife.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: GPL-2.0

/*
 * tcplife      Trace the lifespan of TCP sessions and summarize.
 *
 * Copyright (c) 2022 Hengqi Chen
 *
 * Based on tcplife(8) from BCC by Brendan Gregg.
 * 02-Jun-2022   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "btf_helpers.h"
#include "tcplife.h"
#include "tcplife.skel.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static short target_family = 0;
static char *target_sports = NULL;
static char *target_dports = NULL;
static int column_width = 15;
static bool emit_timestamp = false;
static bool verbose = false;

const char *argp_program_version = "tcplife 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace the lifespan of TCP sessions and summarize.\n"
"\n"
"USAGE: tcplife [-h] [-p PID] [-4] [-6] [-L] [-D] [-T] [-w]\n"
"\n"
"EXAMPLES:\n"
"    tcplife -p 1215             # only trace PID 1215\n"
"    tcplife -p 1215 -4          # trace IPv4 only\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 only", 0 },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 only", 0 },
	{ "wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)", 0 },
	{ "time", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "localport", 'L', "LOCALPORT", 0, "Comma-separated list of local ports to trace.", 0 },
	{ "remoteport", 'D', "REMOTEPORT", 0, "Comma-separated list of remote ports to trace.", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long n;

	switch (key) {
	case 'p':
		errno = 0;
		n = strtol(arg, NULL, 10);
		if (errno || n <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = n;
		break;
	case '4':
		target_family = AF_INET;
		break;
	case '6':
		target_family = AF_INET6;
		break;
	case 'w':
		column_width = 39;
		break;
	case 'L':
		target_sports = strdup(arg);
		break;
	case 'D':
		target_dports = strdup(arg);
		break;
	case 'T':
		emit_timestamp = true;
		break;
	case 'v':
		verbose = true;
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
	char ts[32], saddr[48], daddr[48];
	struct event e;
	struct tm *tm;
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

	printf("%-7d %-16s %-*s %-5d %-*s %-5d %-6.2f %-6.2f %-.2f\n",
	       e.pid, e.comm, column_width, saddr, e.sport, column_width, daddr, e.dport,
	       (double)e.tx_b / 1024, (double)e.rx_b / 1024, (double)e.span_us / 1000);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct tcplife_bpf *obj;
	struct perf_buffer *pb = NULL;
	short port_num;
	char *port;
	int err, i;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = tcplife_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->target_family = target_family;

	if (target_sports) {
		i = 0;
		port = strtok(target_sports, ",");
		while (port && i < MAX_PORTS) {
			port_num = strtol(port, NULL, 10);
			obj->rodata->target_sports[i++] = port_num;
			port = strtok(NULL, ",");
		}
		obj->rodata->filter_sport = true;
	}

	if (target_dports) {
		i = 0;
		port = strtok(target_dports, ",");
		while (port && i < MAX_PORTS) {
			port_num = strtol(port, NULL, 10);
			obj->rodata->target_dports[i++] = port_num;
			port = strtok(NULL, ",");
		}
		obj->rodata->filter_dport = true;
	}

	err = tcplife_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcplife_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
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

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-16s %-*s %-5s %-*s %-5s %-6s %-6s %-s\n",
	       "PID", "COMM", column_width, "LADDR", "LPORT", column_width, "RADDR", "RPORT",
	       "TX_KB", "RX_KB", "MS");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	tcplife_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	return err != 0;
}

"""

```