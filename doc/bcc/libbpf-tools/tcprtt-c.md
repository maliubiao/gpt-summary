Response:
### 功能总结
`tcprtt.c` 是一个基于 eBPF 的工具，用于统计 TCP 连接的往返时间 (RTT) 并生成直方图。主要功能包括：
1. **动态过滤**：支持按本地/远程 IP、端口过滤监控目标。
2. **时间单位选择**：支持微秒或毫秒级统计。
3. **多维度聚合**：可按本地或远程地址聚合直方图。
4. **扩展统计**：可输出平均 RTT。
5. **持续监控**：支持定时输出和持续监控。

---

### 执行顺序（10 步骤）
1. **解析命令行参数**：通过 `argp_parse` 解析用户输入的过滤条件（如端口、IP）和输出选项。
2. **校验参数冲突**：检查 IPv4/IPv6 过滤条件是否同时存在（互斥）。
3. **初始化 eBPF 对象**：调用 `tcprtt_bpf__open()` 打开 eBPF 程序骨架。
4. **配置 eBPF 全局变量**：设置过滤条件（如 `targ_sport`）、统计模式到 eBPF 程序的 `rodata`。
5. **动态选择 Hook 点**：检查内核是否支持 `fentry`，选择 `tcp_rcv` 或 `tcp_rcv_kprobe` 作为入口。
6. **加载并附加 eBPF 程序**：通过 `tcprtt_bpf__load()` 和 `tcprtt_bpf__attach()` 完成。
7. **设置信号处理**：注册 `SIGINT` 处理函数，支持优雅退出。
8. **主循环轮询数据**：定时从 eBPF Map (`hists`) 中读取直方图数据。
9. **处理并打印数据**：调用 `print_map` 解析 Map 数据，生成人类可读的直方图。
10. **资源清理**：退出时销毁 eBPF 对象 (`tcprtt_bpf__destroy`)。

---

### eBPF Hook 点与数据
#### Hook 点
- **函数名**：`tcp_rcv_established`（通过 `fentry` 或 `kprobe` 挂载）。
- **触发场景**：当内核处理已建立连接的 TCP 数据包时触发。
- **有效信息**：
  - **进程 PID**：通过 `bpf_get_current_pid_tgid()` 获取（隐含在 eBPF 代码中）。
  - **Socket 信息**：本地/远程 IP 和端口（从 `struct sock*` 中提取）。
  - **时间戳**：记录数据包到达时间，用于计算 RTT。

---

### 逻辑推理示例
#### 输入与输出
- **输入命令**：`tcprtt -p 80 -m -T`
- **过滤条件**：监控本地端口 80 的 TCP 连接，以毫秒为单位，包含时间戳。
- **输出示例**：
  ```plaintext
  [15:30:45]
  Local Address = 192.168.1.100
  [AVG 120]
  msecs     : count    distribution
  0 -> 1    : 5       |*****             |
  2 -> 3    : 10      |**********        |
  ```

---

### 用户常见错误
1. **IPv4/IPv6 混合过滤**：同时指定 `-a` (IPv4) 和 IPv6 地址会报错。
   ```bash
   tcprtt -a 192.168.1.1 -a ::1  # 错误：不允许同时过滤 IPv4 和 IPv6
   ```
2. **无效端口号**：输入非数字端口导致解析失败。
   ```bash
   tcprtt -p http  # 错误：'http' 无法转换为数字端口
   ```

---

### Syscall 调试线索
1. **TCP 数据接收路径**：
   - 应用调用 `read()` → 系统调用进入内核 → `tcp_recvmsg()` → `tcp_rcv_established()`。
   - eBPF 程序在 `tcp_rcv_established` 处触发，记录当前时间戳。
2. **RTT 计算**：通过比较当前时间与之前记录的时间戳（可能在 ACK 到达时）计算差值。
3. **数据存储**：将 RTT 值写入 eBPF Map (`hists`)，用户空间程序定期读取并汇总。

---

### 关键代码段说明
- **过滤逻辑**：eBPF 程序通过比较 `sock->src_port`、`sock->dst` 等字段与全局变量 (`targ_sport`) 决定是否记录数据。
- **时间单位转换**：通过 `targ_ms` 标志位控制是否将 RTT 转换为毫秒。
- **直方图更新**：使用 `log2l` 计算 RTT 的分布区间，更新 `hist.slots` 数组。
### 提示词
```
这是目录为bcc/libbpf-tools/tcprtt.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
// Copyright (c) 2021 Wenbo Zhang
//
// Based on tcprtt(8) from BCC by zhenwei pi.
// 06-Aug-2021   Wenbo Zhang   Created this.
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <argp.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcprtt.h"
#include "tcprtt.skel.h"
#include "trace_helpers.h"

static struct env {
	__u16 lport;
	__u16 rport;
	__u32 laddr;
	__u32 raddr;
	__u8 laddr_v6[IPV6_LEN];
	__u8 raddr_v6[IPV6_LEN];
	bool milliseconds;
	time_t duration;
	time_t interval;
	bool timestamp;
	bool laddr_hist;
	bool raddr_hist;
	bool extended;
	bool verbose;
} env = {
	.interval = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "tcprtt 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize TCP RTT as a histogram.\n"
"\n"
"USAGE: \n"
"\n"
"EXAMPLES:\n"
"    tcprtt            # summarize TCP RTT\n"
"    tcprtt -i 1 -d 10 # print 1 second summaries, 10 times\n"
"    tcprtt -m -T      # summarize in millisecond, and timestamps\n"
"    tcprtt -p         # filter for local port\n"
"    tcprtt -P         # filter for remote port\n"
"    tcprtt -a         # filter for local address\n"
"    tcprtt -A         # filter for remote address\n"
"    tcprtt -b         # show sockets histogram by local address\n"
"    tcprtt -B         # show sockets histogram by remote address\n"
"    tcprtt -e         # show extension summary(average)\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "INTERVAL", 0, "summary interval, seconds", 0 },
	{ "duration", 'd', "DURATION", 0, "total duration of trace, seconds", 0 },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "millisecond", 'm', NULL, 0, "millisecond histogram", 0 },
	{ "lport", 'p', "LPORT", 0, "filter for local port", 0 },
	{ "rport", 'P', "RPORT", 0, "filter for remote port", 0 },
	{ "laddr", 'a', "LADDR", 0, "filter for local address", 0 },
	{ "raddr", 'A', "RADDR", 0, "filter for remote address", 0 },
	{ "byladdr", 'b', NULL, 0,
	  "show sockets histogram by local address", 0 },
	{ "byraddr", 'B', NULL, 0,
	  "show sockets histogram by remote address", 0 },
	{ "extension", 'e', NULL, 0, "show extension summary(average)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct in_addr addr;
	struct in6_addr addr_v6;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		errno = 0;
		env.interval = strtol(arg, NULL, 10);
		if (errno || env.interval <= 0) {
			fprintf(stderr, "invalid interval: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		errno = 0;
		env.lport = strtoul(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid lport: %s\n", arg);
			argp_usage(state);
		}
		env.lport = htons(env.lport);
		break;
	case 'P':
		errno = 0;
		env.rport = strtoul(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid rport: %s\n", arg);
			argp_usage(state);
		}
		env.rport = htons(env.rport);
		break;
	case 'a':
                if (strchr(arg, ':')) {
                        if (inet_pton(AF_INET6, arg, &addr_v6) < 1) {
                                fprintf(stderr, "invalid local IPv6 address: %s\n", arg);
                                argp_usage(state);
                        }
                        memcpy(env.laddr_v6, &addr_v6, sizeof(env.laddr_v6));
                } else {
                        if (inet_pton(AF_INET, arg, &addr) < 0) {
                                fprintf(stderr, "invalid local address: %s\n", arg);
                                argp_usage(state);
                        }
                        env.laddr = addr.s_addr;
                }
		break;
	case 'A':
                if (strchr(arg, ':')) {
                        if (inet_pton(AF_INET6, arg, &addr_v6) < 1) {
                                fprintf(stderr, "invalid remote address: %s\n", arg);
                                argp_usage(state);
                        }
                        memcpy(env.raddr_v6, &addr_v6, sizeof(env.raddr_v6));
                } else {
                        if (inet_pton(AF_INET, arg, &addr) < 0) {
                                fprintf(stderr, "invalid remote address: %s\n", arg);
                                argp_usage(state);
                        }
                        env.raddr = addr.s_addr;
                }
		break;
	case 'b':
		env.laddr_hist = true;
		break;
	case 'B':
		env.raddr_hist = true;
		break;
	case 'e':
		env.extended = true;
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

static int print_map(struct bpf_map *map)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	struct hist_key *lookup_key = NULL, next_key;
	int err, fd = bpf_map__fd(map);
	struct hist hist;

	while (!bpf_map_get_next_key(fd, lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}


		if (env.laddr_hist)
			printf("Local Address = ");
		else if (env.raddr_hist)
			printf("Remote Address = ");
		else
			printf("All Addresses = ****** ");

		if (env.laddr_hist || env.raddr_hist) {
			__u16 family = next_key.family;
			char str[INET6_ADDRSTRLEN];

			if (!inet_ntop(family, next_key.addr, str, sizeof(str))) {
				perror("converting IP to string:");
				return -1;
			}

			printf("%s ", str);
		}

		if (env.extended)
			printf("[AVG %llu]", hist.latency / hist.cnt);
		printf("\n");
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = &next_key;
	}

	lookup_key = NULL;
	while (!bpf_map_get_next_key(fd, lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup infos: %d\n", err);
			return -1;
		}
		lookup_key = &next_key;
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
	__u8 zero_addr_v6[IPV6_LEN] = {};
	struct tcprtt_bpf *obj;
	__u64 time_end = 0;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if ((env.laddr || env.raddr)
		&& (memcmp(env.laddr_v6, zero_addr_v6, sizeof(env.laddr_v6)) || memcmp(env.raddr_v6, zero_addr_v6, sizeof(env.raddr_v6)))) {
		fprintf(stderr, "It is not permitted to filter by both IPv4 and IPv6\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = tcprtt_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_laddr_hist = env.laddr_hist;
	obj->rodata->targ_raddr_hist = env.raddr_hist;
	obj->rodata->targ_show_ext = env.extended;
	obj->rodata->targ_sport = env.lport;
	obj->rodata->targ_dport = env.rport;
	obj->rodata->targ_saddr = env.laddr;
	obj->rodata->targ_daddr = env.raddr;
	memcpy(obj->rodata->targ_saddr_v6, env.laddr_v6, sizeof(obj->rodata->targ_saddr_v6));
	memcpy(obj->rodata->targ_daddr_v6, env.raddr_v6, sizeof(obj->rodata->targ_daddr_v6));
	obj->rodata->targ_ms = env.milliseconds;

	if (fentry_can_attach("tcp_rcv_established", NULL))
		bpf_program__set_autoload(obj->progs.tcp_rcv_kprobe, false);
	else
		bpf_program__set_autoload(obj->progs.tcp_rcv, false);

	err = tcprtt_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcprtt_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing TCP RTT");
	if (env.duration)
		printf(" for %ld secs.\n", env.duration);
	else
		printf("... Hit Ctrl-C to end.\n");

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

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

		err = print_map(obj->maps.hists);
		if (err)
			break;

		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;

		if (exiting)
			break;
	}

cleanup:
	tcprtt_bpf__destroy(obj);
	return err != 0;
}
```