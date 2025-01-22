Response:
### 功能说明
该 eBPF 程序用于追踪 **TCP 数据包在内核协议栈中的处理延迟**，具体功能如下：
1. 捕获 TCP 数据包发送时间戳（`tcp_probe` 触发）。
2. 在接收窗口调整时（`tcp_rcv_space_adjust`）计算延迟，并记录进程、端口、地址等信息。
3. 清理无效 Socket 的计时信息（`tcp_destroy_sock` 触发）。
4. 支持按 PID/TID、端口、最小延迟过滤事件。

---

### 执行顺序（10 步）
1. **用户空间配置**：设置过滤参数（PID、端口、最小延迟）。
2. **加载 eBPF 程序**：挂载到内核的 `tp_btf` 或 `raw_tp` 跟踪点。
3. **捕获 TCP 发送事件**（`tcp_probe`）：记录 Socket 标识符和时间戳。
4. **触发接收窗口调整**（`tcp_rcv_space_adjust`）：内核处理 TCP 数据时触发。
5. **查找时间戳**：通过 Socket 标识符从 `start` 映射获取发送时间。
6. **过滤事件**：检查 PID/TID、端口、最小延迟是否符合条件。
7. **填充事件数据**：收集进程名、地址、端口、延迟时间。
8. **提交事件到用户空间**：通过环形缓冲区或 Perf 事件输出。
9. **清理映射条目**：在接收窗口调整或 Socket 销毁后删除过期数据。
10. **用户空间处理**：解析并显示延迟事件。

---

### Hook 点与有效信息
| Hook 点                          | 处理函数                    | 有效信息                                                                 |
|----------------------------------|----------------------------|-------------------------------------------------------------------------|
| `tp_btf/tcp_probe`               | `handle_tcp_probe`         | 源端口 (`inet_sport`)、目的端口 (`skc_dport`)、TCP 头长度 (`doff`)、包长 (`skb->len`) |
| `tp_btf/tcp_rcv_space_adjust`    | `handle_tcp_rcv_space_adjust` | 进程 PID/TID、延迟时间 (`delta_us`)、IPv4/IPv6 地址、端口、进程名 (`comm`)          |
| `tp_btf/tcp_destroy_sock`        | `handle_tcp_destroy_sock`  | Socket 标识符（用于清理 `start` 映射）                                          |

---

### 逻辑推理示例
- **输入**：`targ_sport=80`, `targ_min_us=100`
- **输出**：仅记录源端口为 80 且延迟超过 100 微秒的事件。
- **假设场景**：Web 服务器（监听 80 端口）的响应延迟分析。

---

### 常见使用错误
1. **权限不足**：未以 root 权限运行，导致 eBPF 程序加载失败。
2. **内核版本不兼容**：旧内核缺少 `tp_btf` 支持，需回退到 `raw_tp`。
3. **过滤条件无效**：设置不存在的端口或 PID，导致无事件输出。
4. **映射竞争条件**：Socket 快速销毁导致 `start` 映射条目提前删除。

---

### Syscall 到 Hook 的调试线索
1. **发送数据**：应用调用 `send()` -> 内核 `tcp_sendmsg()` -> 触发 `tcp_probe`。
2. **接收处理**：内核处理 TCP 数据包 -> 调整接收窗口 (`tcp_rcv_space_adjust`)。
3. **关闭连接**：应用调用 `close()` -> 内核销毁 Socket (`tcp_destroy_sock`)。

**调试方法**：
- 使用 `bpftool prog list` 查看加载的程序。
- 通过 `trace -K tcp:*` 跟踪内核 TCP 事件触发路径。
- 检查 `/sys/kernel/debug/tracing/trace_pipe` 查看原始事件。
Prompt: 
```
这是目录为bcc/libbpf-tools/tcppktlat.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "compat.bpf.h"
#include "core_fixes.bpf.h"
#include "tcppktlat.h"

#define MAX_ENTRIES	10240
#define AF_INET		2

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tid = 0;
const volatile __u16 targ_sport = 0;
const volatile __u16 targ_dport = 0;
const volatile __u64 targ_min_us = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} start SEC(".maps");

static int handle_tcp_probe(struct sock *sk, struct sk_buff *skb)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	u64 sock_ident, ts, len, doff;
	const struct tcphdr *th;

	if (targ_sport && targ_sport != BPF_CORE_READ(inet, inet_sport))
		return 0;
	if (targ_dport && targ_dport != BPF_CORE_READ(sk, __sk_common.skc_dport))
		return 0;
	th = (const struct tcphdr*)BPF_CORE_READ(skb, data);
	doff = BPF_CORE_READ_BITFIELD_PROBED(th, doff);
	len = BPF_CORE_READ(skb, len);
	/* `doff * 4` means `__tcp_hdrlen` */
	if (len <= doff * 4)
		return 0;
	sock_ident = get_sock_ident(sk);
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &sock_ident, &ts, 0);
	return 0;
}

static int handle_tcp_rcv_space_adjust(void *ctx, struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	u64 sock_ident = get_sock_ident(sk);
	u64 id = bpf_get_current_pid_tgid(), *tsp;
	u32 pid = id >> 32, tid = id;
	struct event *eventp;
	s64 delta_us;
	u16 family;

	tsp = bpf_map_lookup_elem(&start, &sock_ident);
	if (!tsp)
		return 0;

	if (targ_pid && targ_pid != pid)
		goto cleanup;
	if (targ_tid && targ_tid != tid)
		goto cleanup;

	delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
	if (delta_us < 0 || delta_us <= targ_min_us)
		goto cleanup;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	eventp->pid = pid;
	eventp->tid = tid;
	eventp->delta_us = delta_us;
	eventp->sport = BPF_CORE_READ(inet, inet_sport);
	eventp->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	bpf_get_current_comm(&eventp->comm, TASK_COMM_LEN);
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET) {
		eventp->saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		eventp->daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else { /* family == AF_INET6 */
		BPF_CORE_READ_INTO(eventp->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(eventp->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	eventp->family = family;
	submit_buf(ctx, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&start, &sock_ident);
	return 0;
}

static int handle_tcp_destroy_sock(void *ctx, struct sock *sk)
{
	u64 sock_ident = get_sock_ident(sk);

	bpf_map_delete_elem(&start, &sock_ident);
	return 0;
}

SEC("tp_btf/tcp_probe")
int BPF_PROG(tcp_probe_btf, struct sock *sk, struct sk_buff *skb)
{
	return handle_tcp_probe(sk, skb);
}

SEC("tp_btf/tcp_rcv_space_adjust")
int BPF_PROG(tcp_rcv_space_adjust_btf, struct sock *sk)
{
	return handle_tcp_rcv_space_adjust(ctx, sk);
}

SEC("tp_btf/tcp_destroy_sock")
int BPF_PROG(tcp_destroy_sock_btf, struct sock *sk)
{
	return handle_tcp_destroy_sock(ctx, sk);
}

SEC("raw_tp/tcp_probe")
int BPF_PROG(tcp_probe, struct sock *sk, struct sk_buff *skb) {
	return handle_tcp_probe(sk, skb);
}

SEC("raw_tp/tcp_rcv_space_adjust")
int BPF_PROG(tcp_rcv_space_adjust, struct sock *sk)
{
	return handle_tcp_rcv_space_adjust(ctx, sk);
}

SEC("raw_tp/tcp_destroy_sock")
int BPF_PROG(tcp_destroy_sock, struct sock *sk)
{
	return handle_tcp_destroy_sock(ctx, sk);
}

char LICENSE[] SEC("license") = "GPL";

"""

```