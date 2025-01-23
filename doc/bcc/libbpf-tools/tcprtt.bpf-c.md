Response:
### 功能概述
该 eBPF 程序用于统计 TCP 连接的平滑往返时间（SRTT），生成直方图分布，支持 IPv4/IPv6 地址和端口过滤，可展示本地/远程地址的直方图或扩展统计信息。

---

### **执行顺序（10 步）**
1. **用户空间初始化参数**：设置过滤条件（端口、地址）和输出模式（直方图类型、毫秒单位）。
2. **加载 eBPF 程序**：将程序挂载到内核的 `tcp_rcv_established` 函数入口。
3. **触发内核事件**：当 TCP 数据包到达已建立连接时，内核调用 `tcp_rcv_established`。
4. **进入 eBPF 处理函数**：`tcp_rcv`（fentry）或 `tcp_rcv_kprobe`（kprobe）被触发。
5. **调用 `handle_tcp_rcv_established`**：解析 `sock` 结构，提取连接信息。
6. **过滤条件检查**：匹配源/目的端口、IPv4/IPv6 地址，跳过不匹配的连接。
7. **构造直方图 Key**：根据配置选择本地地址（`targ_laddr_hist`）或远程地址（`targ_raddr_hist`）。
8. **读取 SRTT 值**：从 `tcp_sock->srtt_us` 中获取平滑 RTT 并计算时间单位（微秒/毫秒）。
9. **更新直方图数据**：通过原子操作将 SRTT 分布记录到对应的直方图槽位。
10. **用户空间聚合输出**：定期从 `hists` 映射中读取数据，生成直方图或扩展统计。

---

### **Hook 点与有效信息**
| Hook 点                   | 函数名           | 读取信息及用途                                                                 |
|---------------------------|------------------|------------------------------------------------------------------------------|
| `fentry/tcp_rcv_established` | `tcp_rcv`        | `struct sock *sk`：包含 TCP 连接的五元组（地址族、源/目的 IP/端口）、SRTT 值。 |
| `kprobe/tcp_rcv_established` | `tcp_rcv_kprobe` | 同上，兼容旧内核。                                                           |

**关键字段**：
- `sk->__sk_common.skc_{sport/dport}`：源/目的端口。
- `sk->__sk_common.skc_{saddr/daddr}`（IPv4）或 `skc_v6_{saddr/daddr}`（IPv6）：源/目的地址。
- `tcp_sock->srtt_us`：内核计算的平滑 RTT（微秒）。

---

### **假设输入与输出**
**输入示例**：
- 过滤目标端口 80：`targ_dport=80`
- 统计本地地址直方图：`targ_laddr_hist=true`
- 输出单位为毫秒：`targ_ms=true`

**输出示例**：
```
Latency (ms)  : count   distribution
0 -> 1        : 128    |**********|
2 -> 3        : 512    |************************************|
...
```

---

### **常见使用错误**
1. **IPv4/IPv6 过滤冲突**：同时设置 IPv4 地址和 IPv6 地址过滤条件（如 `targ_saddr=192.168.1.1` 和 `targ_saddr_v6=...`），程序会忽略所有连接。
2. **端口混淆**：错误使用 `targ_sport` 过滤目标端口（应用应使用 `targ_dport`）。
3. **地址字节序问题**：用户输入的 IPv4 地址未转换为网络字节序（如 `targ_saddr=0x100007f` 表示 `127.0.0.1`）。
4. **直方图模式未启用**：未设置 `targ_laddr_hist` 或 `targ_raddr_hist` 导致所有连接合并统计。

---

### **Syscall 到达路径（调试线索）**
1. **应用层**：进程调用 `read()` 或 `recv()` 接收 TCP 数据。
2. **内核协议栈**：数据包通过 `tcp_v4_rcv`/`tcp_v6_rcv` 进入 TCP 层。
3. **连接状态处理**：若连接处于 `ESTABLISHED` 状态，调用 `tcp_rcv_established`。
4. **触发 eBPF 程序**：在 `tcp_rcv_established` 入口执行挂载的 eBPF 代码。
5. **数据记录**：通过 `hists` 映射更新直方图，用户工具（如 `tcprtt.py`）读取并展示。

**调试建议**：
- 检查 `hists` 映射内容：`bpftool map dump name hists`
- 验证 eBPF 程序挂载：`bpftool prog list` 查找 `tcp_rcv` 或 `tcp_rcv_kprobe`。
### 提示词
```
这是目录为bcc/libbpf-tools/tcprtt.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "tcprtt.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

/* Taken from kernel include/linux/socket.h. */
#define AF_INET		2	/* IP version 4 */
#define AF_INET6	10	/* IP version 6 */


const volatile bool targ_laddr_hist = false;
const volatile bool targ_raddr_hist = false;
const volatile bool targ_show_ext = false;
const volatile __u16 targ_sport = 0;
const volatile __u16 targ_dport = 0;
const volatile __u32 targ_saddr = 0;
const volatile __u32 targ_daddr = 0;
const volatile __u8 targ_saddr_v6[IPV6_LEN] = {};
const volatile __u8 targ_daddr_v6[IPV6_LEN] = {};
const volatile bool targ_ms = false;

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

/*
 * We cannot use the following:
 * __builtin_memcmp(targ_*addr_v6, *, sizeof(targ_*addr_v6));
 * Indeed, by using the builtin, we would discard the volatile qualifier of
 * targ_*addr_v6, so the compiler would optimize it and replaces the call
 * with 0.
 * So, using the volatile qualifier ensures this function is called at runtime.
 */
static bool inline ipv6_is_not_zero(const volatile __u8 addr[IPV6_LEN])
{
	for (int i = 0; i < IPV6_LEN; i++)
		if (addr[i])
			return true;
	return false;
}

static bool inline ipv6_are_different(const volatile __u8 a[IPV6_LEN], const __u8 b[IPV6_LEN])
{
	for (int i = 0; i < IPV6_LEN; i++)
		if (a[i] != b[i])
			return true;
	return false;
}

static int handle_tcp_rcv_established(struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	struct tcp_sock *ts;
	struct hist *histp;
	struct hist_key key = {};
	u64 slot;
	u32 srtt;

	if (targ_sport && targ_sport != BPF_CORE_READ(inet, inet_sport))
		return 0;
	if (targ_dport && targ_dport != BPF_CORE_READ(sk, __sk_common.skc_dport))
		return 0;

	key.family = BPF_CORE_READ(sk, __sk_common.skc_family);
	switch (key.family) {
	case AF_INET:
		/* If we set any of IPv6 address, we do not care about IPv4 ones. */
		if (ipv6_is_not_zero(targ_saddr_v6) || ipv6_is_not_zero(targ_daddr_v6))
			return 0;

		if (targ_saddr && targ_saddr != BPF_CORE_READ(inet, inet_saddr))
			return 0;

		if (targ_daddr && targ_daddr != BPF_CORE_READ(sk, __sk_common.skc_daddr))
			return 0;

		break;
	case AF_INET6:
		/*
		 * Reciprocal of the above: if we set any of IPv4 address, we do not care
		 * about IPv6 ones.
		 */
		if (targ_saddr || targ_daddr)
			return 0;

		if (ipv6_is_not_zero(targ_saddr_v6)
			&& ipv6_are_different(targ_saddr_v6, BPF_CORE_READ(inet, pinet6, saddr.in6_u.u6_addr8)))
			return 0;

		if (ipv6_is_not_zero(targ_daddr_v6)
			&& ipv6_are_different(targ_daddr_v6, BPF_CORE_READ(sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8)))
			return 0;

		break;
	default:
		return 0;
	}

	if (targ_laddr_hist) {
		if (key.family == AF_INET6)
			bpf_probe_read_kernel(key.addr, sizeof(key.addr), BPF_CORE_READ(inet, pinet6, saddr.in6_u.u6_addr8));
		else
			bpf_probe_read_kernel(key.addr, sizeof(inet->inet_saddr), &inet->inet_saddr);
	} else if (targ_raddr_hist) {
		if (key.family == AF_INET6)
			bpf_probe_read_kernel(&key.addr, sizeof(key.addr), BPF_CORE_READ(sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8));
		else
			bpf_probe_read_kernel(&key.addr, sizeof(inet->sk.__sk_common.skc_daddr), &inet->sk.__sk_common.skc_daddr);
	} else {
		key.family = 0;
	}

	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp)
		return 0;
	ts = (struct tcp_sock *)(sk);
	srtt = BPF_CORE_READ(ts, srtt_us) >> 3;
	if (targ_ms)
		srtt /= 1000U;
	slot = log2l(srtt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	if (targ_show_ext) {
		__sync_fetch_and_add(&histp->latency, srtt);
		__sync_fetch_and_add(&histp->cnt, 1);
	}
	return 0;
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
	return handle_tcp_rcv_established(sk);
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_kprobe, struct sock *sk)
{
	return handle_tcp_rcv_established(sk);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```