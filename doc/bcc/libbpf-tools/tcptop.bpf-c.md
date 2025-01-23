Response:
### 功能概述
此 eBPF 程序用于实时监控系统中各进程的 TCP 流量，按进程、地址、端口统计发送和接收的数据量，支持通过 PID、地址族（IPv4/IPv6）和 CGroup 过滤。输出包含进程名、PID、本地/远程地址/端口及流量统计。

---

### 执行顺序（10 步骤）
1. **加载程序**：用户空间工具加载 eBPF 程序到内核。
2. **挂载 kprobes**：在 `tcp_sendmsg` 和 `tcp_cleanup_rbuf` 函数上注册 kprobes。
3. **触发发送事件**：应用调用 `sendmsg` 等系统调用触发 `tcp_sendmsg`。
4. **捕获发送数据**：kprobe 触发 `BPF_KPROBE(tcp_sendmsg)`，调用 `probe_ip(false, sk, size)`。
5. **过滤检查**：检查 CGroup、PID、地址族是否符合条件。
6. **提取连接信息**：从 `struct sock *sk` 读取端口、IP 地址、协议族。
7. **更新发送统计**：在 `ip_map` 中更新 `sent` 字段。
8. **触发接收事件**：内核处理接收数据后调用 `tcp_cleanup_rbuf`。
9. **捕获接收数据**：kprobe 触发 `BPF_KPROBE(tcp_cleanup_rbuf)`，调用 `probe_ip(true, sk, copied)`。
10. **更新接收统计**：在 `ip_map` 中更新 `received` 字段。

---

### Hook 点与关键信息
| Hook 点                | 函数名                 | 读取信息                                                                 |
|-------------------------|------------------------|--------------------------------------------------------------------------|
| `kprobe/tcp_sendmsg`    | `BPF_KPROBE(tcp_sendmsg)` | - PID、进程名<br>- 源/目的 IP 和端口（IPv4/IPv6）<br>- 发送数据大小 (`size`) |
| `kprobe/tcp_cleanup_rbuf` | `BPF_KPROBE(tcp_cleanup_rbuf)` | - PID、进程名<br>- 源/目的 IP 和端口<br>- 接收数据大小 (`copied`)           |

---

### 逻辑推理示例
- **输入**：进程 PID=1234 发送 1500 字节到 `192.168.1.100:80`。
- **输出**：`ip_map` 中对应条目的 `sent` 增加 1500。
- **输入**：同一进程从 `10.0.0.1:443` 接收 800 字节。
- **输出**：对应条目的 `received` 增加 800。

---

### 用户常见错误
1. **权限不足**：未以 root 或 CAP_BPF 权限运行，导致加载失败。
   ```bash
   $ ./tcptop # 错误：Failed to load BPF program
   ```
2. **无效 PID 过滤**：指定不存在的 PID，无输出。
   ```bash
   $ ./tcptop -p 99999 # 无统计
   ```
3. **内核版本不兼容**：旧内核缺少 `tcp_cleanup_rbuf` 符号，程序无法挂载。

---

### Syscall 到 Hook 的调试线索
1. **发送路径**：
   - 用户调用 `send()` → `sendmsg` 系统调用 → 内核 `tcp_sendmsg()` → 触发 kprobe。
2. **接收路径**：
   - 数据到达网卡 → 内核协议栈处理 → TCP 数据存入缓冲区 → 用户调用 `recv()` → 内核复制数据到用户空间后调用 `tcp_cleanup_rbuf()` → 触发 kprobe。

---

### 关键数据结构
- **`ip_key_t`**：标识唯一连接。
  ```c
  struct ip_key_t {
      u32 pid;        // 进程 PID
      char name[16];  // 进程名（comm）
      u16 lport;      // 本地端口
      u16 dport;      // 目的端口
      int family;     // 地址族 (AF_INET/AF_INET6)
      union {
          __u32 saddr[4]; // 源 IP（IPv4 或 IPv6）
          __u32 daddr[4]; // 目的 IP
      };
  };
  ```
- **`traffic_t`**：流量统计。
  ```c
  struct traffic_t {
      __u64 sent;     // 发送总字节
      __u64 received; // 接收总字节
  };
  ```
### 提示词
```
这是目录为bcc/libbpf-tools/tcptop.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "tcptop.h"

/* Taken from kernel include/linux/socket.h. */
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/

const volatile bool filter_cg = false;
const volatile pid_t target_pid = -1;
const volatile int target_family = -1;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key_t);
	__type(value, struct traffic_t);
} ip_map SEC(".maps");

static int probe_ip(bool receiving, struct sock *sk, size_t size)
{
	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp;
	u16 family;
	u32 pid;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid != -1 && target_pid != pid)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (target_family != -1 && target_family != family)
		return 0;

	/* drop */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	ip_key.pid = pid;
	bpf_get_current_comm(&ip_key.name, sizeof(ip_key.name));
	ip_key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	ip_key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	ip_key.family = family;

	if (family == AF_INET) {
		bpf_probe_read_kernel(&ip_key.saddr,
				      sizeof(sk->__sk_common.skc_rcv_saddr),
				      &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&ip_key.daddr,
				      sizeof(sk->__sk_common.skc_daddr),
				      &sk->__sk_common.skc_daddr);
	} else {
		/*
		 * family == AF_INET6,
		 * we already checked above family is correct.
		 */
		bpf_probe_read_kernel(&ip_key.saddr,
				      sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
				      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&ip_key.daddr,
				      sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
				      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
	if (!trafficp) {
		struct traffic_t zero;

		if (receiving) {
			zero.sent = 0;
			zero.received = size;
		} else {
			zero.sent = size;
			zero.received = 0;
		}

		bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);
	} else {
		if (receiving)
			trafficp->received += size;
		else
			trafficp->sent += size;

		bpf_map_update_elem(&ip_map, &ip_key, trafficp, BPF_EXIST);
	}

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	return probe_ip(false, sk, size);
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;

	return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
```