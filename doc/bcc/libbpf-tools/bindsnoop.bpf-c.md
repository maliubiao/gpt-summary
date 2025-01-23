Response:
### 功能总结
该 eBPF 程序用于监控 Linux 内核中 `bind()` 系统调用的行为，记录进程绑定网络端口时的详细信息，包括绑定的 IP 地址、端口号、协议类型（IPv4/IPv6）、绑定选项（如 `SO_REUSEADDR`、`SO_REUSEPORT` 等），以及绑定操作的返回值。功能特点：
- 支持 IPv4 和 IPv6。
- 支持按进程 PID、cgroup、端口号过滤事件。
- 支持忽略错误事件（如绑定失败）。

---

### 执行顺序（10 步骤）
1. **用户进程调用 `bind()`**：触发内核的 `inet_bind()`（IPv4）或 `inet6_bind()`（IPv6）。
2. **eBPF kprobe 入口触发**：`kprobe/inet_bind` 或 `kprobe/inet6_bind` 被调用，执行 `ipv4_bind_entry` 或 `ipv6_bind_entry`。
3. **过滤检查**：检查 cgroup 过滤条件（`filter_cg`）和目标 PID（`target_pid`）。
4. **记录 Socket 信息**：将当前线程 ID（TID）和 `struct socket*` 存入 `sockets` 哈希表。
5. **内核执行绑定逻辑**：实际执行内核的 `inet_bind()` 或 `inet6_bind()`。
6. **eBPF kretprobe 出口触发**：`kretprobe/inet_bind` 或 `kretprobe/inet6_bind` 被调用，执行 `ipv4_bind_exit` 或 `ipv6_bind_exit`。
7. **过滤与数据提取**：再次检查 cgroup、PID，从 `sockets` 表中获取记录的 socket 结构。
8. **读取绑定结果**：解析 socket 结构，获取端口号、绑定选项、错误码等信息。
9. **端口过滤**：若启用 `filter_by_port`，检查端口是否在允许列表中。
10. **发送事件到用户态**：通过 `events` perf 缓冲区将事件数据发送到用户空间。

---

### Hook 点与关键信息
| Hook 类型       | 函数名         | 触发阶段 | 读取的信息                                  | 信息说明                          |
|-----------------|----------------|----------|--------------------------------------------|-----------------------------------|
| `kprobe`        | `inet_bind`    | 入口     | `struct socket*`（通过参数）               | 绑定的 socket 对象               |
| `kretprobe`     | `inet_bind`    | 出口     | 返回值（`ret`）                            | 绑定操作的错误码（成功为 0）     |
| `kprobe`        | `inet6_bind`   | 入口     | `struct socket*`（通过参数）               | 绑定的 socket 对象（IPv6）       |
| `kretprobe`     | `inet6_bind`   | 出口     | 返回值（`ret`）                            | 绑定操作的错误码（IPv6）         |
| **通用字段**    |                |          | `pid`、`tid`、`task`（进程名）             | 进程 PID、线程 ID、进程名         |
| **Socket 解析** |                |          | `sport`（端口）、`addr`（IP）、`proto`     | 绑定的端口号、IP 地址、协议类型   |
| **绑定选项**    |                |          | `reuseaddress`、`reuseport`、`freebind` 等 | SO_REUSEADDR、SO_REUSEPORT 等选项 |

---

### 假设输入与输出
- **输入**：用户进程调用 `bind(8080, "0.0.0.0")`。
- **输出**：
  ```json
  {
    "ts_us": 1620000000000,
    "pid": 1234,
    "task": "nginx",
    "port": 8080,
    "proto": IPPROTO_TCP,
    "addr": "0.0.0.0",
    "ret": 0,
    "reuseaddress": 1,
    "reuseport": 0
  }
  ```

---

### 常见使用错误
1. **未正确设置 cgroup 过滤**：若启用 `filter_cg` 但未正确配置 `cgroup_map`，所有事件会被丢弃。
   ```bash
   # 错误：未挂载 cgroup 或路径错误
   bindsnoop --cgroup /invalid/path
   ```
2. **端口过滤失效**：若 `filter_by_port` 启用但 `ports` 表中未添加目标端口，事件会被忽略。
   ```bash
   # 错误：未添加端口 80 到过滤列表
   bindsnoop --port 80
   ```
3. **权限问题**：eBPF 程序需要 `CAP_BPF` 权限，普通用户运行可能失败。

---

### Syscall 到达 Hook 的调试线索
1. **用户调用 `bind()`**：应用层代码调用 `bind(sockfd, &addr, addrlen)`。
2. **内核路由**：根据地址类型（IPv4/IPv6），调用 `inet_bind()` 或 `inet6_bind()`。
3. **kprobe 触发**：eBPF 在 `inet_bind` 入口记录 `socket` 对象到 `sockets` 表。
4. **绑定执行**：内核执行端口分配、冲突检查等逻辑。
5. **kretprobe 触发**：绑定完成后，eBPF 读取返回值并构造事件数据。
6. **事件发送**：通过 `perf_event_output()` 将事件发送到用户空间。

**调试技巧**：若事件未生成，检查：
- 是否命中 PID/cgroup/端口过滤。
- `ignore_errors` 是否过滤了错误事件。
- 内核函数名是否匹配（如 `inet_bind` 在不同内核版本可能改名）。
### 提示词
```
这是目录为bcc/libbpf-tools/bindsnoop.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "bindsnoop.h"
#include "core_fixes.bpf.h"

#define MAX_ENTRIES	10240
#define MAX_PORTS	1024

const volatile bool filter_cg = false;
const volatile pid_t target_pid = 0;
const volatile bool ignore_errors = true;
const volatile bool filter_by_port = false;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct socket *);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PORTS);
	__type(key, __u16);
	__type(value, __u16);
} ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int probe_entry(struct pt_regs *ctx, struct socket *socket)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	if (target_pid && target_pid != pid)
		return 0;

	bpf_map_update_elem(&sockets, &tid, &socket, BPF_ANY);
	return 0;
};

static int probe_exit(struct pt_regs *ctx, short ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct socket **socketp, *socket;
	struct inet_sock *inet_sock;
	struct sock *sock;
	union bind_options opts;
	struct bind_event event = {};
	__u16 sport = 0, *port;
	int ret;

	socketp = bpf_map_lookup_elem(&sockets, &tid);
	if (!socketp)
		return 0;

	ret = PT_REGS_RC(ctx);
	if (ignore_errors && ret != 0)
		goto cleanup;

	socket = *socketp;
	sock = BPF_CORE_READ(socket, sk);
	inet_sock = (struct inet_sock *)sock;

	sport = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
	port = bpf_map_lookup_elem(&ports, &sport);
	if (filter_by_port && !port)
		goto cleanup;

	opts.fields.freebind             = get_inet_sock_freebind(inet_sock);
	opts.fields.transparent          = get_inet_sock_transparent(inet_sock);
	opts.fields.bind_address_no_port = get_inet_sock_bind_address_no_port(inet_sock);
	opts.fields.reuseaddress         = BPF_CORE_READ_BITFIELD_PROBED(sock, __sk_common.skc_reuse);
	opts.fields.reuseport            = BPF_CORE_READ_BITFIELD_PROBED(sock, __sk_common.skc_reuseport);
	event.opts = opts.data;
	event.ts_us = bpf_ktime_get_ns() / 1000;
	event.pid = pid;
	event.port = sport;
	event.bound_dev_if = BPF_CORE_READ(sock, __sk_common.skc_bound_dev_if);
	event.ret = ret;
	event.proto = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	if (ver == 4) {
		event.ver = ver;
		bpf_probe_read_kernel(&event.addr, sizeof(event.addr), &inet_sock->inet_saddr);
	} else { /* ver == 6 */
		event.ver = ver;
		bpf_probe_read_kernel(&event.addr, sizeof(event.addr), sock->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	}
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

SEC("kprobe/inet_bind")
int BPF_KPROBE(ipv4_bind_entry, struct socket *socket)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return probe_entry(ctx, socket);
}

SEC("kretprobe/inet_bind")
int BPF_KRETPROBE(ipv4_bind_exit)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return probe_exit(ctx, 4);
}

SEC("kprobe/inet6_bind")
int BPF_KPROBE(ipv6_bind_entry, struct socket *socket)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return probe_entry(ctx, socket);
}

SEC("kretprobe/inet6_bind")
int BPF_KRETPROBE(ipv6_bind_exit)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return probe_exit(ctx, 6);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```