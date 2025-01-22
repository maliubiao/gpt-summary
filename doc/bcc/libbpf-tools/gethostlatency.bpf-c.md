Response:
### 功能说明
该 eBPF 程序用于 **监控用户态函数调用延迟**，具体功能是测量 `gethostbyname` 或类似主机名解析函数的执行耗时，并输出进程 PID、主机名、命令名和延迟时间。

---

### 执行顺序（10 步）
1. **用户进程调用目标函数**（如 `gethostbyname("example.com")`）。
2. **触发 uprobe**，执行 `handle_entry`（调用 `probe_entry`）。
3. **过滤非目标进程**：若 `target_pid` 指定且不匹配当前 PID，直接返回。
4. **记录初始信息**：保存时间戳、PID、TID、进程名和主机名到哈希表 `starts`。
5. **目标函数执行**：实际的主机名解析逻辑在用户态运行。
6. **函数返回时触发 uretprobe**，执行 `handle_return`（调用 `probe_return`）。
7. **查找哈希表**：通过 TID 找到对应的 `event` 条目。
8. **计算延迟**：用当前时间减去初始时间戳，得到耗时。
9. **输出性能事件**：将结果通过 `perf_event_array` 发送到用户态。
10. **清理哈希表**：删除该 TID 对应的条目，避免内存泄漏。

---

### Hook 点与关键信息
| Hook 类型       | 函数名（示例）      | 有效信息                        | 信息说明                     |
|-----------------|---------------------|---------------------------------|----------------------------|
| `uprobe`        | `gethostbyname`     | `PT_REGS_PARM1(ctx)`            | 主机名字符串（如 "example.com"） |
| `uretprobe`     | `gethostbyname`     | `event.time`（计算后）          | 函数执行耗时（纳秒）         |

- **附加信息**：通过 `bpf_get_current_pid_tgid()` 获取 PID/TID，`bpf_get_current_comm()` 获取进程名。

---

### 逻辑推理示例
- **输入**：进程调用 `gethostbyname("example.com")`。
- **输出**：
  ```c
  struct event {
    .pid = 1234,
    .comm = "curl",
    .host = "example.com",
    .time = 1500000 // 1.5 毫秒
  };
  ```

---

### 常见使用错误
1. **权限不足**：未以 `root` 运行导致无法附加 uprobe。
   ```bash
   sudo ./gethostlatency
   ```
2. **目标进程过滤失效**：未设置 `target_pid` 时监控所有进程，可能产生大量无关事件。
3. **符号匹配问题**：Hook 的函数名与实际链接库版本不匹配（如 `glibc` vs `musl`）。

---

### Syscall 调试线索
1. **用户态调用**：应用调用 `gethostbyname`（属于 `libc` 库，非 syscall）。
2. **动态插桩**：通过 uprobe 在函数入口插入探测点。
3. **上下文捕获**：eBPF 读取函数参数（主机名）和进程上下文（PID/TID）。
4. **同步机制**：哈希表 `starts` 通过 TID 关联入口和返回事件。
5. **性能事件传递**：通过 `perf_event_array` 向用户态推送结果。

---

### 关键代码路径
1. **入口处理**：`probe_entry` → 保存初始状态到哈希表。
2. **返回处理**：`probe_return` → 计算延迟并清理状态。
3. **数据流**：`uprobe/uretprobe` → 内核 eBPF 虚拟机 → 用户态性能事件环形缓冲区。
Prompt: 
```
这是目录为bcc/libbpf-tools/gethostlatency.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "gethostlatency.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int probe_entry(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM1(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct event event = {};

	if (target_pid && target_pid != pid)
		return 0;

	event.time = bpf_ktime_get_ns();
	event.pid = pid;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user(&event.host, sizeof(event.host), (void *)PT_REGS_PARM1(ctx));
	bpf_map_update_elem(&starts, &tid, &event, BPF_ANY);
	return 0;
}

static int probe_return(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct event *eventp;

	eventp = bpf_map_lookup_elem(&starts, &tid);
	if (!eventp)
		return 0;

	/* update time from timestamp to delta */
	eventp->time = bpf_ktime_get_ns() - eventp->time;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));
	bpf_map_delete_elem(&starts, &tid);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(handle_entry)
{
	return probe_entry(ctx);
}

SEC("uretprobe")
int BPF_URETPROBE(handle_return)
{
	return probe_return(ctx);
}

char LICENSE[] SEC("license") = "GPL";

"""

```