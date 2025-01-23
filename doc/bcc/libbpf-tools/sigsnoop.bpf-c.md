Response:
### 功能说明
1. **跟踪信号发送系统调用**：捕获 `kill`、`tkill`、`tgkill` 系统调用的入口和退出事件。
2. **信号生成跟踪**：通过内核 `signal_generate` 事件跟踪信号的实际生成过程。
3. **过滤功能**：支持按进程 PID (`filtered_pid`) 或信号类型 (`target_signals`) 过滤事件。
4. **错误监控**：通过 `failed_only` 标记仅记录失败的信号发送事件。
5. **上下文信息记录**：记录发送者 PID、目标 PID、信号值、进程名、返回值等。

---

### 执行顺序（10 步）
1. **用户空间触发系统调用**：例如用户调用 `kill(pid, sig)`。
2. **进入内核 `sys_enter_kill`**：触发 `kill_entry` 函数，读取参数 `tpid` 和 `sig`。
3. **过滤检查**：检查当前进程 PID 和信号是否符合过滤条件。
4. **存储事件上下文**：将 PID、目标 PID、信号、进程名存入哈希表 `values`。
5. **系统调用执行完成**：内核处理信号发送逻辑。
6. **触发 `sys_exit_kill`**：调用 `kill_exit`，从哈希表读取暂存的事件数据。
7. **错误过滤与输出**：若开启 `failed_only`，仅当返回值 `<0` 时输出到 `perf_event`。
8. **用户空间接收事件**：通过 `perf_event` 将事件传递到用户态工具（如 `sigsnoop`）。
9. **独立信号跟踪**：内核生成信号时触发 `signal_generate`，调用 `sig_trace` 直接输出事件。
10. **清理哈希表**：在退出函数中删除哈希表中的临时条目。

---

### eBPF Hook 点与有效信息
| Hook 点                          | 函数名       | 读取信息                          | 信息含义                     |
|----------------------------------|--------------|-----------------------------------|------------------------------|
| `tracepoint/syscalls/sys_enter_kill` | `kill_entry` | `ctx->args[0]` (pid_t), `ctx->args[1]` (int) | 目标进程 PID、信号编号       |
| `tracepoint/syscalls/sys_exit_kill`  | `kill_exit`  | `ctx->ret` (int)                  | 系统调用返回值               |
| `tracepoint/syscalls/sys_enter_tkill`| `tkill_entry`| 同上                              | 同上                         |
| `tracepoint/syscalls/sys_exit_tkill` | `tkill_exit` | 同上                              | 同上                         |
| `tracepoint/syscalls/sys_enter_tgkill`| `tgkill_entry`| `ctx->args[1]` (pid_t), `ctx->args[2]` (int) | 目标 PID、信号编号（注意参数偏移）|
| `tracepoint/syscalls/sys_exit_tgkill` | `tgkill_exit` | 同上                              | 同上                         |
| `tracepoint/signal/signal_generate` | `sig_trace` | `ctx->pid` (pid_t), `ctx->sig` (int), `ctx->errno` (int) | 目标 PID、信号编号、错误码   |

---

### 逻辑推理示例
**假设输入**：
- `filtered_pid=1000`：仅监控 PID=1000 的进程。
- `target_signals=1<<(SIGTERM-1)`：仅跟踪 `SIGTERM`（信号 15）。

**输出事件**：
- 当 PID=1000 的进程调用 `kill(2000, SIGTERM)` 成功时：记录 `pid=1000, tpid=2000, sig=15, ret=0`。
- 若同一进程调用 `kill(2000, SIGKILL)`：因信号不匹配，被过滤。
- 若 PID=2000 的进程发送信号：因 PID 不匹配，被过滤。

---

### 常见使用错误
1. **权限不足**：未以 `root` 或 `CAP_BPF` 权限运行，导致加载 eBPF 程序失败。
2. **信号掩码错误**：`target_signals` 的位掩码计算错误（如 `1 << sig` 应为 `1 << (sig-1)`）。
3. **PID 过滤失效**：误用线程 ID（TID）代替进程 ID（PID），需注意 `bpf_get_current_pid_tgid()` 的高 32 位为 PID。
4. **哈希表冲突**：`MAX_ENTRIES` 过小导致哈希表满，事件丢失。

---

### Syscall 调试线索
1. **系统调用入口**：用户调用 `kill()` → 触发 `sys_enter_kill` → `kill_entry` 记录参数。
2. **内核处理**：执行 `do_send_sig_info` → 实际发送信号。
3. **系统调用退出**：返回用户空间前触发 `sys_exit_kill` → `kill_exit` 记录返回值。
4. **信号生成路径**：若信号在内核生成（如段错误），触发 `signal_generate` → `sig_trace` 直接记录。
5. **调试断点**：可在 `probe_entry` 或 `probe_exit` 插入调试逻辑，检查 `values` 映射中的临时数据。
### 提示词
```
这是目录为bcc/libbpf-tools/sigsnoop.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
/* Copyright (c) 2021~2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "sigsnoop.h"

#define MAX_ENTRIES	10240

const volatile pid_t filtered_pid = 0;
const volatile int target_signals = 0;
const volatile bool failed_only = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline bool is_target_signal(int sig) {
  if (target_signals == 0)
    return true;

  if ((target_signals & (1 << (sig - 1))) == 0)
    return false;

  return true;
}

static int probe_entry(pid_t tpid, int sig)
{
	struct event event = {};
	__u64 pid_tgid;
	__u32 pid, tid;

        if (!is_target_signal(sig))
          return 0;

        pid_tgid = bpf_get_current_pid_tgid();
        pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;
	if (filtered_pid && pid != filtered_pid)
		return 0;

	event.pid = pid;
	event.tpid = tpid;
	event.sig = sig;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
	return 0;
}

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	struct event *eventp;

	eventp = bpf_map_lookup_elem(&values, &tid);
	if (!eventp)
		return 0;

	if (failed_only && ret >= 0)
		goto cleanup;

	eventp->ret = ret;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&values, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct syscall_trace_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int tkill_entry(struct syscall_trace_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tkill")
int tkill_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int tgkill_entry(struct syscall_trace_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[1];
	int sig = (int)ctx->args[2];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tgkill")
int tgkill_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/signal/signal_generate")
int sig_trace(struct trace_event_raw_signal_generate *ctx)
{
	struct event event = {};
	pid_t tpid = ctx->pid;
	int ret = ctx->errno;
	int sig = ctx->sig;
	__u64 pid_tgid;
	__u32 pid;

	if (failed_only && ret == 0)
		return 0;
        if (!is_target_signal(sig))
          return 0;

        pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	if (filtered_pid && pid != filtered_pid)
		return 0;

	event.pid = pid;
	event.tpid = tpid;
	event.sig = sig;
	event.ret = ret;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```