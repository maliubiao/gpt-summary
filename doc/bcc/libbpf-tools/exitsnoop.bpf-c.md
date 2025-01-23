Response:
### 功能
该 eBPF 程序用于监控进程退出事件，捕获以下信息：
- **进程 PID**、**线程 TID**、**父进程 PPID**
- 进程启动时间、退出时间、进程名称（`comm`）
- 退出码（`exit_code`）和终止信号（`sig`）
- 支持按 **cgroup**、**PID**、**失败退出**、**进程/线程粒度** 过滤事件

---

### 执行顺序（10步）
1. **内核触发 Tracepoint**  
   当进程退出时，内核调度器触发 `sched_process_exit` tracepoint。

2. **获取当前 PID/TID**  
   通过 `bpf_get_current_pid_tgid()` 获取进程 PID 和线程 TID。

3. **cgroup 过滤**  
   若 `filter_cg` 启用，检查进程是否属于指定 cgroup（`cgroup_map`），否则跳过。

4. **目标 PID 过滤**  
   若 `target_pid` 非零且不等于当前 PID，跳过事件。

5. **进程/线程粒度过滤**  
   若 `trace_by_process` 为 `true` 且当前为线程（PID ≠ TID），跳过事件。

6. **获取进程上下文**  
   通过 `bpf_get_current_task()` 获取 `task_struct` 结构体指针。

7. **读取退出码**  
   从 `task_struct.exit_code` 中提取退出码，若 `trace_failed_only` 为 `true` 且退出码为 0（成功），跳过事件。

8. **填充事件数据**  
   收集进程启动时间、退出时间、PPID、信号、退出码、进程名称到 `struct event`。

9. **输出事件到用户态**  
   通过 `bpf_perf_event_output` 将事件发送到用户空间的 `perf_event_array` 映射。

10. **返回处理结果**  
    返回 `0` 表示处理完成。

---

### Hook 点与有效信息
| Hook 点                          | 函数名              | 读取的信息                        | 说明                     |
|----------------------------------|---------------------|-----------------------------------|--------------------------|
| `tracepoint/sched/sched_process_exit` | `sched_process_exit` | `pid`、`tid`、`exit_code`、`comm` | 进程 PID、线程 TID、退出码、进程名称 |

---

### 逻辑推理示例
**假设输入**：  
- 进程 PID=123 调用 `exit(1)` 退出。

**输出**：  
- `event.exit_code = 1`（`exit_code >> 8` 后的值）
- `event.sig = 0`（未被信号终止）
- `event.comm = "进程名"`

---

### 常见使用错误
1. **cgroup 过滤失效**  
   未正确配置 `cgroup_map` 导致过滤不生效，需确保 cgroup 路径有效。

2. **目标 PID 混淆**  
   错误设置 `target_pid` 为线程 TID 而非进程 PID，导致无法匹配。

3. **线程事件遗漏**  
   当 `trace_by_process=true` 时，线程退出事件（PID ≠ TID）会被忽略。

---

### Syscall 到 Hook 的调试线索
1. **进程退出入口**  
   - 用户态调用 `exit()` 或 `exit_group()` 系统调用。
   - 内核执行 `do_exit()` 函数处理进程退出逻辑。

2. **触发 Tracepoint**  
   在 `do_exit()` 中调用 `trace_sched_process_exit()`，触发 `sched_process_exit` tracepoint。

3. **调试跟踪**  
   使用 `strace -e trace=exit,exit_group` 跟踪系统调用，或通过 `bpftrace -l 'tracepoint:sched:*'` 验证 tracepoint 有效性。

---

### 总结
该程序通过监听进程退出事件，提供细粒度的进程生命周期监控能力，适用于调试异常退出、分析进程生命周期等场景。
### 提示词
```
这是目录为bcc/libbpf-tools/exitsnoop.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
#include "exitsnoop.h"

const volatile bool filter_cg = false;
const volatile pid_t target_pid = 0;
const volatile bool trace_failed_only = false;
const volatile bool trace_by_process = true;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	int exit_code;
	struct task_struct *task;
	struct event event = {};

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (target_pid && target_pid != pid)
		return 0;

	if (trace_by_process && pid != tid)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	exit_code = BPF_CORE_READ(task, exit_code);
	if (trace_failed_only && exit_code == 0)
		return 0;

	event.start_time = BPF_CORE_READ(task, start_time);
	event.exit_time = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = tid;
	event.ppid = BPF_CORE_READ(task, real_parent, tgid);
	event.sig = exit_code & 0xff;
	event.exit_code = exit_code >> 8;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```