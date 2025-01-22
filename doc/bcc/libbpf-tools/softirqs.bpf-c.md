Response:
### 功能列举
1. **统计软中断事件次数**：记录每个软中断类型（如网络、定时器等）的触发次数。
2. **计算软中断处理时间**：测量每个软中断从进入（entry）到退出（exit）的耗时。
3. **支持时间单位切换**：可选择纳秒或微秒作为时间单位。
4. **按CPU核心过滤**：仅监控特定CPU上的软中断事件。
5. **生成延迟分布直方图**：记录耗时分布，用于分析延迟模式。
6. **多内核版本兼容**：通过`tp_btf`和`raw_tp`跟踪点适配不同内核。

---

### 执行顺序（10步）
1. **用户空间启动工具**：加载并附加eBPF程序到内核跟踪点。
2. **内核触发软中断**：例如网络包到达触发`NET_RX_SOFTIRQ`。
3. **进入`softirq_entry`跟踪点**：内核执行软中断处理前触发。
4. **调用`handle_entry()`**：记录当前时间戳到`start`映射。
5. **执行实际软中断处理**：内核运行软中断处理函数。
6. **进入`softirq_exit`跟踪点**：处理完成后触发。
7. **调用`handle_exit()`**：计算时间差，验证CPU和`vec_nr`有效性。
8. **更新统计信息**：根据`targ_dist`选择更新次数/时间或直方图。
9. **用户空间读取映射数据**：定期从`counts`、`time`或`hists`中拉取数据。
10. **输出结果**：打印统计信息或直方图。

---

### Hook点与关键信息
| Hook点                  | 函数名                 | 有效信息             | 信息说明                     |
|-------------------------|-----------------------|----------------------|----------------------------|
| `tp_btf/softirq_entry`  | `softirq_entry_btf`   | `vec_nr`             | 软中断类型编号（如0-9）      |
| `tp_btf/softirq_exit`   | `softirq_exit_btf`    | `vec_nr`             | 软中断类型编号               |
| `raw_tp/softirq_entry`  | `softirq_entry`       | `vec_nr`             | 同上（旧内核兼容）           |
| `raw_tp/softirq_exit`   | `softirq_exit`        | `vec_nr`             | 同上                        |

---

### 假设输入与输出
- **输入假设**：用户运行命令 `softirqs -d -C 2 -N`，表示监控CPU 2，显示纳秒级延迟分布。
- **输出示例**：
  ```plaintext
  SOFTIRQ          latency (ns)        
  TASKLET          @ 
  [0, 1)          12 
  [1, 2)          120
  ... 
  ```

---

### 常见使用错误
1. **无效CPU编号**：如指定`-C 128`但系统只有4核，导致无数据。
2. **误解时间单位**：未使用`-N`时默认单位为微秒，用户可能误读为纳秒。
3. **权限不足**：未以root运行导致eBPF程序加载失败。
4. **内核版本不兼容**：旧内核不支持`tp_btf`，需回退到`raw_tp`。

---

### Syscall到Hook的调试线索
1. **Syscall触发软中断**：例如`sendmsg()`系统调用触发网络发送，最终引发`NET_TX_SOFTIRQ`。
2. **内核调度软中断**：系统调用返回到用户空间前，内核检查待处理软中断。
3. **进入`softirq_entry`**：内核调用`__do_softirq()`时触发跟踪点。
4. **记录时间戳**：eBPF程序保存`bpf_ktime_get_ns()`到`start`映射。
5. **执行中断处理**：运行`vec_nr`对应的处理函数（如`net_tx_action()`）。
6. **触发`softirq_exit`**：处理完成后再次触发跟踪点，计算耗时。

---

### 调试建议
- **检查`vec_nr`范围**：若`vec_nr >= NR_SOFTIRQS`（通常为10），数据会被丢弃。
- **验证CPU过滤**：通过`bpf_get_smp_processor_id()`确认目标CPU是否匹配。
- **检查时间戳更新**：确保`start`映射在`handle_entry()`中正确写入。
- **直方图桶溢出**：`slot >= MAX_SLOTS`时强制设为最大值，可能需调整`log2(delta)`逻辑。
Prompt: 
```
这是目录为bcc/libbpf-tools/softirqs.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "softirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

const volatile bool targ_dist = false;
const volatile bool targ_ns = false;
const volatile int targ_cpu = -1;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

__u64 counts[NR_SOFTIRQS] = {};
__u64 time[NR_SOFTIRQS] = {};
struct hist hists[NR_SOFTIRQS] = {};

static bool is_target_cpu() {
	if (targ_cpu < 0)
		return true;

	return bpf_get_smp_processor_id() == targ_cpu;
}

static int handle_entry(unsigned int vec_nr)
{
	if (!is_target_cpu())
		return 0;

	u64 ts = bpf_ktime_get_ns();
	u32 key = 0;

	bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
	return 0;
}

static int handle_exit(unsigned int vec_nr)
{
	if (!is_target_cpu())
		return 0;

	u64 delta, *tsp;
	u32 key = 0;

	if (vec_nr >= NR_SOFTIRQS)
		return 0;
	tsp = bpf_map_lookup_elem(&start, &key);
	if (!tsp)
		return 0;
	delta = bpf_ktime_get_ns() - *tsp;
	if (!targ_ns)
		delta /= 1000U;

	if (!targ_dist) {
		__sync_fetch_and_add(&counts[vec_nr], 1);
		__sync_fetch_and_add(&time[vec_nr], delta);
	} else {
		struct hist *hist;
		u64 slot;

		hist = &hists[vec_nr];
		slot = log2(delta);
		if (slot >= MAX_SLOTS)
			slot = MAX_SLOTS - 1;
		__sync_fetch_and_add(&hist->slots[slot], 1);
	}

	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(softirq_entry_btf, unsigned int vec_nr)
{
	return handle_entry(vec_nr);
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(softirq_exit_btf, unsigned int vec_nr)
{
	return handle_exit(vec_nr);
}

SEC("raw_tp/softirq_entry")
int BPF_PROG(softirq_entry, unsigned int vec_nr)
{
	return handle_entry(vec_nr);
}

SEC("raw_tp/softirq_exit")
int BPF_PROG(softirq_exit, unsigned int vec_nr)
{
	return handle_exit(vec_nr);
}

char LICENSE[] SEC("license") = "GPL";

"""

```