Response:
### 功能
1. **监控NUMA页迁移**：跟踪因NUMA（非统一内存访问）策略导致的页迁移事件。
2. **统计迁移次数与延迟**：每秒输出迁移次数和总延迟时间（毫秒）。
3. **动态选择Hook方式**：根据内核支持性，自动选择`fentry`或`kprobe`方式挂载。
4. **兼容新旧内核**：支持`migrate_misplaced_folio`（新内核）和`migrate_misplaced_page`（旧内核）两种内核函数。

---

### 执行顺序（分10步）
1. **参数解析**：解析命令行参数（如`--verbose`），初始化环境变量。
2. **设置Libbpf日志回调**：根据`verbose`参数控制调试输出。
3. **加载BPF对象**：通过`numamove_bpf__open()`打开并验证BPF程序。
4. **检查内存映射支持**：确认内核版本≥5.7以支持BSS段映射。
5. **探测Hook点支持性**：使用`fentry_can_attach`和`kprobe_exists`确定可用的Hook方式（fentry/kprobe）和目标函数（folio/page）。
6. **动态加载BPF程序**：根据探测结果选择性地加载`fentry`或`kprobe`程序。
7. **附加BPF程序**：通过`numamove_bpf__attach()`将BPF程序挂载到内核。
8. **注册信号处理**：捕获`SIGINT`以优雅退出。
9. **主循环输出统计**：每秒从BPF映射中原子读取并重置计数器和延迟数据，格式化输出。
10. **清理资源**：退出时销毁BPF对象。

---

### eBPF Hook点与信息
| Hook点类型       | 函数名                         | 读取信息                          | 信息说明                          |
|------------------|-------------------------------|-----------------------------------|-----------------------------------|
| `fentry`/`kprobe` | `migrate_misplaced_folio`     | 函数入口时间戳（`ts`）            | 记录迁移开始时间，用于计算延迟。  |
| `fexit`/`kretprobe`| `migrate_misplaced_folio`     | 函数退出时间戳（`ts`）            | 结合入口时间计算单次迁移耗时。    |
| `fentry`/`kprobe` | `migrate_misplaced_page`      | 同上                              | 旧内核的页迁移函数监控。          |
| `fexit`/`kretprobe`| `migrate_misplaced_page`      | 同上                              | 旧内核的延迟计算。                |

---

### 假设输入与输出
- **输入**：用户执行`numamove`命令，无额外参数。
- **输出示例**：
  ```plaintext
  TIME       NUMA_migrations   NUMA_migrations_ms
  14:30:25                12                    45
  14:30:26                 5                    18
  ```
  表示第1秒发生12次迁移，总耗时45ms；第2秒5次，耗时18ms。

---

### 用户常见错误
1. **内核版本过低**：错误提示`Memory-mapping BPF maps is supported starting from Linux 5.7`，需升级内核。
2. **缺少内核符号**：若内核未编译`migrate_misplaced_*`函数，报错`can't found any fentry/kprobe...`。
3. **权限不足**：非root用户运行可能导致BPF程序加载失败。
4. **CONFIG_FTRACE未启用**：fentry依赖内核配置`CONFIG_FUNCTION_TRACER`，未启用时回退到kprobe。

---

### Syscall到Hook点的调试线索
1. **触发路径**：进程内存访问 → 内核NUMA平衡机制检测到页面位置不优 → 调用`migrate_misplaced_*`尝试迁移。
2. **调试方法**：
   - 使用`perf trace`跟踪`migrate_misplaced_*`调用。
   - 检查`/proc/vmstat`中的`numa_pages_migrated`确认迁移是否发生。
   - 通过`bpftool prog list`确认BPF程序已加载并附加到目标函数。
Prompt: 
```
这是目录为bcc/libbpf-tools/numamove.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on numamove(8) from BPF-Perf-Tools-Book by Brendan Gregg.
//  8-Jun-2020   Wenbo Zhang   Created this.
// 30-Jan-2023   Rong Tao      Use fentry_can_attach() to decide use fentry/kprobe.
// 06-Apr-2024   Rong Tao      Support migrate_misplaced_folio()
#include <argp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "numamove.skel.h"
#include "trace_helpers.h"

static struct env {
	bool verbose;
} env;

static volatile bool exiting;

const char *argp_program_version = "numamove 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show page migrations of type NUMA misplaced per second.\n"
"\n"
"USAGE: numamove [--help]\n"
"\n"
"EXAMPLES:\n"
"    numamove              # Show page migrations' count and latency";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
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

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct numamove_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;
	bool use_folio, use_fentry;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = numamove_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	if (!obj->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	/* It fallbacks to kprobes when kernel does not support fentry. */
	if (fentry_can_attach("migrate_misplaced_folio", NULL)) {
		use_fentry = true;
		use_folio = true;
	} else if (kprobe_exists("migrate_misplaced_folio")) {
		use_fentry = false;
		use_folio = true;
	} else if (fentry_can_attach("migrate_misplaced_page", NULL)) {
		use_fentry = true;
		use_folio = false;
	} else if (kprobe_exists("migrate_misplaced_page")) {
		use_fentry = false;
		use_folio = false;
	} else {
		fprintf(stderr, "can't found any fentry/kprobe of migrate misplaced folio/page\n");
		return 1;
	}

	bpf_program__set_autoload(obj->progs.fentry_migrate_misplaced_folio, (use_fentry && use_folio));
	bpf_program__set_autoload(obj->progs.fexit_migrate_misplaced_folio_exit, (use_fentry && use_folio));
	bpf_program__set_autoload(obj->progs.kprobe_migrate_misplaced_folio, (!use_fentry && use_folio));
	bpf_program__set_autoload(obj->progs.kretprobe_migrate_misplaced_folio_exit, (!use_fentry && use_folio));

	bpf_program__set_autoload(obj->progs.fentry_migrate_misplaced_page, (use_fentry && !use_folio));
	bpf_program__set_autoload(obj->progs.fexit_migrate_misplaced_page_exit, (use_fentry && !use_folio));
	bpf_program__set_autoload(obj->progs.kprobe_migrate_misplaced_page, (!use_fentry && !use_folio));
	bpf_program__set_autoload(obj->progs.kretprobe_migrate_misplaced_page_exit, (!use_fentry && !use_folio));

	err = numamove_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	err = numamove_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("%-10s %18s %18s\n", "TIME", "NUMA_migrations", "NUMA_migrations_ms");
	while (!exiting) {
		sleep(1);
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-10s %18lld %18lld\n", ts,
			__atomic_exchange_n(&obj->bss->num, 0, __ATOMIC_RELAXED),
			__atomic_exchange_n(&obj->bss->latency, 0, __ATOMIC_RELAXED));
	}

cleanup:
	numamove_bpf__destroy(obj);
	return err != 0;
}

"""

```