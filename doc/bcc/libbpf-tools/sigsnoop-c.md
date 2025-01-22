Response:
### 功能概述
sigsnoop 是一个基于 eBPF 的工具，用于跟踪系统中信号的发送和接收过程。核心功能包括：
1. **信号跟踪**：捕获 `kill()`、`tkill()`、`tgkill()` 系统调用及信号处理事件。
2. **过滤条件**：按 PID、信号类型、失败信号、仅限 `kill` 调用等过滤事件。
3. **动态输出**：显示信号名称或编号、时间戳、进程信息、结果（成功/错误码）。

---

### 执行顺序（分10步）
1. **参数解析**：解析命令行参数（如 `-p PID`, `-s SIGNAL`），设置过滤条件。
2. **别名处理**：若程序名为 `killsnoop`，自动启用 `-k` 仅跟踪 `kill` 调用。
3. **eBPF对象初始化**：调用 `sigsnoop_bpf__open()` 初始化 eBPF 程序结构。
4. **条件加载程序**：根据 `-k` 参数选择性加载 eBPF 钩子（禁用无关探针）。
5. **加载并验证**：`sigsnoop_bpf__load()` 加载 eBPF 字节码到内核，验证合法性。
6. **附加钩子**：`sigsnoop_bpf__attach()` 将 eBPF 程序挂载到内核事件点。
7. **事件缓冲区配置**：创建 `perf_buffer` 用于接收内核传递的事件数据。
8. **注册信号处理**：设置 `SIGINT` 处理函数，优雅退出循环。
9. **事件轮询循环**：通过 `perf_buffer__poll()` 持续读取并处理事件。
10. **资源清理**：退出时释放 `perf_buffer` 和 eBPF 对象。

---

### eBPF Hook 点及信息
| Hook点              | 函数名           | 读取信息                                     | 信息说明                          |
|---------------------|------------------|--------------------------------------------|-----------------------------------|
| `kill()` 入口       | `kill_entry`     | 发起者 PID、目标 PID、信号编号               | 信号发送参数                      |
| `kill()` 出口       | `kill_exit`      | 系统调用返回值                              | 成功 (≥0) 或错误码 (<0)           |
| `tkill()` 入口      | `tkill_entry`    | 同 `kill_entry`                            | 线程信号发送参数                  |
| `tkill()` 出口      | `tkill_exit`     | 同 `kill_exit`                             | 同上                              |
| `tgkill()` 入口     | `tgkill_entry`   | 同 `kill_entry` + 线程组 ID                 | 线程组信号参数                    |
| `tgkill()` 出口     | `tgkill_exit`    | 同 `kill_exit`                             | 同上                              |
| 信号处理函数         | `sig_trace`      | 信号编号、目标进程 PID、处理结果             | 信号实际递送情况                  |

---

### 输入输出假设
- **输入示例**：用户执行 `sigsnoop -p 1234 -s 9,15 -x`。
  - 过滤条件：仅跟踪 PID=1234 的进程，信号 9 (SIGKILL) 和 15 (SIGTERM)，且仅显示失败事件。
- **输出示例**：
  ```
  TIME     PID     COMM            SIG       TPID    RESULT
  14:23:05 1234    bash            SIGTERM   4567    -3
  ```
  - 表示 PID=1234 的 `bash` 进程向 TPID=4567 发送 SIGTERM 失败，错误码为 -3 (权限不足)。

---

### 常见使用错误
1. **无效信号编号**：`-s 99`（信号范围 1-31），触发错误提示。
2. **权限不足**：非 root 用户跟踪其他用户的进程，事件被过滤。
3. **混淆信号来源**：使用 `-k` 但期望捕获非 `kill` 信号（如 `SIGSEGV`）。
4. **遗漏失败事件**：未使用 `-x` 导致成功事件淹没关键错误。

---

### Syscall 跟踪路径（调试线索）
1. **用户调用**：应用程序调用 `kill(pid, sig)`。
2. **内核入口**：`sys_kill()` 被触发，eBPF 程序在入口记录参数。
3. **内核处理**：权限检查、信号队列操作。
4. **内核出口**：`sys_kill()` 返回结果，eBPF 程序捕获返回值。
5. **用户空间**：通过 `perf_buffer` 传递事件，打印输出。

**调试建议**：
- 检查 `dmesg` 确认 eBPF 程序加载无错误。
- 使用 `bpftool prog list` 验证钩子是否附加到正确位置。
- 逐步放宽过滤条件（如去掉 `-p`），确认事件是否被内核丢弃。
Prompt: 
```
这是目录为bcc/libbpf-tools/sigsnoop.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * sigsnoop	Trace standard and real-time signals.
 *
 * Copyright (c) 2021~2022 Hengqi Chen
 *
 * 08-Aug-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <libgen.h>
#include <signal.h>
#include <time.h>

#include <bpf/bpf.h>
#include "sigsnoop.h"
#include "sigsnoop.skel.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static int target_signals = 0;
static bool failed_only = false;
static bool kill_only = false;
static bool signal_name = false;
static bool verbose = false;

static const char *sig_name[] = {
	[0] = "N/A",
	[1] = "SIGHUP",
	[2] = "SIGINT",
	[3] = "SIGQUIT",
	[4] = "SIGILL",
	[5] = "SIGTRAP",
	[6] = "SIGABRT",
	[7] = "SIGBUS",
	[8] = "SIGFPE",
	[9] = "SIGKILL",
	[10] = "SIGUSR1",
	[11] = "SIGSEGV",
	[12] = "SIGUSR2",
	[13] = "SIGPIPE",
	[14] = "SIGALRM",
	[15] = "SIGTERM",
	[16] = "SIGSTKFLT",
	[17] = "SIGCHLD",
	[18] = "SIGCONT",
	[19] = "SIGSTOP",
	[20] = "SIGTSTP",
	[21] = "SIGTTIN",
	[22] = "SIGTTOU",
	[23] = "SIGURG",
	[24] = "SIGXCPU",
	[25] = "SIGXFSZ",
	[26] = "SIGVTALRM",
	[27] = "SIGPROF",
	[28] = "SIGWINCH",
	[29] = "SIGIO",
	[30] = "SIGPWR",
	[31] = "SIGSYS",
};

const char *argp_program_version = "sigsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "Trace standard and real-time signals.\n"
    "\n"
    "USAGE: sigsnoop [-h] [-x] [-k] [-n] [-p PID] [-s SIGNAL]\n"
    "\n"
    "EXAMPLES:\n"
    "    sigsnoop             # trace signals system-wide\n"
    "    sigsnoop -k          # trace signals issued by kill syscall only\n"
    "    sigsnoop -x          # trace failed signals only\n"
    "    sigsnoop -p 1216     # only trace PID 1216\n"
    "    sigsnoop -s 1,9,15   # trace signal 1, 9, 15\n";

static const struct argp_option opts[] = {
    {"failed", 'x', NULL, 0, "Trace failed signals only.", 0},
    {"kill", 'k', NULL, 0, "Trace signals issued by kill syscall only.", 0},
    {"pid", 'p', "PID", 0, "Process ID to trace", 0},
    {"signal", 's', "SIGNAL", 0, "Signals to trace.", 0},
    {"name", 'n', NULL, 0, "Output signal name instead of signal number.", 0},
    {"verbose", 'v', NULL, 0, "Verbose debug output", 0},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, sig;
        char *token;

        switch (key) {
        case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 's':
		errno = 0;
                token = strtok(arg, ",");
                while (token) {
                  sig = strtol(token, NULL, 10);
                  if (errno || sig <= 0 || sig > 31) {
                    warn("Inavlid SIGNAL: %s\n", token);
                    argp_usage(state);
                  }
                  target_signals |= (1 << (sig - 1));
                  token = strtok(NULL, ",");
                }
                break;
        case 'n':
		signal_name = true;
		break;
	case 'x':
		failed_only = true;
		break;
	case 'k':
		kill_only = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (strstr(name, "killsnoop")) {
		kill_only = true;
	}
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (signal_name && e->sig < ARRAY_SIZE(sig_name))
		printf("%-8s %-7d %-16s %-9s %-7d %-6d\n",
		       ts, e->pid, e->comm, sig_name[e->sig], e->tpid, e->ret);
	else
		printf("%-8s %-7d %-16s %-9d %-7d %-6d\n",
		       ts, e->pid, e->comm, e->sig, e->tpid, e->ret);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct sigsnoop_bpf *obj;
	int err;

	alias_parse(argv[0]);
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = sigsnoop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->filtered_pid = target_pid;
        obj->rodata->target_signals = target_signals;
        obj->rodata->failed_only = failed_only;

	if (kill_only) {
		bpf_program__set_autoload(obj->progs.sig_trace, false);
	} else {
		bpf_program__set_autoload(obj->progs.kill_entry, false);
		bpf_program__set_autoload(obj->progs.kill_exit, false);
		bpf_program__set_autoload(obj->progs.tkill_entry, false);
		bpf_program__set_autoload(obj->progs.tkill_exit, false);
		bpf_program__set_autoload(obj->progs.tgkill_entry, false);
		bpf_program__set_autoload(obj->progs.tgkill_exit, false);
	}

	err = sigsnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = sigsnoop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("%-8s %-7s %-16s %-9s %-7s %-6s\n",
	       "TIME", "PID", "COMM", "SIG", "TPID", "RESULT");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	sigsnoop_bpf__destroy(obj);

	return err != 0;
}

"""

```