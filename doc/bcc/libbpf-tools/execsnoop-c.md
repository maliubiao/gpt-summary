Response:
### 功能概述
`execsnoop` 是一个基于 eBPF 的追踪工具，用于监控系统中所有 `exec` 系列系统调用（如 `execve`），实时记录新进程的创建信息。核心功能包括：
- 跟踪进程的启动命令、参数、PID、PPID、UID、返回值等。
- 支持按 UID、进程名、命令行参数内容过滤事件。
- 显示时间戳、耗时、失败调用（`retval < 0`）。
- 支持 cgroup 过滤，仅追踪特定容器/组的进程。

---

### 执行顺序（10 步）
1. **参数解析**  
   解析命令行参数（如 `-u`、`-n`、`-c`），设置过滤条件（UID、进程名、cgroup 路径等）。

2. **初始化 Libbpf**  
   配置 Libbpf 的调试输出回调（`libbpf_set_print`），加载 BTF 信息（`ensure_core_btf`）。

3. **打开 BPF 对象**  
   通过 `execsnoop_bpf__open_opts` 加载 BPF 程序的骨架（`.skel.h`），初始化全局变量（如 `max_args`）。

4. **设置过滤条件到 BPF Map**  
   若启用 cgroup 过滤（`-c`），将 cgroup 路径的 FD 写入 `cgroup_map`，供内核侧校验进程是否属于该 cgroup。

5. **加载并校验 BPF 程序**  
   调用 `execsnoop_bpf__load` 将 BPF 程序加载到内核，验证字节码和 Map 的合法性。

6. **附加到 Hook 点**  
   通过 `execsnoop_bpf__attach` 将 BPF 程序挂载到内核的 **Tracepoint** 或 **Kprobe** 上（如 `sys_enter_execve`）。

7. **初始化 Perf Buffer**  
   创建 `perf_buffer` 用于接收内核传递的事件数据，绑定回调函数 `handle_event` 和 `handle_lost_events`。

8. **注册信号处理**  
   捕获 `SIGINT` 信号（Ctrl+C），设置 `exiting` 标志以优雅退出主循环。

9. **事件轮询循环**  
   通过 `perf_buffer__poll` 持续从内核读取事件，触发回调处理数据，直至收到退出信号。

10. **清理资源**  
    释放 `perf_buffer`、关闭 BPF 对象、清理 BTF 和 cgroup FD。

---

### Hook 点与有效信息
假设 BPF 程序（未直接提供）使用以下 Hook：
- **Hook 点**: `sys_enter_execve`（系统调用入口）  
  **函数名**: `tracepoint__syscalls__sys_enter_execve`（假设基于 Tracepoint）  
  **读取信息**:  
  - `const char *filename`: 被执行的文件路径（如 `/bin/ls`）。  
  - `const char *const argv[]`: 命令行参数数组（如 `["ls", "-l"]`）。  
  - `pid_t pid`: 当前进程的 PID。  
  - `uid_t uid`: 执行进程的用户 UID。

- **Hook 点**: `sys_exit_execve`（系统调用退出）  
  **函数名**: `tracepoint__syscalls__sys_exit_execve`  
  **读取信息**:  
  - `int retval`: 执行结果（成功时为 0，失败为负数错误码）。

---

### 逻辑推理示例
**假设输入**：用户执行 `ls -l /tmp`  
**BPF 输出**（内核侧）:  
```c
struct event {
  .comm = "ls", .pid = 12345, .ppid = 6789, .uid = 1000,
  .args = "ls\0-l\0/tmp\0", .args_count = 3, .retval = 0
}
```
**用户空间输出**（格式化后）:  
```
16:30:45 12345 6789   0 ls -l /tmp
```

---

### 常见使用错误
1. **权限不足**  
   未以 `root` 运行导致 BPF 加载失败：  
   ```bash
   $ ./execsnoop
   ERROR: failed to load BPF object: Permission denied
   ```

2. **无效 cgroup 路径**  
   指定不存在的 cgroup 路径：  
   ```bash
   $ ./execsnoop -c /invalid/path
   Failed opening Cgroup path: No such file or directory
   ```

3. **过多参数截断**  
   `--max-args` 设置过小导致参数显示不全：  
   ```bash
   $ ./execsnoop --max-args 2
   COMM            PID    PPID  RET ARGS
   bash            123    456    0  ls -l ...
   ```

---

### Syscall 到达 Hook 的调试线索
1. **用户态调用**  
   应用调用 `execve("/bin/ls", ["ls", "-l"], envp)`，触发软中断 `int 0x80`/`syscall` 进入内核。

2. **内核系统调用处理**  
   内核执行 `SYSCALL_DEFINE3(execve, ...)`，进入 `do_execve` 系列函数。

3. **触发 Tracepoint**  
   在 `do_execveat_common` 中触发 `sys_enter_execve` Tracepoint，执行绑定的 BPF 程序。

4. **BPF 数据采集**  
   BPF 程序从寄存器/参数中提取 `filename`、`argv`，通过 Map 过滤（UID、cgroup），将数据写入 `events` Map。

5. **用户态读取**  
   `perf_buffer__poll` 从 `events` Map 异步读取数据，调用 `handle_event` 打印结果。

---

### 总结
通过上述分析，`execsnoop` 利用 eBPF 在 `execve` 的入口/出口处捕获进程创建信息，结合用户态过滤逻辑，提供高效的进程监控能力。调试时可通过检查返回值、Map 状态和内核日志定位问题。
### 提示词
```
这是目录为bcc/libbpf-tools/execsnoop.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```c
// Based on execsnoop(8) from BCC by Brendan Gregg and others.
//
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "execsnoop.h"
#include "execsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES   64
#define PERF_POLL_TIMEOUT_MS	100
#define MAX_ARGS_KEY 259

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool time;
	bool timestamp;
	bool fails;
	uid_t uid;
	bool quote;
	const char *name;
	const char *line;
	bool print_uid;
	bool verbose;
	int max_args;
	char *cgroupspath;
	bool cg;
} env = {
	.max_args = DEFAULT_MAXARGS,
	.uid = INVALID_UID
};

static struct timespec start_time;

const char *argp_program_version = "execsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace exec syscalls\n"
"\n"
"USAGE: execsnoop [-h] [-T] [-t] [-x] [-u UID] [-q] [-n NAME] [-l LINE] [-U] [-c CG]\n"
"                 [--max-args MAX_ARGS]\n"
"\n"
"EXAMPLES:\n"
"   ./execsnoop           # trace all exec() syscalls\n"
"   ./execsnoop -x        # include failed exec()s\n"
"   ./execsnoop -T        # include time (HH:MM:SS)\n"
"   ./execsnoop -U        # include UID\n"
"   ./execsnoop -u 1000   # only trace UID 1000\n"
"   ./execsnoop -t        # include timestamps\n"
"   ./execsnoop -q        # add \"quotemarks\" around arguments\n"
"   ./execsnoop -n main   # only print command lines containing \"main\"\n"
"   ./execsnoop -l tpkg   # only print command where arguments contains \"tpkg\""
"   ./execsnoop -c CG     # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "time", 'T', NULL, 0, "include time column on output (HH:MM:SS)", 0 },
	{ "timestamp", 't', NULL, 0, "include timestamp on output", 0 },
	{ "fails", 'x', NULL, 0, "include failed exec()s", 0 },
	{ "uid", 'u', "UID", 0, "trace this UID only", 0 },
	{ "quote", 'q', NULL, 0, "Add quotemarks (\") around arguments", 0 },
	{ "name", 'n', "NAME", 0, "only print commands matching this name, any arg", 0 },
	{ "line", 'l', "LINE", 0, "only print commands where arg contains this line", 0 },
	{ "print-uid", 'U', NULL, 0, "print UID column", 0 },
	{ "max-args", MAX_ARGS_KEY, "MAX_ARGS", 0,
		"maximum number of arguments parsed and displayed, defaults to 20", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long int uid, max_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'T':
		env.time = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'x':
		env.fails = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'u':
		errno = 0;
		uid = strtol(arg, NULL, 10);
		if (errno || uid < 0 || uid >= INVALID_UID) {
			fprintf(stderr, "Invalid UID %s\n", arg);
			argp_usage(state);
		}
		env.uid = uid;
		break;
	case 'q':
		env.quote = true;
		break;
	case 'n':
		env.name = arg;
		break;
	case 'l':
		env.line = arg;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case MAX_ARGS_KEY:
		errno = 0;
		max_args = strtol(arg, NULL, 10);
		if (errno || max_args < 1 || max_args > TOTAL_MAX_ARGS) {
			fprintf(stderr, "Invalid MAX_ARGS %s, should be in [1, %d] range\n",
					arg, TOTAL_MAX_ARGS);

			argp_usage(state);
		}
		env.max_args = max_args;
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

static void sig_int(int signo)
{
	exiting = 1;
}

static void time_since_start()
{
	long nsec, sec;
	static struct timespec cur_time;
	double time_diff;

	clock_gettime(CLOCK_MONOTONIC, &cur_time);
	nsec = cur_time.tv_nsec - start_time.tv_nsec;
	sec = cur_time.tv_sec - start_time.tv_sec;
	if (nsec < 0) {
		nsec += NSEC_PER_SEC;
		sec--;
	}
	time_diff = sec + (double)nsec / NSEC_PER_SEC;
	printf("%-8.3f", time_diff);
}

static void inline quoted_symbol(char c) {
	switch(c) {
		case '"':
			putchar('\\');
			putchar('"');
			break;
		case '\t':
			putchar('\\');
			putchar('t');
			break;
		case '\n':
			putchar('\\');
			putchar('n');
			break;
		default:
			putchar(c);
			break;
	}
}

static void print_args(const struct event *e, bool quote)
{
	int i, args_counter = 0;

	if (env.quote)
		putchar('"');

	for (i = 0; i < e->args_size && args_counter < e->args_count; i++) {
		char c = e->args[i];

		if (env.quote) {
			if (c == '\0') {
				args_counter++;
				putchar('"');
				putchar(' ');
				if (args_counter < e->args_count) {
					putchar('"');
				}
			} else {
				quoted_symbol(c);
			}
		} else {
			if (c == '\0') {
				args_counter++;
				putchar(' ');
			} else {
				putchar(c);
			}
		}
	}
	if (e->args_count == env.max_args + 1) {
		fputs(" ...", stdout);
	}
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	time_t t;
	struct tm *tm;
	char ts[32];

	/* TODO: use pcre lib */
	if (env.name && strstr(e->comm, env.name) == NULL)
		return;

	/* TODO: use pcre lib */
	if (env.line && strstr(e->comm, env.line) == NULL)
		return;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (env.time) {
		printf("%-8s ", ts);
	}
	if (env.timestamp) {
		time_since_start();
	}

	if (env.print_uid)
		printf("%-6d", e->uid);

	printf("%-16s %-6d %-6d %3d ", e->comm, e->pid, e->ppid, e->retval);
	print_args(e, env.quote);
	putchar('\n');
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct execsnoop_bpf *obj;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = execsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->ignore_failed = !env.fails;
	obj->rodata->targ_uid = env.uid;
	obj->rodata->max_args = env.max_args;
	obj->rodata->filter_cg = env.cg;

	err = execsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &start_time);
	err = execsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
	/* print headers */
	if (env.time) {
		printf("%-9s", "TIME");
	}
	if (env.timestamp) {
		printf("%-8s ", "TIME(s)");
	}
	if (env.print_uid) {
		printf("%-6s ", "UID");
	}

	printf("%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS");

	/* setup event callbacks */
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	execsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
```