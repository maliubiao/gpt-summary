Response:
### 功能
1. 跟踪以下系统调用：
   - `mount(2)`: 挂载文件系统
   - `umount(2)`: 卸载文件系统
   - `fsopen(2)`: 创建新文件系统上下文
   - `fsconfig(2)`: 配置文件系统上下文
   - `fsmount(2)`: 从上下文创建挂载对象
   - `move_mount(2)`: 移动挂载点
2. 记录参数、返回值、进程信息、挂载命名空间等数据。
3. 支持按PID过滤、时间戳输出、详细模式显示。

---

### 执行顺序（10步）
1. **解析命令行参数**：处理`-p`、`-t`、`-d`、`-v`等选项。
2. **初始化libbpf回调**：设置调试输出函数。
3. **加载BTF信息**：确保内核BTF支持CO-RE（Compile Once – Run Everywhere）。
4. **打开并加载BPF对象**：加载`mountsnoop.bpf.o`中的eBPF程序。
5. **检查tracepoint存在性**：动态禁用不支持的syscall跟踪（如旧内核无`fsopen`）。
6. **附加BPF程序到tracepoint**：绑定到`sys_enter/exit_*`事件。
7. **初始化事件缓冲区**：创建Perf/Ring Buffer接收内核事件。
8. **注册信号处理器**：捕获`SIGINT`以优雅退出。
9. **输出表头**：打印列名（如`COMM`、`PID`、`CALL`）。
10. **轮询缓冲区并处理事件**：持续监听并格式化输出事件信息。

---

### Hook点与捕获信息
| 系统调用       | Hook点（函数名）               | 捕获信息                                                                 |
|----------------|--------------------------------|--------------------------------------------------------------------------|
| `mount`        | `sys_enter_mount`              | 源路径、目标路径、文件系统类型、挂载标志(`flags`)、附加数据(`data`)       |
|                | `sys_exit_mount`               | 返回值、耗时                                                             |
| `umount`       | `sys_enter_umount`             | 目标路径、卸载标志(`flags`)                                               |
|                | `sys_exit_umount`              | 返回值                                                                   |
| `fsopen`       | `sys_enter_fsopen`             | 文件系统名称、标志                                                        |
|                | `sys_exit_fsopen`              | 返回的文件描述符                                                          |
| `fsconfig`     | `sys_enter_fsconfig`           | 文件描述符、配置命令(`cmd`)、键值对(`key`/`value`)                        |
|                | `sys_exit_fsconfig`            | 返回值                                                                   |
| `fsmount`      | `sys_enter_fsmount`            | 文件描述符、挂载标志(`flags`)、属性标志(`attr_flags`)                     |
|                | `sys_exit_fsmount`             | 返回值                                                                   |
| `move_mount`   | `sys_enter_move_mount`         | 源/目标文件描述符、路径、移动标志                                         |
|                | `sys_exit_move_mount`          | 返回值                                                                   |

---

### 输入输出示例
**输入**：用户执行 `mount -t tmpfs tmpfs /mnt`  
**输出**：
```
COMM            PID    TID    MNT_NS      CALL
bash            1234   1234   4026531840  mount("tmpfs", "/mnt", "tmpfs", MS_STRICTATIME, "") = 0
```

**错误场景**：无权限挂载  
**输出**：`mount("/dev/sda1", "/mnt", "ext4", MS_RDONLY, "") = -EPERM`

---

### 常见使用错误
1. **权限不足**：未以`root`运行导致无法附加BPF程序。
   - 错误：`failed to load BPF object: Permission denied`
2. **PID过滤无效**：指定不存在的PID导致无输出。
3. **内核版本不兼容**：旧内核缺少某些syscall的tracepoint（如`fsopen`）。
   - 表现：相关事件无记录，BPF程序部分禁用。
4. **路径过长**：捕获的路径超过eBPF栈限制导致截断。

---

### Syscall调试线索
1. **用户层调用**：应用调用如`mount("/dev/sda1", "/mnt", "ext4", MS_RDONLY, NULL)`。
2. **触发syscall**：陷入内核，执行`do_mount()`。
3. **Tracepoint触发**：`sys_enter_mount`被eBPF程序捕获，记录参数。
4. **执行挂载逻辑**：内核处理挂载请求。
5. **Exit Tracepoint**：`sys_exit_mount`记录结果和耗时。
6. **用户层输出**：通过Perf Buffer将事件传递到用户空间，格式化后打印。

**调试提示**：若事件丢失，检查缓冲区大小或使用`-v`启用详细日志。
Prompt: 
```
这是目录为bcc/libbpf-tools/mountsnoop.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * mountsnoop  Trace mount(2), umount(2), fsopen(2), fsconfig(2), fsmount(2)
 *             move_mount(2) syscalls
 *
 * Copyright (c) 2021 Hengqi Chen
 * 30-May-2021   Hengqi Chen   Created this.
 * 20-Dec-2024   Rong Tao      Support fsopen(2), fsconfig(2), fsmount(2),
 *                             move_mount(2) syscalls.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mountsnoop.h"
#include "mountsnoop.skel.h"
#include "compat.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

/* https://www.gnu.org/software/gnulib/manual/html_node/strerrorname_005fnp.html */
#if !defined(__GLIBC__) || __GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 32)
	const char *strerrorname_np(int errnum)
	{
		return NULL;
	}
#endif

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool emit_timestamp = false;
static bool output_vertically = false;
static bool verbose = false;

static const char *mnt_flags_names[] = {
	[0] = "MS_RDONLY",
	[1] = "MS_NOSUID",
	[2] = "MS_NODEV",
	[3] = "MS_NOEXEC",
	[4] = "MS_SYNCHRONOUS",
	[5] = "MS_REMOUNT",
	[6] = "MS_MANDLOCK",
	[7] = "MS_DIRSYNC",
	[8] = "MS_NOSYMFOLLOW",
	[9] = "MS_NOATIME",
	[10] = "MS_NODIRATIME",
	[11] = "MS_BIND",
	[12] = "MS_MOVE",
	[13] = "MS_REC",
	[14] = "MS_VERBOSE",
	[15] = "MS_SILENT",
	[16] = "MS_POSIXACL",
	[17] = "MS_UNBINDABLE",
	[18] = "MS_PRIVATE",
	[19] = "MS_SLAVE",
	[20] = "MS_SHARED",
	[21] = "MS_RELATIME",
	[22] = "MS_KERNMOUNT",
	[23] = "MS_I_VERSION",
	[24] = "MS_STRICTATIME",
	[25] = "MS_LAZYTIME",
	[26] = "MS_SUBMOUNT",
	[27] = "MS_NOREMOTELOCK",
	[28] = "MS_NOSEC",
	[29] = "MS_BORN",
	[30] = "MS_ACTIVE",
	[31] = "MS_NOUSER",
};

static const struct fsmount_flags_names {
	unsigned long value;
	const char *name;
} fsmount_flags_names[] = {
	{ 0x00000001, "FSMOUNT_CLOEXEC" },
};

/**
 * See /usr/include/sys/mount.h fsmount(2)
 */
static const struct fsmount_attr_flags_names {
	unsigned long value;
	const char *name;
} fsmount_attr_flags_names[] = {
	{ 0x00000001, "MOUNT_ATTR_RDONLY" },
	{ 0x00000002, "MOUNT_ATTR_NOSUID" },
	{ 0x00000004, "MOUNT_ATTR_NODEV" },
	{ 0x00000008, "MOUNT_ATTR_NOEXEC" },
	{ 0x00000070, "MOUNT_ATTR__ATIME" },
	{ 0x00000000, "MOUNT_ATTR_RELATIME" },
	{ 0x00000010, "MOUNT_ATTR_NOATIME" },
	{ 0x00000020, "MOUNT_ATTR_STRICTATIME" },
	{ 0x00000080, "MOUNT_ATTR_NODIRATIME" },
	{ 0x00100000, "MOUNT_ATTR_IDMAP" },
	{ 0x00200000, "MOUNT_ATTR_NOSYMFOLLOW" },
};

static const char *fsconfig_cmd_names[] = {
	[0] = "FSCONFIG_SET_FLAG",
	[1] = "FSCONFIG_SET_STRING",
	[2] = "FSCONFIG_SET_BINARY",
	[3] = "FSCONFIG_SET_PATH",
	[4] = "FSCONFIG_SET_PATH_EMPTY",
	[5] = "FSCONFIG_SET_FD",
	[6] = "FSCONFIG_CMD_CREATE",
	[7] = "FSCONFIG_CMD_RECONFIGURE",
	[8] = "FSCONFIG_CMD_CREATE_EXCL",
};

/**
 * See /usr/include/sys/mount.h move_mount(2)
 */
static const struct move_mount_flags_names {
	unsigned long value;
	const char *name;
} move_mount_flags_names[] = {
	{ 0x00000001, "MOVE_MOUNT_F_SYMLINKS" },
	{ 0x00000002, "MOVE_MOUNT_F_AUTOMOUNTS" },
	{ 0x00000004, "MOVE_MOUNT_F_EMPTY_PATH" },
	{ 0x00000010, "MOVE_MOUNT_T_SYMLINKS" },
	{ 0x00000020, "MOVE_MOUNT_T_AUTOMOUNTS" },
	{ 0x00000040, "MOVE_MOUNT_T_EMPTY_PATH" },
	{ 0x00000100, "MOVE_MOUNT_SET_GROUP" },
	{ 0x00000200, "MOVE_MOUNT_BENEATH" },
};

const char *argp_program_version = "mountsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace mount, umount, fsopen, fsconfig, fsmount, move_mount syscalls.\n"
"\n"
"USAGE: mountsnoop [-h] [-t] [-p PID] [-v]\n"
"\n"
"EXAMPLES:\n"
"    mountsnoop         # trace mount relative syscalls\n"
"    mountsnoop -d      # detailed output (one line per column value)\n"
"    mountsnoop -p 1216 # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ "detailed", 'd', NULL, 0, "Output result in detail mode", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;

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
	case 't':
		emit_timestamp = true;
		break;
	case 'd':
		output_vertically = true;
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

static void sig_int(int signo)
{
	exiting = 1;
}

/**
 * Used to print special fd, such as AT_FDCWD.
 */
const char *strfd(int fd)
{
	static char buf[8];
	if (fd == AT_FDCWD)
		return "AT_FDCWD";
	snprintf(buf, 8, "%d", fd);
	return buf;
}

static const char *strmountflags(__u64 flags)
{
	static char str[512];
	int i;

	if (!flags)
		return "0x0";

	str[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(mnt_flags_names); i++) {
		if (!((1 << i) & flags))
			continue;
		if (str[0])
			strcat(str, " | ");
		strcat(str, mnt_flags_names[i]);
	}
	return str;
}

/**
 * Print fsmount(2) flags
 */
static const char *strfsmntflags(__u32 flags)
{
	static char str[512];
	int i;

	if (!flags)
		return "0x0";

	str[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(fsmount_flags_names); i++) {
		if (!(fsmount_flags_names[i].value & flags))
			continue;
		if (str[0])
			strcat(str, " | ");
		strcat(str, fsmount_flags_names[i].name);
	}
	return str;
}

/**
 * Print fsmount(2) attr_flags
 */
static const char *strfsmntattrflags(__u32 attr_flags)
{
	static char str[512];
	int i;

	str[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(fsmount_attr_flags_names); i++) {
		if (!(fsmount_attr_flags_names[i].value & attr_flags))
			continue;
		if (str[0])
			strcat(str, " | ");
		strcat(str, fsmount_attr_flags_names[i].name);
	}
	return str;
}

/**
 * Print move_mount(2) flags
 */
static const char *strmovemntflags(__u32 flags)
{
	static char str[512];
	int i;

	str[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(move_mount_flags_names); i++) {
		if (!(move_mount_flags_names[i].value & flags))
			continue;
		if (str[0])
			strcat(str, " | ");
		strcat(str, move_mount_flags_names[i].name);
	}
	return str;
}

static const char *strcmd(int cmd)
{
	/**
	 * 0: FSCONFIG_SET_FLAG
	 * 8: FSCONFIG_CMD_CREATE_EXCL
	 */
	if (cmd >= 0 && cmd <= 8)
		return fsconfig_cmd_names[cmd];
	return "UNKNOWN";
}

static const char *strerrno(int errnum)
{
	const char *errstr;
	static char ret[32] = {};

	if (!errnum)
		return "0";

	ret[0] = '\0';
	errstr = strerrorname_np(-errnum);
	if (!errstr) {
		snprintf(ret, sizeof(ret), "%d", errnum);
		return ret;
	}

	snprintf(ret, sizeof(ret), "-%s", errstr);
	return ret;
}

static const char *gen_call(const struct event *e)
{
	static char call[10240];

	memset(call, 0, sizeof(call));
	switch (e->op) {
	case UMOUNT:
		snprintf(call, sizeof(call), "umount(\"%s\", %s) = %s",
			 e->umount.dest, strmountflags(e->umount.flags),
			 strerrno(e->ret));
		break;
	case MOUNT:
		snprintf(call, sizeof(call), "mount(\"%s\", \"%s\", \"%s\", %s, \"%s\") = %s",
			 e->mount.src, e->mount.dest, e->mount.fs,
			 strmountflags(e->mount.flags), e->mount.data,
			 strerrno(e->ret));
		break;
	case FSOPEN:
		snprintf(call, sizeof(call), "fsopen(\"%s\", %s) = %s",
			 e->fsopen.fs, strmountflags(e->fsopen.flags),
			 strerrno(e->ret));
		break;
	case FSCONFIG:
		snprintf(call, sizeof(call), "fsconfig(%d, \"%s\", \"%s\", \"%s\", %d) = %s",
			 e->fsconfig.fd, strcmd(e->fsconfig.cmd),
			 e->fsconfig.key, e->fsconfig.value, e->fsconfig.aux,
			 strerrno(e->ret));
		break;
	case FSMOUNT:
		snprintf(call, sizeof(call), "fsmount(%d, \"%s\", \"%s\") = %s",
			 e->fsmount.fs_fd, strfsmntflags(e->fsmount.flags),
			 strfsmntattrflags(e->fsmount.attr_flags),
			 strerrno(e->ret));
		break;
	case MOVE_MOUNT:
		snprintf(call, sizeof(call), "move_mount(%d, \"%s\", %s, \"%s\", \"%s\") = %s",
			 e->move_mount.from_dfd, e->move_mount.from_pathname,
			 strfd(e->move_mount.to_dfd), e->move_mount.to_pathname,
			 strmovemntflags(e->move_mount.flags),
			 strerrno(e->ret));
		break;
	default:
		break;
	}
	return call;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	const char *indent;
	static const char *op_name[] = {
		[MOUNT] = "MOUNT",
		[UMOUNT] = "UMOUNT",
		[FSOPEN] = "FSOPEN",
		[FSCONFIG] = "FSCONFIG",
		[FSMOUNT] = "FSMOUNT",
		[MOVE_MOUNT] = "MOVE_MOUNT",
	};

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S ", tm);
		printf("%s", ts);
		indent = "    ";
	} else {
		indent = "";
	}
	if (!output_vertically) {
		printf("%-16s %-7d %-7d %-11u %s\n",
		       e->comm, e->pid, e->tid, e->mnt_ns, gen_call(e));
		return 0;
	}
	if (emit_timestamp)
		printf("\n");
	printf("%sPID:    %d\n", indent, e->pid);
	printf("%sTID:    %d\n", indent, e->tid);
	printf("%sCOMM:   %s\n", indent, e->comm);
	printf("%sOP:     %s\n", indent, op_name[e->op]);
	printf("%sRET:    %s\n", indent, strerrno(e->ret));
	printf("%sLAT:    %lldus\n", indent, e->delta / 1000);
	printf("%sMNT_NS: %u\n", indent, e->mnt_ns);
	switch (e->op) {
	case MOUNT:
		printf("%sFS:     %s\n", indent, e->mount.fs);
		printf("%sSOURCE: %s\n", indent, e->mount.src);
		printf("%sTARGET: %s\n", indent, e->mount.dest);
		printf("%sDATA:   %s\n", indent, e->mount.data);
		printf("%sFLAGS:  %s\n", indent, strmountflags(e->mount.flags));
		break;
	case UMOUNT:
		printf("%sTARGET: %s\n", indent, e->umount.dest);
		printf("%sFLAGS:  %s\n", indent, strmountflags(e->umount.flags));
		break;
	case FSOPEN:
		printf("%sFS:     %s\n", indent, e->fsopen.fs);
		printf("%sFLAGS:  %s\n", indent, strmountflags(e->fsopen.flags));
		break;
	case FSCONFIG:
		printf("%sFD:     %d\n", indent, e->fsconfig.fd);
		printf("%sCMD:    %s\n", indent, strcmd(e->fsconfig.cmd));
		printf("%sKEY:    %s\n", indent, e->fsconfig.key);
		printf("%sVALUE:  %s\n", indent, e->fsconfig.value);
		break;
	case FSMOUNT:
		printf("%sFS_FD:       %d\n", indent, e->fsmount.fs_fd);
		printf("%sFLAGS:       %s\n", indent, strfsmntflags(e->fsmount.flags));
		printf("%sATTR_FLAGS:  %s\n", indent, strfsmntattrflags(e->fsmount.attr_flags));
		break;
	case MOVE_MOUNT:
		printf("%sFROM_DFD:       %d\n", indent, e->move_mount.from_dfd);
		printf("%sFROM_PATHNAME:  %s\n", indent, e->move_mount.from_pathname);
		printf("%sTO_DFD:         %d\n", indent, e->move_mount.to_dfd);
		printf("%sTO_PATHNAME:    %s\n", indent, e->move_mount.to_pathname);
		printf("%sFLAGS:          %s\n", indent, strmovemntflags(e->move_mount.flags));
		break;
	default:
		break;
	}
	printf("\n");

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct mountsnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = mountsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warn("failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	/**
	 * kernel commit 24dcb3d90a1f ("vfs: syscall: Add fsopen() to prepare
	 * for superblock creation") v5.1-rc1-5-g24dcb3d90a1f
	 */
	if (!tracepoint_exists("syscalls", "sys_enter_fsopen")) {
		bpf_program__set_autoload(obj->progs.fsopen_entry, false);
		bpf_program__set_autoload(obj->progs.fsopen_exit, false);
	}

	/**
	 * kernel commit ecdab150fddb ("vfs: syscall: Add fsconfig() for
	 * configuring and managing a context") v5.1-rc1-7-gecdab150fddb
	 */
	if (!tracepoint_exists("syscalls", "sys_enter_fsconfig")) {
		bpf_program__set_autoload(obj->progs.fsconfig_entry, false);
		bpf_program__set_autoload(obj->progs.fsconfig_exit, false);
	}

	/**
	 * kernel commit 93766fbd2696 ("vfs: syscall: Add fsmount() to create
	 * a mount for a superblock") v5.1-rc1-8-g93766fbd2696
	 */
	if (!tracepoint_exists("syscalls", "sys_enter_fsmount")) {
		bpf_program__set_autoload(obj->progs.fsmount_entry, false);
		bpf_program__set_autoload(obj->progs.fsmount_exit, false);
	}

	/**
	 * kernel commit 2db154b3ea8e ("vfs: syscall: Add move_mount(2) to
	 * move mounts around") v5.1-rc1-2-g2db154b3ea8e
	 */
	if (!tracepoint_exists("syscalls", "sys_enter_move_mount")) {
		bpf_program__set_autoload(obj->progs.move_mount_entry, false);
		bpf_program__set_autoload(obj->progs.move_mount_exit, false);
	}

	err = mountsnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = mountsnoop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warn("failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (!output_vertically) {
		if (emit_timestamp)
			printf("%-8s ", "TIME");
		printf("%-16s %-7s %-7s %-11s %s\n", "COMM", "PID", "TID", "MNT_NS", "CALL");
	}

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling ring/perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	mountsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}

"""

```