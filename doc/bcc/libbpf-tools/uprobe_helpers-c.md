Response:
### 功能说明
1. **解析进程二进制路径**：通过 `/proc/<pid>/exe` 获取进程的可执行文件路径。
2. **解析动态库路径**：通过 `/proc/<pid>/maps` 查找进程加载的特定动态库路径。
3. **搜索系统命令路径**：通过 `which` 命令查找用户态程序的绝对路径。
4. **智能路径解析**：根据 `pid` 和 `binary` 参数组合自动选择上述方法。
5. **ELF 文件操作**：打开、关闭 ELF 文件，验证 ELF 格式。
6. **符号偏移计算**：从 ELF 文件中提取函数符号的偏移量，用于用户态探针（uprobe）挂载。

---

### 执行顺序（10 步）
1. **用户调用 `resolve_binary_path`**  
   输入 `binary` 和 `pid`，确定目标类型（进程二进制/动态库/系统命令）。
2. **分支逻辑判断**  
   - 若 `binary` 为空且 `pid` 有效：调用 `get_pid_binary_path`。
   - 若 `binary` 非空且 `pid` 有效：调用 `get_pid_lib_path`。
   - 若 `pid=0` 且 `binary` 非空：调用 `which_program`。
3. **读取 `/proc` 文件系统**  
   通过 `/proc/<pid>/exe` 或 `/proc/<pid>/maps` 获取路径信息。
4. **路径截断检查**  
   验证 `readlink` 或 `fgets` 的结果，防止缓冲区溢出。
5. **ELF 文件打开与验证**  
   使用 `open_elf` 打开目标文件，检查 ELF 格式合法性。
6. **符号表遍历**  
   在 ELF 的 `.symtab` 或 `.dynsym` 节中搜索目标函数符号。
7. **函数类型过滤**  
   跳过非 `STT_FUNC` 类型的符号（如变量、调试符号）。
8. **计算内存偏移**  
   针对可执行文件或动态库（`ET_EXEC/ET_DYN`），将虚拟地址转换为文件偏移。
9. **返回偏移量**  
   输出函数在 ELF 文件中的物理偏移，供 uprobe 使用。
10. **资源清理**  
    关闭 ELF 句柄和文件描述符，释放资源。

---

### eBPF Hook 点与信息
| Hook 点            | 函数名                | 有效信息                          | 信息说明                  |
|---------------------|-----------------------|-----------------------------------|---------------------------|
| 用户态函数入口/退出 | uprobe/uretprobe      | 函数偏移量（来自 `get_elf_func_offset`） | 目标函数在 ELF 中的偏移   |
| 进程执行路径        | `resolve_binary_path` | 二进制路径（如 `/usr/bin/bash`）  | 进程 PID 或库名解析结果   |
| 动态库加载事件      | `get_pid_lib_path`    | 库路径（如 `/lib/x86_64-libc.so`）| 通过 `/proc/<pid>/maps` 解析 |

---

### 输入输出示例
#### 场景：跟踪进程 1234 的 `malloc` 函数
1. **输入**  
   ```c
   resolve_binary_path("c", 1234, path_buf, 1024);
   ```
2. **输出**  
   `path_buf = "/usr/lib/libc.so.6"`  
   `get_elf_func_offset` 返回 `malloc` 的偏移量 `0x12345`。

---

### 常见错误示例
1. **PID 不存在**  
   ```bash
   # 输入：pid=99999（不存在）
   get_pid_binary_path(99999, ...)
   # 输出：warn("No such pid 99999")
   ```
2. **路径缓冲区过小**  
   ```c
   char path[10];
   get_pid_lib_path(1234, "c", path, 10);
   # 输出：warn("path size too small")
   ```
3. **拼写错误的库名**  
   ```c
   resolve_binary_path("libmytpyo.so", 1234, ...)
   # 输出：warn("Cannot find library libmytpyo.so")
   ```

---

### Syscall 调试线索
1. **进程启动**  
   - `fork()` → `execve()` 加载可执行文件。
   - `execve` 触发 ELF 解析，内核记录 `/proc/<pid>/exe`。
2. **动态库加载**  
   - `ld.so` 通过 `mmap` 加载共享库，更新 `/proc/<pid>/maps`。
3. **BCC 工具触发**  
   - 用户调用 `resolve_binary_path` 解析路径。
   - 读取 `/proc` 文件系统，确认目标存在。
   - 解析 ELF 获取函数偏移，生成 uprobe 事件。
4. **内核注册 uprobe**  
   - 通过 `perf_event_open` 将偏移量注册到内核。
   - eBPF 程序在函数入口/退出时触发回调。
Prompt: 
```
这是目录为bcc/libbpf-tools/uprobe_helpers.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Google LLC. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <gelf.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

/*
 * Returns 0 on success; -1 on failure.  On sucess, returns via `path` the full
 * path to the program for pid.
 */
int get_pid_binary_path(pid_t pid, char *path, size_t path_sz)
{
	ssize_t ret;
	char proc_pid_exe[32];

	if (snprintf(proc_pid_exe, sizeof(proc_pid_exe), "/proc/%d/exe", pid)
	    >= sizeof(proc_pid_exe)) {
		warn("snprintf /proc/PID/exe failed");
		return -1;
	}
	ret = readlink(proc_pid_exe, path, path_sz);
	if (ret < 0) {
		warn("No such pid %d\n", pid);
		return -1;
	}
	if (ret >= path_sz) {
		warn("readlink truncation");
		return -1;
	}
	path[ret] = '\0';

	return 0;
}

/*
 * Returns 0 on success; -1 on failure.  On success, returns via `path` the full
 * path to a library matching the name `lib` that is loaded into pid's address
 * space.
 */
int get_pid_lib_path(pid_t pid, const char *lib, char *path, size_t path_sz)
{
	FILE *maps;
	char *p;
	char proc_pid_maps[32];
	char line_buf[1024];
	char path_buf[1024];

	if (snprintf(proc_pid_maps, sizeof(proc_pid_maps), "/proc/%d/maps", pid)
	    >= sizeof(proc_pid_maps)) {
		warn("snprintf /proc/PID/maps failed");
		return -1;
	}
	maps = fopen(proc_pid_maps, "r");
	if (!maps) {
		warn("No such pid %d\n", pid);
		return -1;
	}
	while (fgets(line_buf, sizeof(line_buf), maps)) {
		if (sscanf(line_buf, "%*x-%*x %*s %*x %*s %*u %s", path_buf) != 1)
			continue;
		/* e.g. /usr/lib/x86_64-linux-gnu/libc-2.31.so */
		p = strrchr(path_buf, '/');
		if (!p)
			continue;
		if (strncmp(p, "/lib", 4))
			continue;
		p += 4;
		if (strncmp(lib, p, strlen(lib)))
			continue;
		p += strlen(lib);
		/* libraries can have - or . after the name */
		if (*p != '.' && *p != '-')
			continue;
		if (strnlen(path_buf, 1024) >= path_sz) {
			warn("path size too small\n");
			return -1;
		}
		strcpy(path, path_buf);
		fclose(maps);
		return 0;
	}

	warn("Cannot find library %s\n", lib);
	fclose(maps);
	return -1;
}

/*
 * Returns 0 on success; -1 on failure.  On success, returns via `path` the full
 * path to the program.
 */
static int which_program(const char *prog, char *path, size_t path_sz)
{
	FILE *which;
	char cmd[100];

	if (snprintf(cmd, sizeof(cmd), "which %s", prog) >= sizeof(cmd)) {
		warn("snprintf which prog failed");
		return -1;
	}
	which = popen(cmd, "r");
	if (!which) {
		warn("which failed");
		return -1;
	}
	if (!fgets(path, path_sz, which)) {
		warn("fgets which failed");
		pclose(which);
		return -1;
	}
	/* which has a \n at the end of the string */
	path[strlen(path) - 1] = '\0';
	pclose(which);
	return 0;
}

/*
 * Returns 0 on success; -1 on failure.  On success, returns via `path` the full
 * path to the binary for the given pid.
 * 1) pid == x, binary == ""    : returns the path to x's program
 * 2) pid == x, binary == "foo" : returns the path to libfoo linked in x
 * 3) pid == 0, binary == ""    : failure: need a pid or a binary
 * 4) pid == 0, binary == "bar" : returns the path to `which bar`
 *
 * For case 4), ideally we'd like to search for libbar too, but we don't support
 * that yet.
 */
int resolve_binary_path(const char *binary, pid_t pid, char *path, size_t path_sz)
{
	if (!strcmp(binary, "")) {
		if (!pid) {
			warn("Uprobes need a pid or a binary\n");
			return -1;
		}
		return get_pid_binary_path(pid, path, path_sz);
	}
	if (pid)
		return get_pid_lib_path(pid, binary, path, path_sz);

	if (which_program(binary, path, path_sz)) {
		/*
		 * If the user is tracing a program by name, we can find it.
		 * But we can't find a library by name yet.  We'd need to parse
		 * ld.so.cache or something similar.
		 */
		warn("Can't find %s (Need a PID if this is a library)\n", binary);
		return -1;
	}
	return 0;
}

/*
 * Opens an elf at `path` of kind ELF_K_ELF.  Returns NULL on failure.  On
 * success, close with close_elf(e, fd_close).
 */
Elf *open_elf(const char *path, int *fd_close)
{
	int fd;
	Elf *e;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		warn("elf init failed\n");
		return NULL;
	}
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		warn("Could not open %s\n", path);
		return NULL;
	}
	e = elf_begin(fd, ELF_C_READ, NULL);
	if (!e) {
		warn("elf_begin failed: %s\n", elf_errmsg(-1));
		close(fd);
		return NULL;
	}
	if (elf_kind(e) != ELF_K_ELF) {
		warn("elf kind %d is not ELF_K_ELF\n", elf_kind(e));
		elf_end(e);
		close(fd);
		return NULL;
	}
	*fd_close = fd;
	return e;
}

Elf *open_elf_by_fd(int fd)
{
	Elf *e;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		warn("elf init failed\n");
		return NULL;
	}
	e = elf_begin(fd, ELF_C_READ, NULL);
	if (!e) {
		warn("elf_begin failed: %s\n", elf_errmsg(-1));
		close(fd);
		return NULL;
	}
	if (elf_kind(e) != ELF_K_ELF) {
		warn("elf kind %d is not ELF_K_ELF\n", elf_kind(e));
		elf_end(e);
		close(fd);
		return NULL;
	}
	return e;
}

void close_elf(Elf *e, int fd_close)
{
	elf_end(e);
	close(fd_close);
}

/* Returns the offset of a function in the elf file `path`, or -1 on failure. */
off_t get_elf_func_offset(const char *path, const char *func)
{
	off_t ret = -1;
	int i, fd = -1;
	Elf *e;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr[1];
	GElf_Phdr phdr;
	GElf_Sym sym[1];
	size_t shstrndx, nhdrs;
	char *n;

	e = open_elf(path, &fd);

	if (!gelf_getehdr(e, &ehdr))
		goto out;

	if (elf_getshdrstrndx(e, &shstrndx) != 0)
		goto out;

	scn = NULL;
	while ((scn = elf_nextscn(e, scn))) {
		if (!gelf_getshdr(scn, shdr))
			continue;
		if (!(shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM))
			continue;
		data = NULL;
		while ((data = elf_getdata(scn, data))) {
			for (i = 0; gelf_getsym(data, i, sym); i++) {
				n = elf_strptr(e, shdr->sh_link, sym->st_name);
				if (!n)
					continue;
				if (GELF_ST_TYPE(sym->st_info) != STT_FUNC)
					continue;
				if (!strcmp(n, func)) {
					ret = sym->st_value;
					goto check;
				}
			}
		}
	}

check:
	if (ehdr.e_type == ET_EXEC || ehdr.e_type == ET_DYN) {
		if (elf_getphdrnum(e, &nhdrs) != 0) {
			ret = -1;
			goto out;
		}
		for (i = 0; i < (int)nhdrs; i++) {
			if (!gelf_getphdr(e, i, &phdr))
				continue;
			if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
				continue;
			if (phdr.p_vaddr <= ret && ret < (phdr.p_vaddr + phdr.p_memsz)) {
				ret = ret - phdr.p_vaddr + phdr.p_offset;
				goto out;
			}
		}
		ret = -1;
	}
out:
	close_elf(e, fd);
	return ret;
}

"""

```