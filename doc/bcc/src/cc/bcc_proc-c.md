Response:
### 功能列举及执行顺序（10步）

1. **查找可执行文件路径**  
   调用 `bcc_procutils_which`，通过环境变量 `PATH` 遍历，验证文件是否为可执行文件（`bcc_elf_is_exe`），返回完整路径。

2. **判断内存映射是否为文件支持**  
   `bcc_mapping_is_file_backed` 检查 `/proc/pid/maps` 中的映射名称，过滤匿名内存（如堆、栈）。

3. **处理内存映射中的特殊文件（如 memfd）**  
   通过 `_procutils_memfd_path` 解析内存文件描述符（memfd）对应的路径，访问 `/proc/pid/fd` 目录匹配 inode。

4. **解析 ZIP/APK 内嵌文件**  
   `_procfs_find_zip_entry` 处理映射到 ZIP/APK 文件的条目，提取内部文件路径（如 `lib.zip!/file.so`）。

5. **遍历进程的内存映射模块**  
   `bcc_procutils_each_module` 读取 `/proc/pid/maps`，解析每行信息，通过回调处理每个模块（如共享库、可执行文件）。

6. **加载 Perf 映射文件**  
   检查 `/tmp/perf-<pid>.map`，用于动态符号解析（如 JIT 编译的代码）。

7. **解析内核符号表**  
   `bcc_procutils_each_ksym` 读取 `/proc/kallsyms`，过滤内核函数符号，供 eBPF 程序使用。

8. **加载 LD 库缓存**  
   `load_ld_cache` 解析 `/etc/ld.so.cache`，加速共享库路径查找。

9. **查找共享库路径**  
   `bcc_procutils_which_so` 结合进程内存映射和 LD 缓存，定位库文件（如 `libc.so`）。

10. **检测进程编程语言**  
    `bcc_procutils_language` 分析 `/proc/pid/exe` 和内存映射，识别语言特征（如 Python、Java）。

---

### eBPF Hook 点及信息

1. **Hook 点：用户态文件访问**  
   - **函数名**: `bcc_procutils_each_module` → `fopen("/proc/pid/maps")`  
   - **读取信息**: 进程内存映射的地址范围、权限、文件路径、设备号、inode。  
     *示例*: `/lib/x86_64-linux-gnu/libc.so.6`（文件路径）、`1234`（PID）。

2. **Hook 点：内核符号解析**  
   - **函数名**: `bcc_procutils_each_ksym` → `fopen("/proc/kallsyms")`  
   - **读取信息**: 内核函数符号名、所属模块（如 `kernel`）、虚拟地址。  
     *示例*: `sys_open`（函数名）、`0xffffffff81345678`（地址）。

3. **Hook 点：共享库查找**  
   - **函数名**: `bcc_procutils_which_so` → `open("/etc/ld.so.cache")`  
   - **读取信息**: 共享库名称、缓存路径（如 `/usr/lib/libz.so.1`）。

---

### 逻辑推理示例

- **输入**: `libname="c", pid=1234`  
  **输出**: `/lib/x86_64-linux-gnu/libc.so.6`  
  **过程**: 通过 `which_so_in_process` 遍历 `/proc/1234/maps`，找到包含 `libc.so` 的映射路径。

- **输入**: `binpath="ls"`  
  **输出**: `/usr/bin/ls`  
  **过程**: `bcc_procutils_which` 遍历 `PATH`，验证 `/usr/bin/ls` 为可执行文件。

---

### 常见使用错误

1. **路径缓冲区溢出**  
   *错误示例*: 使用 `strcpy` 未检查长度，导致 `PATH_MAX` 溢出。  
   *修复*: 改用 `snprintf` 并检查返回值。

2. **未处理命名空间**  
   *错误示例*: 直接访问 `/proc/pid/root` 未进入进程的挂载命名空间，路径解析失败。  
   *修复*: 使用 `enter_ns` 参数控制是否切换命名空间。

3. **忽略 ZIP 偏移修正**  
   *错误示例*: 解析 ZIP 内文件时未调整 `mod.file_offset`，导致符号错误。  
   *修复*: 调用 `_procfs_find_zip_entry` 修正偏移。

---

### Syscall 调试线索

1. **访问 `/proc` 文件系统**  
   - **Syscall**: `open("/proc/1234/maps", O_RDONLY)` → 读取进程内存布局。  
   - **调试**: 检查 `fopen` 返回值，确认进程存在且权限足够。

2. **读取内核符号**  
   - **Syscall**: `open("/proc/kallsyms", O_RDONLY)` → 解析内核函数地址。  
   - **调试**: 确认 `kptr_restrict=0` 允许读取内核地址。

3. **查找共享库**  
   - **Syscall**: `open("/etc/ld.so.cache", O_RDONLY)` → 加载库缓存。  
   - **调试**: 检查缓存文件格式是否兼容（如 `ld_cache1` vs `ld_cache2`）。

---

### 总结

此文件是 BCC 的核心组件，负责进程信息解析和符号处理，通过 `/proc` 和系统调用获取数据，结合多种缓存机制优化性能。开发者需注意路径处理、命名空间隔离和文件格式兼容性。
### 提示词
```
这是目录为bcc/src/cc/bcc_proc.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```c
/*
 * Copyright (c) 2016 GitHub, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bcc_proc.h"

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_zip.h"

#ifdef __x86_64__
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
const unsigned long long kernelAddrSpace = 0x00ffffffffffffff;
#else
const unsigned long long kernelAddrSpace = 0x0;
#endif

char *bcc_procutils_which(const char *binpath) {
  char buffer[PATH_MAX];
  const char *PATH;

  if (strchr(binpath, '/'))
    return bcc_elf_is_exe(binpath) ? strdup(binpath) : 0;

  if (!(PATH = getenv("PATH")))
    return 0;

  while (PATH) {
    const char *next = strchr(PATH, ':') ?: strchr(PATH, '\0');
    const size_t path_len = next - PATH;

    if (path_len) {
      int ret = snprintf(buffer, sizeof(buffer), "%.*s/%s",
	                  (int)path_len, PATH, binpath);
      if (ret < 0 || ret >= sizeof(buffer))
        return 0;

      if (bcc_elf_is_exe(buffer))
        return strdup(buffer);
    }

    PATH = *next ? (next + 1) : 0;
  }

  return 0;
}

#define STARTS_WITH(mapname, prefix) (!strncmp(mapname, prefix, sizeof(prefix)-1))

int bcc_mapping_is_file_backed(const char *mapname) {
  return mapname[0] && !(
    STARTS_WITH(mapname, "//anon") ||
    STARTS_WITH(mapname, "/dev/zero") ||
    STARTS_WITH(mapname, "/anon_hugepage") ||
    STARTS_WITH(mapname, "[stack") ||
    STARTS_WITH(mapname, "/SYSV") ||
    STARTS_WITH(mapname, "[heap]") ||
    STARTS_WITH(mapname, "[vsyscall]"));
}

/*
Finds a file descriptor for a given inode if it's a memory-backed fd.
*/
static char *_procutils_memfd_path(const int pid, const uint64_t inum) {
  char path_buffer[PATH_MAX + 1];
  char *path = NULL;
  char *dirstr;
  DIR *dirstream;
  struct stat sb;
  struct dirent *dent;

  snprintf(path_buffer, (PATH_MAX + 1), "/proc/%d/fd", pid);
  dirstr = malloc(strlen(path_buffer) + 1);
  strcpy(dirstr, path_buffer);
  dirstream = opendir(dirstr);

  if (dirstream == NULL) {
    free(dirstr);
    return NULL;
  }

  while (path == NULL && (dent = readdir(dirstream)) != NULL) {
    snprintf(path_buffer, (PATH_MAX + 1), "%s/%s", dirstr, dent->d_name);
    if (stat(path_buffer, &sb) == -1)
      continue;

    if (sb.st_ino == inum) {
      char *pid_fd_path = malloc(strlen(path_buffer) + 1);
      strcpy(pid_fd_path, path_buffer);
      path = pid_fd_path;
    }
  }
  closedir(dirstream);
  free(dirstr);

  return path;
}

static int _procfs_might_be_zip_path(const char *path) {
  return strstr(path, ".zip") || strstr(path, ".apk");
}

static char *_procfs_find_zip_entry(const char *path, int pid,
                                    uint32_t *offset) {
  char ns_relative_path[PATH_MAX];
  int rc = snprintf(ns_relative_path, sizeof(ns_relative_path),
                    "/proc/%d/root%s", pid, path);
  if (rc < 0 || rc >= sizeof(ns_relative_path)) {
    return NULL;
  }

  struct bcc_zip_archive *archive = bcc_zip_archive_open(ns_relative_path);
  if (archive == NULL) {
    return NULL;
  }

  struct bcc_zip_entry entry;
  if (bcc_zip_archive_find_entry_at_offset(archive, *offset, &entry) ||
      entry.compression) {
    bcc_zip_archive_close(archive);
    return NULL;
  }

  char *result = malloc(strlen(path) + entry.name_length + 3);
  if (result == NULL) {
    bcc_zip_archive_close(archive);
    return NULL;
  }

  sprintf(result, "%s!/%.*s", path, entry.name_length, entry.name);
  *offset -= entry.data_offset;
  bcc_zip_archive_close(archive);
  return result;
}

// return: 0 -> callback returned < 0, stopped iterating
//        -1 -> callback never indicated to stop
int _procfs_maps_each_module(FILE *procmap, int pid,
                             bcc_procutils_modulecb callback, void *payload) {
  char buf[PATH_MAX + 1], perm[5];
  char *name, *resolved_name;
  mod_info mod;
  uint8_t enter_ns;
  while (true) {
    enter_ns = 1;
    buf[0] = '\0';
    // From fs/proc/task_mmu.c:show_map_vma
    if (fscanf(procmap,
               "%" PRIx64 "-%" PRIx64 " %4s %llx %" PRIx64 ":%" PRIx64
               " %" PRIu64 "%[^\n]",
               &mod.start_addr, &mod.end_addr, perm, &mod.file_offset,
               &mod.dev_major, &mod.dev_minor, &mod.inode, buf) != 8)
      break;

    if (perm[2] != 'x')
      continue;

    name = buf;
    while (isspace(*name))
      name++;
    mod.name = name;
    if (!bcc_mapping_is_file_backed(name))
      continue;

    resolved_name = NULL;
    if (strstr(name, "/memfd:")) {
      resolved_name = _procutils_memfd_path(pid, mod.inode);
      if (resolved_name != NULL) {
        enter_ns = 0;
      }
    } else if (_procfs_might_be_zip_path(mod.name)) {
      uint32_t zip_entry_offset = mod.file_offset;
      resolved_name = _procfs_find_zip_entry(mod.name, pid, &zip_entry_offset);
      if (resolved_name != NULL) {
        mod.file_offset = zip_entry_offset;
      }
    }

    if (resolved_name != NULL) {
      strncpy(buf, resolved_name, PATH_MAX);
      buf[PATH_MAX] = 0;
      free(resolved_name);
      mod.name = buf;
    }

    if (callback(&mod, enter_ns, payload) < 0)
      return 0;
  }

  return -1;
}

int bcc_procutils_each_module(int pid, bcc_procutils_modulecb callback,
                              void *payload) {
  char procmap_filename[128];
  FILE *procmap;
  snprintf(procmap_filename, sizeof(procmap_filename), "/proc/%ld/maps",
           (long)pid);
  procmap = fopen(procmap_filename, "r");
  if (!procmap)
    return -1;

  _procfs_maps_each_module(procmap, pid, callback, payload);

  // Address mapping for the entire address space maybe in /tmp/perf-<PID>.map
  // This will be used if symbols aren't resolved in an earlier mapping.
  char map_path[4096];
  // Try perf-<PID>.map path with process's mount namespace, chroot and NSPID,
  // in case it is generated by the process itself.
  mod_info mod;
  memset(&mod, 0, sizeof(mod_info));
  if (bcc_perf_map_path(map_path, sizeof(map_path), pid)) {
    mod.name = map_path;
    mod.end_addr = -1;
    if (callback(&mod, 1, payload) < 0)
      goto done;
  }
  // Try perf-<PID>.map path with global root and PID, in case it is generated
  // by other Process. Avoid checking mount namespace for this.
  memset(&mod, 0, sizeof(mod_info));
  int res = snprintf(map_path, 4096, "/tmp/perf-%d.map", pid);
  if (res > 0 && res < 4096) {
    mod.name = map_path;
    mod.end_addr = -1;
    if (callback(&mod, 0, payload) < 0)
      goto done;
  }

done:
  fclose(procmap);
  return 0;
}

int bcc_procutils_each_ksym(bcc_procutils_ksymcb callback, void *payload) {
  char line[2048];
  char *symname, *endsym, *modname, *endmod = NULL;
  FILE *kallsyms;
  unsigned long long addr;

  kallsyms = fopen("/proc/kallsyms", "r");
  if (!kallsyms)
    return -1;

  while (fgets(line, sizeof(line), kallsyms)) {
    addr = strtoull(line, &symname, 16);
    if (addr == 0 || addr == ULLONG_MAX)
      continue;
    if (addr < kernelAddrSpace)
      continue;

    symname++;
    // Ignore data symbols
    if (*symname == 'b' || *symname == 'B' || *symname == 'd' ||
        *symname == 'D' || *symname == 'r' || *symname =='R')
      continue;

    endsym = (symname = symname + 2);
    while (*endsym && !isspace(*endsym)) endsym++;
    *endsym = '\0';

    // Parse module name if it's available
    modname = endsym + 1;
    while (*modname && isspace(*endsym)) modname++;

    if (*modname && *modname == '[') {
      endmod = ++modname;
      while (*endmod && *endmod != ']') endmod++;
      if (*endmod)
        *(endmod) = '\0';
      else
        endmod = NULL;
    }

    if (!endmod)
      modname = "kernel";

    callback(symname, modname, addr, payload);
  }

  fclose(kallsyms);
  return 0;
}

#define CACHE1_HEADER "ld.so-1.7.0"
#define CACHE1_HEADER_LEN (sizeof(CACHE1_HEADER) - 1)

#define CACHE2_HEADER "glibc-ld.so.cache"
#define CACHE2_HEADER_LEN (sizeof(CACHE2_HEADER) - 1)
#define CACHE2_VERSION "1.1"

struct ld_cache1_entry {
  int32_t flags;
  uint32_t key;
  uint32_t value;
};

struct ld_cache1 {
  char header[CACHE1_HEADER_LEN];
  uint32_t entry_count;
  struct ld_cache1_entry entries[0];
};

struct ld_cache2_entry {
  int32_t flags;
  uint32_t key;
  uint32_t value;
  uint32_t pad1_;
  uint64_t pad2_;
};

struct ld_cache2 {
  char header[CACHE2_HEADER_LEN];
  char version[3];
  uint32_t entry_count;
  uint32_t string_table_len;
  uint32_t pad_[5];
  struct ld_cache2_entry entries[0];
};

static int lib_cache_count;
static struct ld_lib {
  char *libname;
  char *path;
  int flags;
} * lib_cache;

static int read_cache1(const char *ld_map) {
  struct ld_cache1 *ldcache = (struct ld_cache1 *)ld_map;
  const char *ldstrings =
      (const char *)(ldcache->entries + ldcache->entry_count);
  uint32_t i;

  lib_cache =
      (struct ld_lib *)malloc(ldcache->entry_count * sizeof(struct ld_lib));
  lib_cache_count = (int)ldcache->entry_count;

  for (i = 0; i < ldcache->entry_count; ++i) {
    const char *key = ldstrings + ldcache->entries[i].key;
    const char *val = ldstrings + ldcache->entries[i].value;
    const int flags = ldcache->entries[i].flags;

    lib_cache[i].libname = strdup(key);
    lib_cache[i].path = strdup(val);
    lib_cache[i].flags = flags;
  }
  return 0;
}

static int read_cache2(const char *ld_map) {
  struct ld_cache2 *ldcache = (struct ld_cache2 *)ld_map;
  uint32_t i;

  if (memcmp(ld_map, CACHE2_HEADER, CACHE2_HEADER_LEN))
    return -1;

  lib_cache =
      (struct ld_lib *)malloc(ldcache->entry_count * sizeof(struct ld_lib));
  lib_cache_count = (int)ldcache->entry_count;

  for (i = 0; i < ldcache->entry_count; ++i) {
    const char *key = ld_map + ldcache->entries[i].key;
    const char *val = ld_map + ldcache->entries[i].value;
    const int flags = ldcache->entries[i].flags;

    lib_cache[i].libname = strdup(key);
    lib_cache[i].path = strdup(val);
    lib_cache[i].flags = flags;
  }
  return 0;
}

static int load_ld_cache(const char *cache_path) {
  struct stat st;
  size_t ld_size;
  const char *ld_map;
  int ret, fd = open(cache_path, O_RDONLY);

  if (fd < 0)
    return -1;

  if (fstat(fd, &st) < 0 || st.st_size < sizeof(struct ld_cache1)) {
    close(fd);
    return -1;
  }

  ld_size = st.st_size;
  ld_map = (const char *)mmap(NULL, ld_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (ld_map == MAP_FAILED) {
    close(fd);
    return -1;
  }

  if (memcmp(ld_map, CACHE1_HEADER, CACHE1_HEADER_LEN) == 0) {
    const struct ld_cache1 *cache1 = (struct ld_cache1 *)ld_map;
    size_t cache1_len = sizeof(struct ld_cache1) +
                        (cache1->entry_count * sizeof(struct ld_cache1_entry));
    cache1_len = (cache1_len + 0x7) & ~0x7ULL;

    if (ld_size > (cache1_len + sizeof(struct ld_cache2)))
      ret = read_cache2(ld_map + cache1_len);
    else
      ret = read_cache1(ld_map);
  } else {
    ret = read_cache2(ld_map);
  }

  munmap((void *)ld_map, ld_size);
  close(fd);
  return ret;
}

#define LD_SO_CACHE "/etc/ld.so.cache"
#define FLAG_TYPE_MASK 0x00ff
#define TYPE_ELF_LIBC6 0x0003
#define FLAG_ABI_MASK 0xff00
#define ABI_SPARC_LIB64 0x0100
#define ABI_IA64_LIB64 0x0200
#define ABI_X8664_LIB64 0x0300
#define ABI_S390_LIB64 0x0400
#define ABI_POWERPC_LIB64 0x0500
#define ABI_AARCH64_LIB64 0x0a00

static bool match_so_flags(int flags) {
  if ((flags & FLAG_TYPE_MASK) != TYPE_ELF_LIBC6)
    return false;

  switch (flags & FLAG_ABI_MASK) {
  case ABI_SPARC_LIB64:
  case ABI_IA64_LIB64:
  case ABI_X8664_LIB64:
  case ABI_S390_LIB64:
  case ABI_POWERPC_LIB64:
  case ABI_AARCH64_LIB64:
    return (sizeof(void *) == 8);
  }

  return sizeof(void *) == 4;
}

static bool which_so_in_process(const char* libname, int pid, char* libpath) {
  int ret, found = false;
  char endline[4096], *mapname = NULL, *newline;
  char mappings_file[128];
  const size_t search_len = strlen(libname) + strlen("/lib.");
  char search1[search_len + 1];
  char search2[search_len + 1];

  snprintf(mappings_file, sizeof(mappings_file), "/proc/%ld/maps", (long)pid);
  FILE *fp = fopen(mappings_file, "r");
  if (!fp)
    return NULL;

  snprintf(search1, search_len + 1, "/lib%s.", libname);
  snprintf(search2, search_len + 1, "/lib%s-", libname);

  do {
    ret = fscanf(fp, "%*x-%*x %*s %*x %*s %*d");
    if (!fgets(endline, sizeof(endline), fp))
      break;

    mapname = endline;
    newline = strchr(endline, '\n');
    if (newline)
      newline[0] = '\0';

    while (isspace(mapname[0])) mapname++;

    if (strstr(mapname, ".so") && (strstr(mapname, search1) ||
                                   strstr(mapname, search2))) {
      const size_t mapnamelen = strlen(mapname);
      if (mapnamelen >= PATH_MAX) {
        fprintf(stderr, "Found mapped library path is too long\n");
        break;
      }
      found = true;
      memcpy(libpath, mapname, mapnamelen + 1);
      break;
    }
  } while (ret != EOF);

  fclose(fp);
  return found;
}

static bool which_so_in_ldconfig_cache(const char* libname, char* libpath) {
  const size_t soname_len = strlen(libname) + strlen("lib.so");
  char soname[soname_len + 1];
  int i;

  if (lib_cache_count < 0)
    return false;

  if (!lib_cache_count && load_ld_cache(LD_SO_CACHE) < 0) {
    lib_cache_count = -1;
    return false;
  }

  snprintf(soname, soname_len + 1, "lib%s.so", libname);

  for (i = 0; i < lib_cache_count; ++i) {
    if (!strncmp(lib_cache[i].libname, soname, soname_len) &&
        match_so_flags(lib_cache[i].flags)) {
      
      const char* path = lib_cache[i].path;
      const size_t pathlen = strlen(path);
      if (pathlen >= PATH_MAX) {
        fprintf(stderr, "Found library path is too long\n");
        return false;
      }
      memcpy(libpath, path, pathlen + 1);
      return true;
    }
  }

  return false;
}

char *bcc_procutils_which_so(const char *libname, int pid) {
  char libpath[PATH_MAX];

  if (strchr(libname, '/'))
    return strdup(libname);

  if (pid && which_so_in_process(libname, pid, libpath))
    return strdup(libpath);

  if (which_so_in_ldconfig_cache(libname, libpath))
    return strdup(libpath);

  return NULL;
}

char *bcc_procutils_which_so_in_process(const char *libname, int pid) {
  char libpath[PATH_MAX];
  if (pid && which_so_in_process(libname, pid, libpath))
    return strdup(libpath);
  return NULL;
}

void bcc_procutils_free(const char *ptr) {
  free((void *)ptr);
}

/* Detects the following languages + C. */
const char *languages[] = {"java", "node", "perl", "php", "python", "ruby"};
const char *language_c = "c";
const int nb_languages = 6;

const char *bcc_procutils_language(int pid) {
  char procfilename[24], line[4096], pathname[32], *str;
  FILE *procfile;
  int i, ret;

  /* Look for clues in the absolute path to the executable. */
  snprintf(procfilename, sizeof(procfilename), "/proc/%ld/exe", (long)pid);
  if (realpath(procfilename, line)) {
    for (i = 0; i < nb_languages; i++)
      if (strstr(line, languages[i]))
        return languages[i];
  }

  snprintf(procfilename, sizeof(procfilename), "/proc/%ld/maps", (long)pid);
  procfile = fopen(procfilename, "r");
  if (!procfile)
    return NULL;

  /* Look for clues in memory mappings. */
  bool libc = false;
  do {
    char perm[8], dev[8];
    long long begin, end, size, inode;
    ret = fscanf(procfile, "%llx-%llx %s %llx %s %lld", &begin, &end, perm,
                 &size, dev, &inode);
    if (!fgets(line, sizeof(line), procfile))
      break;
    if (ret == 6) {
      char *mapname = line;
      char *newline = strchr(line, '\n');
      if (newline)
        newline[0] = '\0';
      while (isspace(mapname[0])) mapname++;
      for (i = 0; i < nb_languages; i++) {
        snprintf(pathname, sizeof(pathname), "/lib%s", languages[i]);
        if (strstr(mapname, pathname)) {
          fclose(procfile);
          return languages[i];
	}
        if ((str = strstr(mapname, "libc")) &&
            (str[4] == '-' || str[4] == '.'))
          libc = true;
      }
    }
  } while (ret && ret != EOF);

  fclose(procfile);

  /* Return C as the language if libc was found and nothing else. */
  return libc ? language_c : NULL;
}
```