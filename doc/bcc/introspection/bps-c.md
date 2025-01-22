Response:
### 功能列举
1. **查询系统中所有已加载的BPF程序**：列出程序ID、类型、UID、关联的Map数量、加载时间、名称。
2. **查询单个BPF程序的详细信息**：通过指定程序ID，展示该程序关联的所有Map的详细信息。
3. **支持多种BPF程序类型**：如kprobe、tracepoint、XDP等（通过`prog_type_strings`枚举）。
4. **支持多种Map类型**：如Hash、Array、Perf Event Array等（通过`map_type_strings`枚举）。
5. **错误处理**：处理权限不足（EPERM）、内核不支持（EINVAL）等错误。
6. **时间戳转换**：将内核的`load_time`转换为可读的本地时间。
7. **兼容性处理**：处理未知的程序/Map类型（显示`<type>`）。
8. **内存管理**：动态分配内存存储Map ID列表。
9. **权限检查**：提示需要CAP_SYS_ADMIN权限（需root运行）。
10. **用户交互**：提供命令行参数解析和帮助信息。

---

### 执行顺序（非行号顺序）
1. **解析命令行参数**：检查是否传入`bpf-prog-id`。
2. **选择模式**：调用`print_one_prog`（带参数）或`print_all_progs`（无参数）。
3. **内核交互**：通过`bpf_prog_get_fd_by_id`获取BPF程序的文件描述符。
4. **获取程序信息**：调用`bpf_obj_get_info`填充`bpf_prog_info`结构体。
5. **动态内存分配**：根据`nr_map_ids`分配内存存储关联的Map ID列表。
6. **打印程序信息**：格式化输出程序ID、类型、UID、加载时间等。
7. **遍历关联的Map**：对每个Map ID调用`bpf_map_get_fd_by_id`获取Map信息。
8. **打印Map信息**：输出Map类型、标志、键值大小等。
9. **错误处理**：处理`ENOENT`（程序/Map不存在）、`EPERM`（权限不足）等错误。
10. **资源释放**：关闭文件描述符并释放动态分配的内存。

---

### 假设的输入与输出
**输入示例**：
```bash
$ bps 123  # 查询ID为123的BPF程序
```
**假设输出**：
```
BID      TYPE            UID    #MAPS LoadTime     NAME
     123 kprobe          1000    2    May10/14:30  my_probe

MID      TYPE           FLAGS    KeySz  ValueSz MaxEnts  NAME
     456 hash           0x0        4       8     1024    my_map
     789 perf-ev array  0x1        8      16     4096    events
```

---

### 用户常见错误示例
1. **权限不足**：
   ```bash
   $ bps
   Require CAP_SYS_ADMIN capability. Please retry as root
   ```
2. **无效程序ID**：
   ```bash
   $ bps 99999
   BID:99999 not found
   ```
3. **非数字参数**：
   ```bash
   $ bps abc
   Usage: bps [bpf-prog-id]
   ```

---

### Syscall调试线索
1. **用户调用**：用户执行`bps`或`bps <ID>`。
2. **参数解析**：`main`函数解析参数，调用`print_all_progs`或`print_one_prog`。
3. **获取程序FD**：`bpf_prog_get_fd_by_id`触发`bpf(BPF_PROG_GET_FD_BY_ID)`系统调用。
4. **查询程序信息**：`bpf_obj_get_info`触发`bpf(BPF_OBJ_GET_INFO_BY_FD)`系统调用。
5. **遍历Map ID**：通过`bpf_map_get_fd_by_id`和`bpf_obj_get_info`获取Map信息。
6. **内核路径**：内核通过`bpf_prog_get_info_by_fd`和`bpf_map_get_info_by_fd`返回数据。
7. **错误处理**：若权限不足，内核返回`-EPERM`，工具提示需root运行。

---

### Hook点与有效信息（针对被查询的BPF程序）
| Hook点类型       | 函数名（示例）       | 有效信息                     | 信息含义               |
|------------------|----------------------|------------------------------|------------------------|
| **Kprobe**       | `do_sys_openat2`     | 进程PID、文件路径            | 监控文件打开操作       |
| **Tracepoint**   | `syscalls:sys_enter` | 系统调用号、参数             | 跟踪系统调用入口       |
| **XDP**          | `xdp_do_redirect`    | 网络接口索引、数据包元数据   | 处理网络数据包         |
| **Perf Event**   | `perf_event_output`  | 性能事件数据（如CPU周期）    | 性能分析               |
| **Cgroup SKB**   | `cgroup_skb_ingress` | Cgroup路径、网络包方向       | 控制Cgroup网络流量     |

---

### 关键代码逻辑说明
1. **`print_prog_info`**：
   - 从`bpf_prog_info`中读取`load_time`，转换为本地时间。
   - 若程序类型未知，显示`<type>`（如`<42>`）。
2. **`print_map_info`**：
   - 输出Map的键值大小（`key_size`、`value_size`）和最大条目数（`max_entries`）。
3. **动态内存分配**：
   - 根据`nr_map_ids`动态调整Map ID列表大小（最多重试一次）。
4. **错误处理链**：
   - `handle_get_next_errno`统一处理`ENOENT`、`EINVAL`、`EPERM`等错误。
Prompt: 
```
这是目录为bcc/introspection/bps.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sysexits.h>

#include "libbpf.h"

// TODO: Remove this when CentOS 6 support is not needed anymore
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

static const char * const prog_type_strings[] = {
  [BPF_PROG_TYPE_UNSPEC] = "unspec",
  [BPF_PROG_TYPE_SOCKET_FILTER] = "socket filter",
  [BPF_PROG_TYPE_KPROBE] = "kprobe",
  [BPF_PROG_TYPE_SCHED_CLS] = "sched cls",
  [BPF_PROG_TYPE_SCHED_ACT] = "sched act",
  [BPF_PROG_TYPE_TRACEPOINT] = "tracepoint",
  [BPF_PROG_TYPE_XDP] = "xdp",
  [BPF_PROG_TYPE_PERF_EVENT] = "perf event",
  [BPF_PROG_TYPE_CGROUP_SKB] = "cgroup skb",
  [BPF_PROG_TYPE_CGROUP_SOCK] = "cgroup sock",
  [BPF_PROG_TYPE_LWT_IN] = "lwt in",
  [BPF_PROG_TYPE_LWT_OUT] = "lwt out",
  [BPF_PROG_TYPE_LWT_XMIT] = "lwt xmit",
  [BPF_PROG_TYPE_SOCK_OPS] = "sock ops",
  [BPF_PROG_TYPE_SK_SKB] = "sk skb",
  [BPF_PROG_TYPE_CGROUP_DEVICE] = "cgroup_device",
  [BPF_PROG_TYPE_SK_MSG] = "sk_msg",
  [BPF_PROG_TYPE_RAW_TRACEPOINT] = "raw_tracepoint",
  [BPF_PROG_TYPE_CGROUP_SOCK_ADDR] = "cgroup_sock_addr",
  [BPF_PROG_TYPE_LIRC_MODE2] = "lirc_mode2",
  [BPF_PROG_TYPE_SK_REUSEPORT] = "sk_reuseport",
  [BPF_PROG_TYPE_FLOW_DISSECTOR] = "flow_dissector",
  [BPF_PROG_TYPE_CGROUP_SYSCTL] = "cgroup_sysctl",
  [BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE] = "raw_tracepoint_writable",
  [BPF_PROG_TYPE_CGROUP_SOCKOPT] = "cgroup_sockopt",
  [BPF_PROG_TYPE_TRACING] = "tracing",
  [BPF_PROG_TYPE_STRUCT_OPS] = "struct_ops",
  [BPF_PROG_TYPE_EXT] = "ext",
  [BPF_PROG_TYPE_LSM] = "lsm",
  [BPF_PROG_TYPE_SK_LOOKUP] = "sk_lookup",
  [BPF_PROG_TYPE_SYSCALL] = "syscall",
  [BPF_PROG_TYPE_NETFILTER] = "netfilter",
};

static const char * const map_type_strings[] = {
  [BPF_MAP_TYPE_UNSPEC] = "unspec",
  [BPF_MAP_TYPE_HASH] = "hash",
  [BPF_MAP_TYPE_ARRAY] = "array",
  [BPF_MAP_TYPE_PROG_ARRAY] = "prog array",
  [BPF_MAP_TYPE_PERF_EVENT_ARRAY] = "perf-ev array",
  [BPF_MAP_TYPE_PERCPU_HASH] = "percpu hash",
  [BPF_MAP_TYPE_PERCPU_ARRAY] = "percpu array",
  [BPF_MAP_TYPE_STACK_TRACE] = "stack trace",
  [BPF_MAP_TYPE_CGROUP_ARRAY] = "cgroup array",
  [BPF_MAP_TYPE_LRU_HASH] = "lru hash",
  [BPF_MAP_TYPE_LRU_PERCPU_HASH] = "lru percpu hash",
  [BPF_MAP_TYPE_LPM_TRIE] = "lpm trie",
  [BPF_MAP_TYPE_ARRAY_OF_MAPS] = "array of maps",
  [BPF_MAP_TYPE_HASH_OF_MAPS] = "hash of maps",
  [BPF_MAP_TYPE_DEVMAP] = "devmap",
  [BPF_MAP_TYPE_SOCKMAP] = "sockmap",
  [BPF_MAP_TYPE_CPUMAP] = "cpumap",
  [BPF_MAP_TYPE_SOCKHASH] = "sockhash",
  [BPF_MAP_TYPE_CGROUP_STORAGE] = "cgroup_storage",
  [BPF_MAP_TYPE_REUSEPORT_SOCKARRAY] = "reuseport_sockarray",
  [BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE] = "precpu_cgroup_storage",
  [BPF_MAP_TYPE_QUEUE] = "queue",
  [BPF_MAP_TYPE_STACK] = "stack",
  [BPF_MAP_TYPE_SK_STORAGE] = "sk_storage",
  [BPF_MAP_TYPE_DEVMAP_HASH] = "devmap_hash",
  [BPF_MAP_TYPE_STRUCT_OPS] = "struct_ops",
  [BPF_MAP_TYPE_RINGBUF] = "ringbuf",
  [BPF_MAP_TYPE_INODE_STORAGE] = "inode_storage",
  [BPF_MAP_TYPE_TASK_STORAGE] = "task_storage",
  [BPF_MAP_TYPE_BLOOM_FILTER] = "bloom_filter",
  [BPF_MAP_TYPE_USER_RINGBUF] = "user_ringbuf",
  [BPF_MAP_TYPE_CGRP_STORAGE] = "cgrp_storage",
  [BPF_MAP_TYPE_ARENA] = "arena",
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define LAST_KNOWN_PROG_TYPE (ARRAY_SIZE(prog_type_strings) - 1)
#define LAST_KNOWN_MAP_TYPE (ARRAY_SIZE(map_type_strings) - 1)
#define min(x, y) ((x) < (y) ? (x) : (y))

static inline uint64_t ptr_to_u64(const void *ptr)
{
  return (uint64_t) (unsigned long) ptr;
}

static inline void * u64_to_ptr(uint64_t ptr)
{
  return (void *) (unsigned long ) ptr;
}

static int handle_get_next_errno(int eno)
{
  switch (eno) {
    case ENOENT:
      return 0;
    case EINVAL:
      fprintf(stderr, "Kernel does not support BPF introspection\n");
      return EX_UNAVAILABLE;
    case EPERM:
      fprintf(stderr,
              "Require CAP_SYS_ADMIN capability.  Please retry as root\n");
      return EX_NOPERM;
    default:
      fprintf(stderr, "%s\n", strerror(errno));
      return 1;
  }
}

static void print_prog_hdr(void)
{
  printf("%9s %-15s %8s %6s %-12s %-15s\n",
         "BID", "TYPE", "UID", "#MAPS", "LoadTime", "NAME");
}

static void print_prog_info(const struct bpf_prog_info *prog_info)
{
  struct timespec real_time_ts, boot_time_ts;
  time_t wallclock_load_time = 0;
  char unknown_prog_type[16];
  const char *prog_type;
  char load_time[16];
  struct tm load_tm;

  if (prog_info->type > LAST_KNOWN_PROG_TYPE) {
    snprintf(unknown_prog_type, sizeof(unknown_prog_type), "<%u>",
             prog_info->type);
    unknown_prog_type[sizeof(unknown_prog_type) - 1] = '\0';
    prog_type = unknown_prog_type;
  } else {
    prog_type = prog_type_strings[prog_info->type];
  }

  if (!clock_gettime(CLOCK_REALTIME, &real_time_ts) &&
      !clock_gettime(CLOCK_BOOTTIME, &boot_time_ts) &&
      real_time_ts.tv_sec >= boot_time_ts.tv_sec)
    wallclock_load_time =
      (real_time_ts.tv_sec - boot_time_ts.tv_sec) +
      prog_info->load_time / 1000000000;

  if (wallclock_load_time && localtime_r(&wallclock_load_time, &load_tm))
    strftime(load_time, sizeof(load_time), "%b%d/%H:%M", &load_tm);
  else
    snprintf(load_time, sizeof(load_time), "<%llu>",
             prog_info->load_time / 1000000000);
  load_time[sizeof(load_time) - 1] = '\0';

  if (prog_info->jited_prog_len)
    printf("%9u %-15s %8u %6u %-12s %-15s\n",
           prog_info->id, prog_type, prog_info->created_by_uid,
           prog_info->nr_map_ids, load_time, prog_info->name);
  else
    printf("%8u- %-15s %8u %6u %-12s %-15s\n",
           prog_info->id, prog_type, prog_info->created_by_uid,
           prog_info->nr_map_ids, load_time, prog_info->name);
}

static void print_map_hdr(void)
{
  printf("%8s %-15s %-10s %8s %8s %8s %-15s\n",
         "MID", "TYPE", "FLAGS", "KeySz", "ValueSz", "MaxEnts",
         "NAME");
}

static void print_map_info(const struct bpf_map_info *map_info)
{
  char unknown_map_type[16];
  const char *map_type;

  if (map_info->type > LAST_KNOWN_MAP_TYPE) {
    snprintf(unknown_map_type, sizeof(unknown_map_type),
             "<%u>", map_info->type);
    unknown_map_type[sizeof(unknown_map_type) - 1] = '\0';
    map_type = unknown_map_type;
  } else {
    map_type = map_type_strings[map_info->type];
  }

  printf("%8u %-15s 0x%-8x %8u %8u %8u %-15s\n",
         map_info->id, map_type, map_info->map_flags, map_info->key_size,
         map_info->value_size, map_info->max_entries,
         map_info->name);
}

static int print_one_prog(uint32_t prog_id)
{
  const uint32_t usual_nr_map_ids = 64;
  uint32_t nr_map_ids = usual_nr_map_ids;
  struct bpf_prog_info prog_info;
  uint32_t *map_ids =  NULL;
  uint32_t info_len;
  int ret = 0;
  int prog_fd;
  uint32_t i;

  prog_fd = bpf_prog_get_fd_by_id(prog_id);
  if (prog_fd == -1) {
    if (errno == ENOENT) {
      fprintf(stderr, "BID:%u not found\n", prog_id);
      return EX_DATAERR;
    } else {
      return handle_get_next_errno(errno);
    }
  }

  /* Retry at most one time for larger map_ids array */
  for (i = 0; i < 2; i++) {
    bzero(&prog_info, sizeof(prog_info));
    prog_info.map_ids = ptr_to_u64(realloc(map_ids,
                                           nr_map_ids * sizeof(*map_ids)));
    if (!prog_info.map_ids) {
      fprintf(stderr,
              "Cannot allocate memory for %u map_ids for BID:%u\n",
              nr_map_ids, prog_id);
      close(prog_fd);
      free(map_ids);
      return 1;
    }

    map_ids = u64_to_ptr(prog_info.map_ids);
    prog_info.nr_map_ids = nr_map_ids;
    info_len = sizeof(prog_info);
    ret = bpf_obj_get_info(prog_fd, &prog_info, &info_len);
    if (ret) {
      fprintf(stderr, "Cannot get info for BID:%u. %s(%d)\n",
              prog_id, strerror(errno), errno);
      close(prog_fd);
      free(map_ids);
      return ret;
    }

    if (prog_info.nr_map_ids <= nr_map_ids)
      break;

    nr_map_ids = prog_info.nr_map_ids;
  }
  close(prog_fd);

  print_prog_hdr();
  print_prog_info(&prog_info);
  printf("\n");

  /* Print all map_info used by the prog */
  print_map_hdr();
  nr_map_ids = min(prog_info.nr_map_ids, nr_map_ids);
  for (i = 0; i < nr_map_ids; i++) {
    struct bpf_map_info map_info = {};
    info_len = sizeof(map_info);
    int map_fd;

    map_fd = bpf_map_get_fd_by_id(map_ids[i]);
    if (map_fd == -1) {
      if (errno == -ENOENT)
        continue;

      fprintf(stderr,
              "Cannot get fd for map:%u. %s(%d)\n",
              map_ids[i], strerror(errno), errno);
      ret = map_fd;
      break;
    }

    ret = bpf_obj_get_info(map_fd, &map_info, &info_len);
    close(map_fd);
    if (ret) {
      fprintf(stderr, "Cannot get info for map:%u. %s(%d)\n",
              map_ids[i], strerror(errno), errno);
      break;
    }

    print_map_info(&map_info);
  }

  free(map_ids);
  return ret;
}

int print_all_progs(void)
{
  uint32_t next_id = 0;

  print_prog_hdr();

  while (!bpf_prog_get_next_id(next_id, &next_id)) {
    struct bpf_prog_info prog_info = {};
    uint32_t prog_info_len = sizeof(prog_info);
    int prog_fd;
    int ret;

    prog_fd = bpf_prog_get_fd_by_id(next_id);
    if (prog_fd < 0) {
      if (errno == ENOENT)
        continue;
      fprintf(stderr,
              "Cannot get fd for BID:%u. %s(%d)\n",
              next_id, strerror(errno), errno);
      return 1;
    }

    ret = bpf_obj_get_info(prog_fd, &prog_info, &prog_info_len);
    close(prog_fd);
    if (ret) {
      fprintf(stderr,
              "Cannot get bpf_prog_info for BID:%u. %s(%d)\n",
              next_id, strerror(errno), errno);
      return ret;
    }

    print_prog_info(&prog_info);
  }

  return handle_get_next_errno(errno);
}

void usage(void)
{
  printf("BPF Program Snapshot (bps):\n"
         "List of all BPF programs loaded into the system.\n\n");
  printf("Usage: bps [bpf-prog-id]\n");
  printf("    [bpf-prog-id] If specified, it shows the details info of the bpf-prog\n");
  printf("\n");
}

int main(int argc, char **argv)
{
  if (argc > 1) {
    if (!isdigit(*argv[1])) {
      usage();
      return EX_USAGE;
    }
    return print_one_prog((uint32_t)atoi(argv[1]));
  }

  return print_all_progs();
}

"""

```