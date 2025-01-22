Response:
### 第1部分功能归纳

#### 核心功能概述
该文件是BCC框架中与eBPF内核交互的核心模块，主要职责包括：
1. **eBPF Map管理**：创建/删除各类Map（哈希表、数组、Perf缓冲区等）。
2. **eBPF程序加载**：将编译后的BPF字节码加载到内核，处理验证与重定位。
3. **Hook点自动附加**：根据程序名智能识别kprobe/tracepoint等挂载点。
4. **BPF类型格式（BTF）支持**：处理内核模块的符号解析。
5. **错误诊断**：解析验证器日志，提供常见错误提示。
6. **兼容性处理**：适配不同内核版本的特性支持。

#### 执行流程（10步）
1. **参数预处理**：检查程序名格式（如`kprobe__vfs_read`）提取符号。
2. **BTF查找**：在vmlinux或内核模块中定位目标函数ID。
3. **Map创建**：根据类型调用`bcc_create_map_xattr`初始化存储结构。
4. **程序加载**：调用`bpf_prog_load`提交字节码到内核。
5. **验证器交互**：捕获内核返回的验证错误日志。
6. **错误重试**：自动调整内存限制/日志缓冲区大小。
7. **ELF重定位**：处理map引用、辅助函数等重定位项。
8. **Hook点附加**：根据程序类型自动附加到对应事件源。
9. **性能监控设置**：配置Perf事件环形缓冲区。
10. **资源绑定**：将程序绑定到socket/tracepoint等接口。

#### Hook点示例
| Hook类型         | 函数名模式       | 有效信息示例                  |
|------------------|------------------|-----------------------------|
| kprobe          | `kprobe__vfs_read` | 文件路径(`path`)、当前PID(`tgid`) |
| tracepoint      | `tracepoint__sched_switch` | 前/后进程PID、优先级         |
| socket过滤器    | N/A              | 网络包内容、协议类型          |
| LSM             | `lsm__file_open`  | 被操作文件路径、进程UID       |
| XDP             | N/A              | 网络接口索引、数据包元数据    |

#### 典型错误案例
1. **Map大小超限**  
   - 现象：`map_create: max_entries too large`
   - 原因：未考虑value占用的内存页对齐
   - 示例：创建`BPF_MAP_TYPE_HASH`时`max_entries=1e6`但value_size=1024，实际需要1GB内存

2. **权限不足**  
   - 现象：`Operation not permitted`
   - 调试：检查`CAP_BPF`能力或`RLIMIT_MEMLOCK`
   - 复现：容器环境中未授予`SYS_ADMIN`权限时加载BPF程序

3. **验证器拒绝**  
   - 现象：`invalid stack off=-512`
   - 分析：栈变量超过512字节限制
   - 示例：在BPF函数中定义大结构体`char buf[600]`

#### Syscall调试路径
当出现加载失败时，可跟踪以下关键节点：
```
用户态bcc_prog_load_xattr()
  ↓ 系统调用
sys_bpf(BPF_PROG_LOAD) 
  ↓ 内核处理
bpf_prog_load() 
  → bpf_check()验证器
  → bpf_prog_alloc()分配资源
  → 返回文件描述符或错误码
```
可通过`strace -e bpf`观察具体系统调用参数，结合`dmesg`查看内核日志。

（第2部分将深入分析Map管理机制、验证器提示解析及性能优化策略）
Prompt: 
```
这是目录为bcc/src/cc/libbpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (c) 2015 PLUMgrid, Inc.
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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "libbpf.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_alg.h>
#include <linux/if_packet.h>
#include <linux/perf_event.h>
#include <linux/pkt_cls.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "bcc_zip.h"
#include "perf_reader.h"

// TODO: Remove this when CentOS 6 support is not needed anymore
#include "setns.h"

#include "bcc_libbpf_inc.h"

// TODO: remove these defines when linux-libc-dev exports them properly

#ifndef __NR_bpf
#if defined(__powerpc64__)
#define __NR_bpf 361
#elif defined(__s390x__)
#define __NR_bpf 351
#elif defined(__aarch64__)
#define __NR_bpf 280
#else
#define __NR_bpf 321
#endif
#endif

#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF 50
#endif

#ifndef PERF_EVENT_IOC_SET_BPF
#define PERF_EVENT_IOC_SET_BPF _IOW('$', 8, __u32)
#endif

#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC (1UL << 3)
#endif

// TODO: Remove this when CentOS 6 support is not needed anymore
#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

#define UNUSED(expr) do { (void)(expr); } while (0)

#define PERF_UPROBE_REF_CTR_OFFSET_SHIFT 32

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC		0xcafe4a11
#endif

struct bpf_helper {
  char *name;
  char *required_version;
};

static struct bpf_helper helpers[] = {
  {"map_lookup_elem", "3.19"},
  {"map_update_elem", "3.19"},
  {"map_delete_elem", "3.19"},
  {"probe_read", "4.1"},
  {"ktime_get_ns", "4.1"},
  {"trace_printk", "4.1"},
  {"get_prandom_u32", "4.1"},
  {"get_smp_processor_id", "4.1"},
  {"skb_store_bytes", "4.1"},
  {"l3_csum_replace", "4.1"},
  {"l4_csum_replace", "4.1"},
  {"tail_call", "4.2"},
  {"clone_redirect", "4.2"},
  {"get_current_pid_tgid", "4.2"},
  {"get_current_uid_gid", "4.2"},
  {"get_current_comm", "4.2"},
  {"get_cgroup_classid", "4.3"},
  {"skb_vlan_push", "4.3"},
  {"skb_vlan_pop", "4.3"},
  {"skb_get_tunnel_key", "4.3"},
  {"skb_set_tunnel_key", "4.3"},
  {"perf_event_read", "4.3"},
  {"redirect", "4.4"},
  {"get_route_realm", "4.4"},
  {"perf_event_output", "4.4"},
  {"skb_load_bytes", "4.5"},
  {"get_stackid", "4.6"},
  {"csum_diff", "4.6"},
  {"skb_get_tunnel_opt", "4.6"},
  {"skb_set_tunnel_opt", "4.6"},
  {"skb_change_proto", "4.8"},
  {"skb_change_type", "4.8"},
  {"skb_under_cgroup", "4.8"},
  {"get_hash_recalc", "4.8"},
  {"get_current_task", "4.8"},
  {"probe_write_user", "4.8"},
  {"current_task_under_cgroup", "4.9"},
  {"skb_change_tail", "4.9"},
  {"skb_pull_data", "4.9"},
  {"csum_update", "4.9"},
  {"set_hash_invalid", "4.9"},
  {"get_numa_node_id", "4.10"},
  {"skb_change_head", "4.10"},
  {"xdp_adjust_head", "4.10"},
  {"probe_read_str", "4.11"},
  {"get_socket_cookie", "4.12"},
  {"get_socket_uid", "4.12"},
  {"set_hash", "4.13"},
  {"setsockopt", "4.13"},
  {"skb_adjust_room", "4.13"},
  {"redirect_map", "4.14"},
  {"sk_redirect_map", "4.14"},
  {"sock_map_update", "4.14"},
  {"xdp_adjust_meta", "4.15"},
  {"perf_event_read_value", "4.15"},
  {"perf_prog_read_value", "4.15"},
  {"getsockopt", "4.15"},
  {"override_return", "4.16"},
  {"sock_ops_cb_flags_set", "4.16"},
  {"msg_redirect_map", "4.17"},
  {"msg_apply_bytes", "4.17"},
  {"msg_cork_bytes", "4.17"},
  {"msg_pull_data", "4.17"},
  {"bind", "4.17"},
  {"xdp_adjust_tail", "4.18"},
  {"skb_get_xfrm_state", "4.18"},
  {"get_stack", "4.18"},
  {"skb_load_bytes_relative", "4.18"},
  {"fib_lookup", "4.18"},
  {"sock_hash_update", "4.18"},
  {"msg_redirect_hash", "4.18"},
  {"sk_redirect_hash", "4.18"},
  {"lwt_push_encap", "4.18"},
  {"lwt_seg6_store_bytes", "4.18"},
  {"lwt_seg6_adjust_srh", "4.18"},
  {"lwt_seg6_action", "4.18"},
  {"rc_repeat", "4.18"},
  {"rc_keydown", "4.18"},
  {"skb_cgroup_id", "4.18"},
  {"get_current_cgroup_id", "4.18"},
  {"get_local_storage", "4.19"},
  {"sk_select_reuseport", "4.19"},
  {"skb_ancestor_cgroup_id", "4.19"},
  {"sk_lookup_tcp", "4.20"},
  {"sk_lookup_udp", "4.20"},
  {"sk_release", "4.20"},
  {"map_push_elem", "4.20"},
  {"map_pop_elem", "4.20"},
  {"map_peak_elem", "4.20"},
  {"msg_push_data", "4.20"},
  {"msg_pop_data", "5.0"},
  {"rc_pointer_rel", "5.0"},
  {"spin_lock", "5.1"},
  {"spin_unlock", "5.1"},
  {"sk_fullsock", "5.1"},
  {"tcp_sock", "5.1"},
  {"skb_ecn_set_ce", "5.1"},
  {"get_listener_sock", "5.1"},
  {"skc_lookup_tcp", "5.2"},
  {"tcp_check_syncookie", "5.2"},
  {"sysctl_get_name", "5.2"},
  {"sysctl_get_current_value", "5.2"},
  {"sysctl_get_new_value", "5.2"},
  {"sysctl_set_new_value", "5.2"},
  {"strtol", "5.2"},
  {"strtoul", "5.2"},
  {"sk_storage_get", "5.2"},
  {"sk_storage_delete", "5.2"},
  {"send_signal", "5.3"},
  {"tcp_gen_syncookie", "5.3"},
  {"skb_output", "5.5"},
  {"probe_read_user", "5.5"},
  {"probe_read_kernel", "5.5"},
  {"probe_read_user_str", "5.5"},
  {"probe_read_kernel_str", "5.5"},
  {"tcp_send_ack", "5.5"},
  {"send_signal_thread", "5.5"},
  {"jiffies64", "5.5"},
  {"read_branch_records", "5.6"},
  {"get_ns_current_pid_tgid", "5.6"},
  {"xdp_output", "5.6"},
  {"get_netns_cookie", "5.6"},
  {"get_current_ancestor_cgroup_id", "5.6"},
  {"sk_assign", "5.6"},
  {"ktime_get_boot_ns", "5.7"},
  {"seq_printf", "5.7"},
  {"seq_write", "5.7"},
  {"sk_cgroup_id", "5.7"},
  {"sk_ancestor_cgroup_id", "5.7"},
  {"csum_level", "5.7"},
  {"ringbuf_output", "5.8"},
  {"ringbuf_reserve", "5.8"},
  {"ringbuf_submit", "5.8"},
  {"ringbuf_discard", "5.8"},
  {"ringbuf_query", "5.8"},
  {"skc_to_tcp6_sock", "5.9"},
  {"skc_to_tcp_sock", "5.9"},
  {"skc_to_tcp_timewait_sock", "5.9"},
  {"skc_to_tcp_request_sock", "5.9"},
  {"skc_to_udp6_sock", "5.9"},
  {"get_task_stack", "5.9"},
  {"load_hdr_opt", "5.10"},
  {"store_hdr_opt", "5.10"},
  {"reserve_hdr_opt", "5.10"},
  {"inode_storage_get", "5.10"},
  {"inode_storage_delete", "5.10"},
  {"d_path", "5.10"},
  {"copy_from_user", "5.10"},
  {"snprintf_btf", "5.10"},
  {"seq_printf_btf", "5.10"},
  {"skb_cgroup_classid", "5.10"},
  {"redirect_neigh", "5.10"},
  {"per_cpu_ptr", "5.10"},
  {"this_cpu_ptr", "5.10"},
  {"redirect_peer", "5.10"},
  {"task_storage_get", "5.11"},
  {"task_storage_delete", "5.11"},
  {"get_current_task_btf", "5.11"},
  {"bprm_opts_set", "5.11"},
  {"ktime_get_coarse_ns", "5.11"},
  {"ima_inode_hash", "5.11"},
  {"sock_from_file", "5.11"},
  {"check_mtu", "5.12"},
  {"for_each_map_elem", "5.13"},
  {"snprintf", "5.13"},
  {"sys_bpf", "5.14"},
  {"btf_find_by_name_kind", "5.14"},
  {"sys_close", "5.14"},
  {"timer_init", "5.15"},
  {"timer_set_callback", "5.15"},
  {"timer_start", "5.15"},
  {"timer_cancel", "5.15"},
  {"get_func_ip", "5.15"},
  {"get_attach_cookie", "5.15"},
  {"task_pt_regs", "5.15"},
  {"get_branch_snapshot", "5.16"},
  {"trace_vprintk", "5.16"},
  {"skc_to_unix_sock", "5.16"},
  {"kallsyms_lookup_name", "5.16"},
  {"find_vma", "5.17"},
  {"loop", "5.17"},
  {"strncmp", "5.17"},
  {"get_func_arg", "5.17"},
  {"get_func_ret", "5.17"},
  {"get_func_ret", "5.17"},
  {"get_retval", "5.18"},
  {"set_retval", "5.18"},
  {"xdp_get_buff_len", "5.18"},
  {"xdp_load_bytes", "5.18"},
  {"xdp_store_bytes", "5.18"},
  {"copy_from_user_task", "5.18"},
  {"skb_set_tstamp", "5.18"},
  {"ima_file_hash", "5.18"},
  {"kptr_xchg", "5.19"},
  {"map_lookup_percpu_elem", "5.19"},
  {"skc_to_mptcp_sock", "5.19"},
  {"dynptr_from_mem", "5.19"},
  {"ringbuf_reserve_dynptr", "5.19"},
  {"ringbuf_submit_dynptr", "5.19"},
  {"ringbuf_discard_dynptr", "5.19"},
  {"dynptr_read", "5.19"},
  {"dynptr_write", "5.19"},
  {"dynptr_data", "5.19"},
  {"tcp_raw_gen_syncookie_ipv4", "6.0"},
  {"tcp_raw_gen_syncookie_ipv6", "6.0"},
  {"tcp_raw_check_syncookie_ipv4", "6.0"},
  {"tcp_raw_check_syncookie_ipv6", "6.0"},
  {"ktime_get_tai_ns", "6.1"},
  {"user_ringbuf_drain", "6.1"},
  {"cgrp_storage_get", "6.2"},
  {"cgrp_storage_delete", "6.2"},
};

static uint64_t ptr_to_u64(void *ptr)
{
  return (uint64_t) (unsigned long) ptr;
}

static int libbpf_bpf_map_create(struct bcc_create_map_attr *create_attr)
{
  LIBBPF_OPTS(bpf_map_create_opts, p);

  p.map_flags = create_attr->map_flags;
  p.numa_node = create_attr->numa_node;
  p.btf_fd = create_attr->btf_fd;
  p.btf_key_type_id = create_attr->btf_key_type_id;
  p.btf_value_type_id = create_attr->btf_value_type_id;
  p.map_ifindex = create_attr->map_ifindex;
  if (create_attr->map_type == BPF_MAP_TYPE_STRUCT_OPS)
    p.btf_vmlinux_value_type_id = create_attr->btf_vmlinux_value_type_id;
  else
    p.inner_map_fd = create_attr->inner_map_fd;

  return bpf_map_create(create_attr->map_type, create_attr->name, create_attr->key_size,
                        create_attr->value_size, create_attr->max_entries, &p);
}

int bcc_create_map_xattr(struct bcc_create_map_attr *attr, bool allow_rlimit)
{
  unsigned name_len = attr->name ? strlen(attr->name) : 0;
  char map_name[BPF_OBJ_NAME_LEN] = {};

  memcpy(map_name, attr->name, min(name_len, BPF_OBJ_NAME_LEN - 1));
  attr->name = map_name;
  int ret = libbpf_bpf_map_create(attr);

  if (ret < 0 && errno == EPERM) {
    if (!allow_rlimit)
      return ret;

    // see note below about the rationale for this retry
    struct rlimit rl = {};
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
      rl.rlim_max = RLIM_INFINITY;
      rl.rlim_cur = rl.rlim_max;
      if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0)
        ret = libbpf_bpf_map_create(attr);
    }
  }

  // kernel already supports btf if its loading is successful,
  // but this map type may not support pretty print yet.
  if (ret < 0 && attr->btf_key_type_id && errno == 524 /* ENOTSUPP */) {
    attr->btf_fd = 0;
    attr->btf_key_type_id = 0;
    attr->btf_value_type_id = 0;
    ret = libbpf_bpf_map_create(attr);
  }

  if (ret < 0 && name_len && (errno == E2BIG || errno == EINVAL)) {
    map_name[0] = '\0';
    ret = libbpf_bpf_map_create(attr);
  }

  if (ret < 0 && errno == EPERM) {
    if (!allow_rlimit)
      return ret;

    // see note below about the rationale for this retry
    struct rlimit rl = {};
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
      rl.rlim_max = RLIM_INFINITY;
      rl.rlim_cur = rl.rlim_max;
      if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0)
        ret = libbpf_bpf_map_create(attr);
    }
  }
  return ret;
}

int bcc_create_map(enum bpf_map_type map_type, const char *name,
                   int key_size, int value_size,
                   int max_entries, int map_flags)
{
  struct bcc_create_map_attr attr = {};

  attr.map_type = map_type;
  attr.name = name;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = map_flags;
  return bcc_create_map_xattr(&attr, true);
}

int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags)
{
  return bpf_map_update_elem(fd, key, value, flags);
}

int bpf_lookup_elem(int fd, void *key, void *value)
{
  return bpf_map_lookup_elem(fd, key, value);
}

int bpf_delete_elem(int fd, void *key)
{
  return bpf_map_delete_elem(fd, key);
}

int bpf_lookup_and_delete(int fd, void *key, void *value)
{
  return bpf_map_lookup_and_delete_elem(fd, key, value);
}

int bpf_lookup_batch(int fd, __u32 *in_batch, __u32 *out_batch, void *keys,
                     void *values, __u32 *count)
{
  return bpf_map_lookup_batch(fd, in_batch, out_batch, keys, values, count,
                              NULL);
}

int bpf_delete_batch(int fd,  void *keys, __u32 *count)
{
  return bpf_map_delete_batch(fd, keys, count, NULL);
}

int bpf_update_batch(int fd, void *keys, void *values, __u32 *count)
{
  return bpf_map_update_batch(fd, keys, values, count, NULL);
}

int bpf_lookup_and_delete_batch(int fd, __u32 *in_batch, __u32 *out_batch,
                                void *keys, void *values, __u32 *count)
{
  return bpf_map_lookup_and_delete_batch(fd, in_batch, out_batch, keys, values,
                                         count, NULL);
}

int bpf_get_first_key(int fd, void *key, size_t key_size)
{
  int i, res;

  // 4.12 and above kernel supports passing NULL to BPF_MAP_GET_NEXT_KEY
  // to get first key of the map. For older kernels, the call will fail.
  res = bpf_map_get_next_key(fd, 0, key);
  if (res < 0 && errno == EFAULT) {
    // Fall back to try to find a non-existing key.
    static unsigned char try_values[3] = {0, 0xff, 0x55};
    for (i = 0; i < 3; i++) {
      memset(key, try_values[i], key_size);
      // We want to check the existence of the key but we don't know the size
      // of map's value. So we pass an invalid pointer for value, expect
      // the call to fail and check if the error is ENOENT indicating the
      // key doesn't exist. If we use NULL for the invalid pointer, it might
      // trigger a page fault in kernel and affect performance. Hence we use
      // ~0 which will fail and return fast.
      // This should fail since we pass an invalid pointer for value.
      if (bpf_map_lookup_elem(fd, key, (void *)~0) >= 0)
        return -1;
      // This means the key doesn't exist.
      if (errno == ENOENT)
        return bpf_map_get_next_key(fd, (void*)&try_values[i], key);
    }
    return -1;
  } else {
    return res;
  }
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
  return bpf_map_get_next_key(fd, key, next_key);
}

static void bpf_print_hints(int ret, char *log)
{
  if (ret < 0)
    fprintf(stderr, "bpf: Failed to load program: %s\n", strerror(errno));
  if (log == NULL)
    return;
  else
    fprintf(stderr, "%s\n", log);

  if (ret >= 0)
    return;

  // The following error strings will need maintenance to match LLVM.

  // stack busting
  if (strstr(log, "invalid stack off=-") != NULL) {
    fprintf(stderr, "HINT: Looks like you exceeded the BPF stack limit. "
      "This can happen if you allocate too much local variable storage. "
      "For example, if you allocated a 1 Kbyte struct (maybe for "
      "BPF_PERF_OUTPUT), busting a max stack of 512 bytes.\n\n");
  }

  // didn't check NULL on map lookup
  if (strstr(log, "invalid mem access 'map_value_or_null'") != NULL) {
    fprintf(stderr, "HINT: The 'map_value_or_null' error can happen if "
      "you dereference a pointer value from a map lookup without first "
      "checking if that pointer is NULL.\n\n");
  }

  // lacking a bpf_probe_read
  if (strstr(log, "invalid mem access 'inv'") != NULL) {
    fprintf(stderr, "HINT: The invalid mem access 'inv' error can happen "
      "if you try to dereference memory without first using "
      "bpf_probe_read_kernel() to copy it to the BPF stack. Sometimes the "
      "bpf_probe_read_kernel() is automatic by the bcc rewriter, other times "
      "you'll need to be explicit.\n\n");
  }

  // referencing global/static variables or read only data
  if (strstr(log, "unknown opcode") != NULL) {
    fprintf(stderr, "HINT: The 'unknown opcode' can happen if you reference "
      "a global or static variable, or data in read-only section. For example,"
      " 'char *p = \"hello\"' will result in p referencing a read-only section,"
      " and 'char p[] = \"hello\"' will have \"hello\" stored on the stack.\n\n");
  }

  // helper function not found in kernel
  char *helper_str = strstr(log, "invalid func ");
  if (helper_str != NULL) {
    helper_str += strlen("invalid func ");
    char *str = strchr(helper_str, '#');
    if (str != NULL) {
      helper_str = str + 1;
    }
    int helper_id = atoi(helper_str);
    if (helper_id && helper_id < sizeof(helpers) / sizeof(struct bpf_helper)) {
      struct bpf_helper helper = helpers[helper_id - 1];
      fprintf(stderr, "HINT: bpf_%s missing (added in Linux %s).\n\n",
              helper.name, helper.required_version);
    }
  }
}
#define ROUND_UP(x, n) (((x) + (n) - 1u) & ~((n) - 1u))

int bpf_obj_get_info(int prog_map_fd, void *info, uint32_t *info_len)
{
  return bpf_obj_get_info_by_fd(prog_map_fd, info, info_len);
}

int bpf_prog_compute_tag(const struct bpf_insn *insns, int prog_len,
                         unsigned long long *ptag)
{
  struct sockaddr_alg alg = {
    .salg_family    = AF_ALG,
    .salg_type      = "hash",
    .salg_name      = "sha1",
  };
  int shafd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (shafd < 0) {
    fprintf(stderr, "sha1 socket not available %s\n", strerror(errno));
    return -1;
  }
  int ret = bind(shafd, (struct sockaddr *)&alg, sizeof(alg));
  if (ret < 0) {
    fprintf(stderr, "sha1 bind fail %s\n", strerror(errno));
    close(shafd);
    return ret;
  }
  int shafd2 = accept(shafd, NULL, 0);
  if (shafd2 < 0) {
    fprintf(stderr, "sha1 accept fail %s\n", strerror(errno));
    close(shafd);
    return -1;
  }
  struct bpf_insn prog[prog_len / 8];
  bool map_ld_seen = false;
  int i;
  for (i = 0; i < prog_len / 8; i++) {
    prog[i] = insns[i];
    if (insns[i].code == (BPF_LD | BPF_DW | BPF_IMM) &&
        insns[i].src_reg == BPF_PSEUDO_MAP_FD &&
        !map_ld_seen) {
      prog[i].imm = 0;
      map_ld_seen = true;
    } else if (insns[i].code == 0 && map_ld_seen) {
      prog[i].imm = 0;
      map_ld_seen = false;
    } else {
      map_ld_seen = false;
    }
  }
  ret = write(shafd2, prog, prog_len);
  if (ret != prog_len) {
    fprintf(stderr, "sha1 write fail %s\n", strerror(errno));
    close(shafd2);
    close(shafd);
    return -1;
  }

  union {
    unsigned char sha[20];
    unsigned long long tag;
  } u = {};
  ret = read(shafd2, u.sha, 20);
  if (ret != 20) {
    fprintf(stderr, "sha1 read fail %s\n", strerror(errno));
    close(shafd2);
    close(shafd);
    return -1;
  }
  *ptag = __builtin_bswap64(u.tag);
  close(shafd2);
  close(shafd);
  return 0;
}

int bpf_prog_get_tag(int fd, unsigned long long *ptag)
{
  char fmt[64];
  snprintf(fmt, sizeof(fmt), "/proc/self/fdinfo/%d", fd);
  FILE * f = fopen(fmt, "r");
  if (!f) {
/*    fprintf(stderr, "failed to open fdinfo %s\n", strerror(errno));*/
    return -1;
  }
  unsigned long long tag = 0;
  // prog_tag: can appear in different lines
  while (fgets(fmt, sizeof(fmt), f)) {
    if (sscanf(fmt, "prog_tag:%llx", &tag) == 1) {
      *ptag = tag;
      fclose(f);
      return 0;
    }
  }
  fclose(f);
  return -2;
}

static int libbpf_bpf_prog_load(enum bpf_prog_type prog_type,
                                const char *prog_name, const char *license,
                                const struct bpf_insn *insns, size_t insn_cnt,
                                struct bpf_prog_load_opts *opts,
                                char *log_buf, size_t log_buf_sz)
{

  LIBBPF_OPTS(bpf_prog_load_opts, p);

  if (!opts || !log_buf != !log_buf_sz) {
    errno = EINVAL;
    return -EINVAL;
  }

  p.expected_attach_type = opts->expected_attach_type;
  switch (prog_type) {
  case BPF_PROG_TYPE_STRUCT_OPS:
  case BPF_PROG_TYPE_LSM:
    p.attach_btf_id = opts->attach_btf_id;
    break;
  case BPF_PROG_TYPE_TRACING:
  case BPF_PROG_TYPE_EXT:
    p.attach_btf_id = opts->attach_btf_id;
    p.attach_prog_fd = opts->attach_prog_fd;
    p.attach_btf_obj_fd = opts->attach_btf_obj_fd;
    break;
  default:
    p.prog_ifindex = opts->prog_ifindex;
    p.kern_version = opts->kern_version;
  }
  p.log_level = opts->log_level;
  p.log_buf = log_buf;
  p.log_size = log_buf_sz;
  p.prog_btf_fd = opts->prog_btf_fd;
  p.func_info_rec_size = opts->func_info_rec_size;
  p.func_info_cnt = opts->func_info_cnt;
  p.func_info = opts->func_info;
  p.line_info_rec_size = opts->line_info_rec_size;
  p.line_info_cnt = opts->line_info_cnt;
  p.line_info = opts->line_info;
  p.prog_flags = opts->prog_flags;

  return bpf_prog_load(prog_type, prog_name, license,
                       insns, insn_cnt, &p);
}

static int find_btf_id(const char *module_name, const char *func_name,
                       enum bpf_attach_type expected_attach_type, int *btf_fd)
{
  struct btf *vmlinux_btf = NULL, *module_btf = NULL;
  struct bpf_btf_info info;
  int err, fd, btf_id;
  __u32 id = 0, len;
  char name[64];

  if (!module_name[0] || !strcmp(module_name, "vmlinux"))
    return libbpf_find_vmlinux_btf_id(func_name, expected_attach_type);

  while (true) {
    err = bpf_btf_get_next_id(id, &id);
    if (err) {
      fprintf(stderr, "bpf_btf_get_next_id failed: %d\n", err);
      return err;
    }

    fd = bpf_btf_get_fd_by_id(id);
    if (fd < 0) {
      err = fd;
      fprintf(stderr, "bpf_btf_get_fd_by_id failed: %d\n", err);
      return err;
    }

    len = sizeof(info);
    memset(&info, 0, sizeof(info));
    info.name = ptr_to_u64(name);
    info.name_len = sizeof(name);

    err = bpf_btf_get_info_by_fd(fd, &info, &len);
    if (err) {
      fprintf(stderr, "bpf_btf_get_info_by_fd failed: %d\n", err);
      goto err_out;
    }

    if (!info.kernel_btf || strcmp(name, module_name)) {
      close(fd);
      continue;
    }

    vmlinux_btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(vmlinux_btf);
    if (err) {
      fprintf(stderr, "btf__load_vmlinux_btf failed: %d\n", err);
      goto err_out;
    }

    module_btf = btf__load_module_btf(module_name, vmlinux_btf);
    err = libbpf_get_error(vmlinux_btf);
    if (err) {
      fprintf(stderr, "btf__load_module_btf failed: %d\n", err);
      goto err_out;
    }

    btf_id = btf__find_by_name_kind(module_btf, func_name, BTF_KIND_FUNC);
    if (btf_id < 0) {
      err = btf_id;
      fprintf(stderr, "btf__find_by_name_kind failed: %d\n", err);
      goto err_out;
    }

    btf__free(module_btf);
    btf__free(vmlinux_btf);

    *btf_fd = fd;
    return btf_id;

err_out:
    btf__free(module_btf);
    btf__free(vmlinux_btf);
    close(fd);
    *btf_fd = -1;
    return err;
  }

  return -1;
}

int bcc_prog_load_xattr(enum bpf_prog_type prog_type, const char *prog_name,
                        const char *license, const struct bpf_insn *insns,
                        struct bpf_prog_load_opts *opts, int prog_len,
                        char *log_buf, unsigned log_buf_size, bool allow_rlimit)
{
  unsigned name_len = prog_name ? strlen(prog_name) : 0;
  char *tmp_log_buf = NULL, *opts_log_buf = NULL;
  unsigned tmp_log_buf_size = 0, opts_log_buf_size = 0;
  int ret = 0, name_offset = 0, expected_attach_type = 0;
  char new_prog_name[BPF_OBJ_NAME_LEN] = {};
  char mod_name[64] = {};
  char *mod_end;
  int mod_len;
  int fd = -1;

  unsigned insns_cnt = prog_len / sizeof(struct bpf_insn);

  if (opts->log_level > 0) {
    if (log_buf_size > 0) {
      // Use user-provided log buffer if available.
      log_buf[0] = 0;
      opts_log_buf = log_buf;
      opts_log_buf_size = log_buf_size;
    } else {
      // Create and use temporary log buffer if user didn't provide one.
      tmp_log_buf_size = LOG_BUF_SIZE;
      tmp_log_buf = malloc(tmp_log_buf_size);
      if (!tmp_log_buf) {
        fprintf(stderr, "bpf: Failed to allocate temporary log buffer: %s\n\n",
                strerror(errno));
        opts->log_level = 0;
      } else {
        tmp_log_buf[0] = 0;
        opts_log_buf = tmp_log_buf;
        opts_log_buf_size = tmp_log_buf_size;
      }
    }
  }

  if (name_len) {
    if (strncmp(prog_name, "kprobe__", 8) == 0)
      name_offset = 8;
    else if (strncmp(prog_name, "kretprobe__", 11) == 0)
      name_offset = 11;
    else if (strncmp(prog_name, "tracepoint__", 12) == 0)
      name_offset = 12;
    else if (strncmp(prog_name, "raw_tracepoint__", 16) == 0)
      name_offset = 16;
    else if (strncmp(prog_name, "kfunc__", 7) == 0) {
      // kfunc__vmlinux__vfs_read
      mod_end = strstr(prog_name + 7, "__");
      mod_len = mod_end - prog_name - 7;
      strncpy(mod_name, prog_name + 7, mod_len);
      name_offset = 7 + mod_len + 2;
      expected_attach_type = BPF_TRACE_FENTRY;
    } else if (strncmp(prog_name, "kmod_ret__", 10) == 0) {
      name_offset = 10;
      expected_attach_type = BPF_MODIFY_RETURN;
    } else if (strncmp(prog_name, "kretfunc__", 10) == 0) {
      // kretfunc__vmlinux__vfs_read
      mod_end = strstr(prog_name + 10, "__");
      mod_len = mod_end - prog_name - 10;
      strncpy(mod_name, prog_name + 10, mod_len);
      name_offset = 10 + mod_len + 2;
      expected_attach_type = BPF_TRACE_FEXIT;
    } else if (strncmp(prog_name, "lsm__", 5) == 0) {
      name_offset = 5;
      expected_attach_type = BPF_LSM_MAC;
    } else if (strncmp(prog_name, "bpf_iter__", 10) == 0) {
      name_offset = 10;
      expected_attach_type = BPF_TRACE_ITER;
    }

    if (prog_type == BPF_PROG_TYPE_TRACING ||
        prog_type == BPF_PROG_TYPE_LSM) {
      ret = find_btf_id(mod_name, prog_name + name_offset,
                        expected_attach_type, &fd);
      if (ret == -EINVAL) {
        fprintf(stderr, "bpf: %s BTF is not found\n", mod_name);
        return ret;
      } else if (ret < 0) {
        fprintf(stderr, "bpf: %s is not found in %s BTF\n",
                prog_name + name_offset, mod_name);
        return ret;
      }

      opts->attach_btf_obj_fd = fd == -1 ? 0 : fd;
      opts->attach_btf_id = ret;
      opts->expected_attach_type = expected_attach_type;
    }

    memcpy(new_prog_name, prog_name + name_offset,
           min(name_len - name_offset, BPF_OBJ_NAME_LEN - 1));
  }

  ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, opts_log_buf, opts_log_buf_size);

  // func_info/line_info may not be supported in old kernels.
  if (ret < 0 && opts->func_info && errno == EINVAL) {
    opts->prog_btf_fd = 0;
    opts->func_info = NULL;
    opts->func_info_cnt = 0;
    opts->func_info_rec_size = 0;
    opts->line_info = NULL;
    opts->line_info_cnt = 0;
    opts->line_info_rec_size = 0;
    ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, opts_log_buf, opts_log_buf_size);
  }

  // BPF object name is not supported on older Kernels.
  // If we failed due to this, clear the name and try again.
  if (ret < 0 && name_len && (errno == E2BIG || errno == EINVAL)) {
    new_prog_name[0] = '\0';
    ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, opts_log_buf, opts_log_buf_size);
  }

  if (ret < 0 && errno == EPERM) {
    if (!allow_rlimit)
      return ret;

    // When EPERM is returned, two reasons are possible:
    //  1. user has no permissions for bpf()
    //  2. user has insufficent rlimit for locked memory
    // Unfortunately, there is no api to inspect the current usage of locked
    // mem for the user, so an accurate calculation of how much memory to lock
    // for this new program is difficult to calculate. As a hack, bump the limit
    // to unlimited. If program load fails again, return the error.
    struct rlimit rl = {};
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
      rl.rlim_max = RLIM_INFINITY;
      rl.rlim_cur = rl.rlim_max;
      if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0)
        ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, opts_log_buf, opts_log_buf_size);
    }
  }

  if (ret < 0 && errno == E2BIG) {
    fprintf(stderr,
            "bpf: %s. Program %s too large (%u insns), at most %d insns\n\n",
            strerror(errno), new_prog_name, insns_cnt, BPF_MAXINSNS);
    return -1;
  }

  // The load has failed. Handle log message.
  if (ret < 0) {
    // User has provided a log buffer.
    if (log_buf_size) {
      // If logging is not already enabled, enable it and do the syscall again.
      if (opts->log_level == 0) {
        opts->log_level = 1;
        ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, log_buf, log_buf_size);
      }
      // Print the log message and return.
      bpf_print_hints(ret, log_buf);
      if (errno == ENOSPC)
        fprintf(stderr, "bpf: log_buf size may be insufficient\n");
      goto return_result;
    }

    // User did not provide log buffer. We will try to increase size of
    // our temporary log buffer to get full error message.
    if (tmp_log_buf)
      free(tmp_log_buf);
    tmp_log_buf_size = LOG_BUF_SIZE;
    if (opts->log_level == 0)
      opts->log_level = 1;
    for (;;) {
      tmp_log_buf = malloc(tmp_log_buf_size);
      if (!tmp_log_buf) {
        fprintf(stderr, "bpf: Failed to allocate temporary log buffer: %s\n\n",
                strerror(errno));
        goto return_result;
      }
      tmp_log_buf[0] = 0;
      ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, tmp_log_buf, tmp_log_buf_size);
      if (ret < 0 && errno == ENOSPC) {
        // Temporary buffer size is not enough. Double it and try again.
        free(tmp_log_buf);
        tmp_log_buf = NULL;
        tmp_log_buf_size <<= 1;
      } else {
        break;
      }
    }
  }

  // Check if we should print the log message if log_level is not 0,
  // either specified by user or set due to error.
  if (opts->log_level > 0) {
    // Don't print if user enabled logging and provided log buffer,
    // but there is no error.
    if (log_buf && ret < 0)
      bpf_print_hints(ret, log_buf);
    else if (tmp_log_buf)
      bpf_print_hints(ret, tmp_log_buf);
  }

return_result:
  if (fd >= 0)
    close(fd);
  if (tmp_log_buf)
    free(tmp_log_buf);
  return ret;
}

int bcc_prog_load(enum bpf_prog_type prog_type, const char *name,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, unsigned kern_version,
                  int log_level, char *log_buf, unsigned log_buf_size)
{
  struct bpf_prog_load_opts opts = {};


  if (prog_type != BPF_PROG_TYPE_TRACING && prog_type != BPF_PROG_TYPE_EXT)
    opts.kern_version = kern_version;
  opts.log_level = log_level;
  return bcc_prog_load_xattr(prog_type, name, license, insns, &opts, prog_len, log_buf, log_buf_size, true);
}

int bpf_open_raw_sock(const char *name)
{
  struct sockaddr_ll sll;
  int sock;

  sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (sock < 0) {
    fprintf(stderr, "cannot create raw socket\n");
    return -1;
  }

  /* Do not bind on empty interface names */
  if (!name || *name == '\0')
    return sock;

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = if_nametoindex(name);
  if (sll.sll_ifindex == 0) {
    fprintf(stderr, "bpf: Resolving device name to index: %s\n", strerror(errno));
    close(sock);
    return -1;
  }
  sll.sll_protocol = htons(ETH_P_ALL);
  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    fprintf(stderr, "bind to %s: %s\n", name, strerror(errno));
    close(sock);
    return -1;
  }

  return sock;
}

int bpf_attach_socket(int sock, int prog) {
  return setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog, sizeof(prog));
}

#define PMU_TYPE_FILE "/sys/bus/event_source/devices/%s/type"
static int bpf_find_probe_type(const char *event_type)
{
  int fd;
  int ret;
  char buf[PATH_MAX];

  ret = snprintf(buf, sizeof(buf), PMU_TYPE_FILE, event_type);
  if (ret < 0 || ret >= sizeof(buf))
    return -1;

  fd = open(buf, O_RDONLY);
  if (fd < 0)
    return -1;
  ret = read(fd, buf, sizeof(buf));
  close(fd);
  if (ret < 0 || ret >= sizeof(buf))
    return -1;
  errno = 0;
  ret = (int)strtol(buf, NULL, 10);
  return errno ? -1 : ret;
}

#define PMU_RETPROBE_FILE "/sys/bus/event_source/devices/%s/format/retprobe"
static int bpf_get_retprobe_bit(const char *event_type)
{
  int fd;
  int ret;
  char buf[PATH_MAX];

  ret = snprintf(buf, sizeof(buf), PMU_RETPROBE_FILE, event_type);
  if (ret < 0 || ret >= sizeof(buf))
    return -1;

  fd = open(buf, O_RDONLY);
  if (fd < 0)
    return -1;
  ret = read(fd, buf, sizeof(buf));
  close(fd);
  if (ret < 0 || ret >= sizeof(buf))
    return -1;
  if (strncmp(buf, "config:", strlen("config:")))
    return -1;
  errno = 0;
  ret = (int)strtol(buf + strlen("config:"), NULL, 10);
  return errno ? -1 : ret;
}

/*
 * Kernel API with e12f03d ("perf/core: Implement the 'perf_k
"""


```