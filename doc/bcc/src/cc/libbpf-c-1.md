Response:
### 功能归纳（第2部分）

#### 1. **动态探测管理（kprobe/uprobe）**
- **执行顺序**:
  1. 调用`bpf_attach_kprobe/uprobe`创建事件
  2. 尝试通过`perf_event_open`创建探测（支持新内核的PMU特性）
  3. 若失败则通过`create_probe_event`写入tracefs创建传统事件
  4. 通过`bpf_attach_tracing_event`关联BPF程序与事件
  5. 最终通过`ioctl`启用事件
- **Hook点**:
  - **kprobe**: 内核函数入口（`BPF_PROBE_ENTRY`）或返回（`BPF_PROBE_RETURN`），如`do_sys_open`
  - **uprobe**: 用户态函数地址（通过`binary_path`和`offset`定位），如`/usr/bin/app:0x1234`
- **有效信息**:
  - kprobe：函数名、寄存器值、内核调用参数
  - uprobe：二进制路径、内存偏移量、PID（可选过滤特定进程）

#### 2. **跟踪点（Tracepoint）管理**
- **执行顺序**:
  1. 构造tracefs路径（如`/sys/kernel/tracing/events/syscalls/sys_enter_open`）
  2. 通过`bpf_attach_tracing_event`打开事件并附加BPF程序
- **Hook点**: 预定义内核跟踪点（如`sys_enter_open`）
- **有效信息**: 系统调用参数（如文件路径、进程PID）

#### 3. **Perf事件管理**
- **功能**：通过`perf_event_open`创建硬件/软件性能事件
- **Hook点**:
  - 硬件事件：CPU周期、缓存命中（`PERF_TYPE_HARDWARE`）
  - 软件事件：上下文切换、页错误（`PERF_TYPE_SOFTWARE`）
- **示例输入**：`bpf_attach_perf_event(progfd, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, ...)`
- **常见错误**：配置超出范围（如`config >= PERF_COUNT_HW_MAX`）

#### 4. **XDP程序附加**
- **执行顺序**:
  1. 通过`if_nametoindex`获取网络设备索引
  2. 调用`bpf_xdp_attach`关联XDP程序
- **Hook点**：网络设备驱动接收路径
- **有效信息**：网络数据包原始内容

#### 5. **环形缓冲区（Ring Buffer）管理**
- **功能**：替代传统Perf Buffer的高效数据传递机制
- **关键操作**：`bpf_new_ringbuf`创建缓冲区、`bpf_poll_ringbuf`异步消费数据

#### 6. **BPF迭代器支持**
- **功能**：通过`bcc_iter_attach`创建BPF迭代器链接，遍历内核数据结构（如TCP连接）
- **示例**：遍历所有进程的`task_struct`

#### 7. **内核BTF检查**
- **逻辑**：`bpf_has_kernel_btf`检查是否存在`/sys/kernel/btf/vmlinux`
- **用途**：CO-RE（Compile Once – Run Everywhere）兼容性检测

#### 8. **内核结构体字段探测**
- **函数**：`kernel_struct_has_field`通过BTF检查结构体是否存在特定字段
- **示例**：验证`struct task_struct`是否有`mm`成员

#### 9. **动态事件清理**
- **流程**：`bpf_detach_probe`通过tracefs删除[k,u]probe事件
- **关键步骤**：向`kprobe_events/uprobe_events`写入`-:event_name`

#### 10. **文件系统检查**
- **功能**：`bcc_check_bpffs_path`验证路径是否在BPF文件系统中
- **常见错误**：未挂载`bpffs`或路径权限不足

---

### 调试线索示例
**场景**：kprobe附加失败
1. 检查`create_probe_event`是否成功写入`/sys/kernel/tracing/kprobe_events`
2. 验证`bpf_attach_tracing_event`中`perf_event_open`返回值
3. 检查`ioctl(PERF_EVENT_IOC_SET_BPF)`是否返回权限错误（需CAP_BPF）
4. 通过`strace`跟踪系统调用序列：
   ```bash
   strace -e perf_event_open,ioctl,openat ./my_bpf_tool
   ```

---

### 常见使用错误
1. **无效函数名**：
   ```c
   bpf_attach_kprobe(progfd, BPF_PROBE_ENTRY, "myprobe", "nonexist_func", 0, 0);
   // 错误：内核函数不存在，触发ENOENT
   ```

2. **权限不足**：
   ```bash
   # 未以root运行或缺少CAP_PERFMON
   $ ./opensnoop
   open(/sys/kernel/debug/tracing/kprobe_events): Permission denied
   ```

3. **路径截断**：
   ```c
   char path[10] = "/very/long/...";
   bpf_attach_uprobe(..., path, ...); // 缓冲区溢出导致路径错误
   ```

4. **事件泄漏**：
   ```c
   int pfd = bpf_attach_kprobe(...);
   // 忘记调用bpf_close_perf_event_fd(pfd)，导致FD泄漏
   ```

---

### 系统调用路径示例（kprobe）
1. 用户调用`bpf_attach_kprobe()`
2. 调用`bpf_attach_probe()`选择创建方式
3. **路径A**（新内核）：
   - `perf_event_open(..., PERF_TYPE_TRACEPOINT, ...)`
   - `ioctl(fd, PERF_EVENT_IOC_SET_BPF, progfd)`
4. **路径B**（旧内核）：
   - 写入`/sys/kernel/tracing/kprobe_events`
   - 通过`perf_event_open`关联tracepoint ID
5. 内核执行`perf_event_open`系统调用（`__NR_perf_event_open=298`）
6. 内核创建`perf_event`结构体并与BPF程序绑定
### 提示词
```
这是目录为bcc/src/cc/libbpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
probe' PMU") allows
 * creating [k,u]probe with perf_event_open, which makes it easier to clean up
 * the [k,u]probe. This function tries to create pfd with the perf_kprobe PMU.
 */
static int bpf_try_perf_event_open_with_probe(const char *name, uint64_t offs,
             int pid, const char *event_type, int is_return,
             uint64_t ref_ctr_offset)
{
  struct perf_event_attr attr = {};
  int type = bpf_find_probe_type(event_type);
  int is_return_bit = bpf_get_retprobe_bit(event_type);
  int cpu = 0;

  if (type < 0 || is_return_bit < 0)
    return -1;
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  if (is_return)
    attr.config |= 1 << is_return_bit;
  attr.config |= (ref_ctr_offset << PERF_UPROBE_REF_CTR_OFFSET_SHIFT);

  /*
   * struct perf_event_attr in latest perf_event.h has the following
   * extension to config1 and config2. To keep bcc compatibe with
   * older perf_event.h, we use config1 and config2 here instead of
   * kprobe_func, uprobe_path, kprobe_addr, and probe_offset.
   *
   * union {
   *  __u64 bp_addr;
   *  __u64 kprobe_func;
   *  __u64 uprobe_path;
   *  __u64 config1;
   * };
   * union {
   *   __u64 bp_len;
   *   __u64 kprobe_addr;
   *   __u64 probe_offset;
   *   __u64 config2;
   * };
   */
  attr.config2 = offs;  /* config2 here is kprobe_addr or probe_offset */
  attr.size = sizeof(attr);
  attr.type = type;
  /* config1 here is kprobe_func or  uprobe_path */
  attr.config1 = ptr_to_u64((void *)name);
  // PID filter is only possible for uprobe events.
  if (pid < 0)
    pid = -1;
  // perf_event_open API doesn't allow both pid and cpu to be -1.
  // So only set it to -1 when PID is not -1.
  // Tracing events do not do CPU filtering in any cases.
  if (pid != -1)
    cpu = -1;
  return syscall(__NR_perf_event_open, &attr, pid, cpu, -1 /* group_fd */,
                 PERF_FLAG_FD_CLOEXEC);
}

#define DEBUGFS_TRACEFS "/sys/kernel/debug/tracing"
#define TRACEFS "/sys/kernel/tracing"

static const char *get_tracefs_path()
{
  if (access(DEBUGFS_TRACEFS, F_OK) == 0) {
    return DEBUGFS_TRACEFS;
  }
  return TRACEFS;
}


// When a valid Perf Event FD provided through pfd, it will be used to enable
// and attach BPF program to the event, and event_path will be ignored.
// Otherwise, event_path is expected to contain the path to the event in tracefs
// and it will be used to open the Perf Event FD.
// In either case, if the attach partially failed (such as issue with the
// ioctl operations), the **caller** need to clean up the Perf Event FD, either
// provided by the caller or opened here.
static int bpf_attach_tracing_event(int progfd, const char *event_path, int pid,
                                    int *pfd)
{
  int efd, cpu = 0;
  ssize_t bytes;
  char buf[PATH_MAX];
  struct perf_event_attr attr = {};
  // Caller did not provide a valid Perf Event FD. Create one with the tracefs
  // event path provided.
  if (*pfd < 0) {
    snprintf(buf, sizeof(buf), "%s/id", event_path);
    efd = open(buf, O_RDONLY, 0);
    if (efd < 0) {
      fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
      return -1;
    }

    bytes = read(efd, buf, sizeof(buf));
    if (bytes <= 0 || bytes >= sizeof(buf)) {
      fprintf(stderr, "read(%s): %s\n", buf, strerror(errno));
      close(efd);
      return -1;
    }
    close(efd);
    buf[bytes] = '\0';
    attr.config = strtol(buf, NULL, 0);
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    // PID filter is only possible for uprobe events.
    if (pid < 0)
      pid = -1;
    // perf_event_open API doesn't allow both pid and cpu to be -1.
    // So only set it to -1 when PID is not -1.
    // Tracing events do not do CPU filtering in any cases.
    if (pid != -1)
      cpu = -1;
    *pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
    if (*pfd < 0) {
      fprintf(stderr, "perf_event_open(%s/id): %s\n", event_path, strerror(errno));
      return -1;
    }
  }

  if (ioctl(*pfd, PERF_EVENT_IOC_SET_BPF, progfd) < 0) {
    perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
    return -1;
  }
  if (ioctl(*pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    return -1;
  }

  return 0;
}

/* Creates an [uk]probe using tracefs.
 * On success, the path to the probe is placed in buf (which is assumed to be of size PATH_MAX).
 */
static int create_probe_event(char *buf, const char *ev_name,
                              enum bpf_probe_attach_type attach_type,
                              const char *config1, uint64_t offset,
                              const char *event_type, pid_t pid, int maxactive)
{
  int kfd = -1, res = -1;
  char ev_alias[256];
  bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;

  snprintf(buf, PATH_MAX, "%s/%s_events", get_tracefs_path(), event_type);
  kfd = open(buf, O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    fprintf(stderr, "%s: open(%s): %s\n", __func__, buf,
            strerror(errno));
    return -1;
  }

  res = snprintf(ev_alias, sizeof(ev_alias), "%s_bcc_%d", ev_name, getpid());
  if (res < 0 || res >= sizeof(ev_alias)) {
    fprintf(stderr, "Event name (%s) is too long for buffer\n", ev_name);
    close(kfd);
    goto error;
  }

  if (is_kprobe) {
    if (offset > 0 && attach_type == BPF_PROBE_ENTRY)
      snprintf(buf, PATH_MAX, "p:kprobes/%s %s+%"PRIu64,
               ev_alias, config1, offset);
    else if (maxactive > 0 && attach_type == BPF_PROBE_RETURN)
      snprintf(buf, PATH_MAX, "r%d:kprobes/%s %s",
               maxactive, ev_alias, config1);
    else
      snprintf(buf, PATH_MAX, "%c:kprobes/%s %s",
               attach_type == BPF_PROBE_ENTRY ? 'p' : 'r',
               ev_alias, config1);
  } else {
    res = snprintf(buf, PATH_MAX, "%c:%ss/%s %s:0x%lx", attach_type==BPF_PROBE_ENTRY ? 'p' : 'r',
                   event_type, ev_alias, config1, (unsigned long)offset);
    if (res < 0 || res >= PATH_MAX) {
      fprintf(stderr, "Event alias (%s) too long for buffer\n", ev_alias);
      close(kfd);
      return -1;
    }
  }

  if (write(kfd, buf, strlen(buf)) < 0) {
    if (errno == ENOENT)
      fprintf(stderr, "cannot attach %s, probe entry may not exist\n", event_type);
    else
      fprintf(stderr, "cannot attach %s, %s\n", event_type, strerror(errno));
    close(kfd);
    goto error;
  }
  close(kfd);
  snprintf(buf, PATH_MAX, "%s/events/%ss/%s", get_tracefs_path(),
           event_type, ev_alias);
  return 0;
error:
  return -1;
}

// config1 could be either kprobe_func or uprobe_path,
// see bpf_try_perf_event_open_with_probe().
static int bpf_attach_probe(int progfd, enum bpf_probe_attach_type attach_type,
                            const char *ev_name, const char *config1, const char* event_type,
                            uint64_t offset, pid_t pid, int maxactive,
                            uint32_t ref_ctr_offset)
{
  int kfd, pfd = -1;
  char buf[PATH_MAX], fname[256], kprobe_events[PATH_MAX];
  bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;

  if (maxactive <= 0)
    // Try create the [k,u]probe Perf Event with perf_event_open API.
    pfd = bpf_try_perf_event_open_with_probe(config1, offset, pid, event_type,
                                             attach_type != BPF_PROBE_ENTRY,
                                             ref_ctr_offset);

  // If failed, most likely Kernel doesn't support the perf_kprobe PMU
  // (e12f03d "perf/core: Implement the 'perf_kprobe' PMU") yet.
  // Try create the event using tracefs.
  if (pfd < 0) {
    if (create_probe_event(buf, ev_name, attach_type, config1, offset,
                           event_type, pid, maxactive) < 0)
      goto error;

    // If we're using maxactive, we need to check that the event was created
    // under the expected name.  If tracefs doesn't support maxactive yet
    // (kernel < 4.12), the event is created under a different name; we need to
    // delete that event and start again without maxactive.
    if (is_kprobe && maxactive > 0 && attach_type == BPF_PROBE_RETURN) {
      if (snprintf(fname, sizeof(fname), "%s/id", buf) >= sizeof(fname)) {
        fprintf(stderr, "filename (%s) is too long for buffer\n", buf);
        goto error;
      }
      if (access(fname, F_OK) == -1) {
        snprintf(kprobe_events, PATH_MAX, "%s/kprobe_events", get_tracefs_path());
        // Deleting kprobe event with incorrect name.
        kfd = open(kprobe_events, O_WRONLY | O_APPEND, 0);
        if (kfd < 0) {
          fprintf(stderr, "open(%s): %s\n", kprobe_events, strerror(errno));
          return -1;
        }
        snprintf(fname, sizeof(fname), "-:kprobes/%s_0", ev_name);
        if (write(kfd, fname, strlen(fname)) < 0) {
          if (errno == ENOENT)
            fprintf(stderr, "cannot detach kprobe, probe entry may not exist\n");
          else
            fprintf(stderr, "cannot detach kprobe, %s\n", strerror(errno));
          close(kfd);
          goto error;
        }
        close(kfd);

        // Re-creating kprobe event without maxactive.
        if (create_probe_event(buf, ev_name, attach_type, config1,
                               offset, event_type, pid, 0) < 0)
          goto error;
      }
    }
  }
  // If perf_event_open succeeded, bpf_attach_tracing_event will use the created
  // Perf Event FD directly and buf would be empty and unused.
  // Otherwise it will read the event ID from the path in buf, create the
  // Perf Event event using that ID, and updated value of pfd.
  if (bpf_attach_tracing_event(progfd, buf, pid, &pfd) == 0)
    return pfd;

error:
  bpf_close_perf_event_fd(pfd);
  return -1;
}

int bpf_attach_kprobe(int progfd, enum bpf_probe_attach_type attach_type,
                      const char *ev_name, const char *fn_name,
                      uint64_t fn_offset, int maxactive)
{
  return bpf_attach_probe(progfd, attach_type,
                          ev_name, fn_name, "kprobe",
                          fn_offset, -1, maxactive, 0);
}

static int _find_archive_path_and_offset(const char *entry_path,
                                         char out_path[PATH_MAX],
                                         uint64_t *offset) {
  const char *separator = strstr(entry_path, "!/");
  if (separator == NULL || (separator - entry_path) >= PATH_MAX) {
    return -1;
  }

  struct bcc_zip_entry entry;
  struct bcc_zip_archive *archive =
      bcc_zip_archive_open_and_find(entry_path, &entry);
  if (archive == NULL) {
    return -1;
  }
  if (entry.compression) {
    bcc_zip_archive_close(archive);
    return -1;
  }

  strncpy(out_path, entry_path, separator - entry_path);
  out_path[separator - entry_path] = 0;
  *offset += entry.data_offset;

  bcc_zip_archive_close(archive);
  return 0;
}

int bpf_attach_uprobe(int progfd, enum bpf_probe_attach_type attach_type,
                      const char *ev_name, const char *binary_path,
                      uint64_t offset, pid_t pid, uint32_t ref_ctr_offset)
{
  char archive_path[PATH_MAX];
  if (access(binary_path, F_OK) != 0 &&
      _find_archive_path_and_offset(binary_path, archive_path, &offset) == 0) {
    binary_path = archive_path;
  }

  return bpf_attach_probe(progfd, attach_type,
                          ev_name, binary_path, "uprobe",
                          offset, pid, -1, ref_ctr_offset);
}

static int bpf_detach_probe(const char *ev_name, const char *event_type)
{
  int kfd = -1, res;
  char buf[PATH_MAX];
  int found_event = 0;
  size_t bufsize = 0;
  char *cptr = NULL;
  FILE *fp;

  /*
   * For [k,u]probe created with perf_event_open (on newer kernel), it is
   * not necessary to clean it up in [k,u]probe_events. We first look up
   * the %s_bcc_%d line in [k,u]probe_events. If the event is not found,
   * it is safe to skip the cleaning up process (write -:... to the file).
   */
  snprintf(buf, sizeof(buf), "%s/%s_events", get_tracefs_path(), event_type);
  fp = fopen(buf, "r");
  if (!fp) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  res = snprintf(buf, sizeof(buf), "%ss/%s_bcc_%d", event_type, ev_name, getpid());
  if (res < 0 || res >= sizeof(buf)) {
    fprintf(stderr, "snprintf(%s): %d\n", ev_name, res);
    goto error;
  }

  while (getline(&cptr, &bufsize, fp) != -1)
    if (strstr(cptr, buf) != NULL) {
      found_event = 1;
      break;
    }
  free(cptr);
  fclose(fp);
  fp = NULL;

  if (!found_event)
    return 0;

  snprintf(buf, sizeof(buf), "%s/%s_events", get_tracefs_path(), event_type);
  kfd = open(buf, O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  res = snprintf(buf, sizeof(buf), "-:%ss/%s_bcc_%d", event_type, ev_name, getpid());
  if (res < 0 || res >= sizeof(buf)) {
    fprintf(stderr, "snprintf(%s): %d\n", ev_name, res);
    goto error;
  }
  if (write(kfd, buf, strlen(buf)) < 0) {
    fprintf(stderr, "write(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  close(kfd);
  return 0;

error:
  if (kfd >= 0)
    close(kfd);
  if (fp)
    fclose(fp);
  return -1;
}

int bpf_detach_kprobe(const char *ev_name)
{
  return bpf_detach_probe(ev_name, "kprobe");
}

int bpf_detach_uprobe(const char *ev_name)
{
  return bpf_detach_probe(ev_name, "uprobe");
}

int bpf_attach_tracepoint(int progfd, const char *tp_category,
                          const char *tp_name)
{
  char buf[256];
  int pfd = -1;

  snprintf(buf, sizeof(buf), "%s/events/%s/%s", get_tracefs_path(), tp_category, tp_name);
  if (bpf_attach_tracing_event(progfd, buf, -1 /* PID */, &pfd) == 0)
    return pfd;

  bpf_close_perf_event_fd(pfd);
  return -1;
}

int bpf_detach_tracepoint(const char *tp_category, const char *tp_name) {
  UNUSED(tp_category);
  UNUSED(tp_name);
  // Right now, there is nothing to do, but it's a good idea to encourage
  // callers to detach anything they attach.
  return 0;
}

int bpf_attach_raw_tracepoint(int progfd, const char *tp_name)
{
  int ret;

  ret = bpf_raw_tracepoint_open(tp_name, progfd);
  if (ret < 0)
    fprintf(stderr, "bpf_attach_raw_tracepoint (%s): %s\n", tp_name, strerror(errno));
  return ret;
}

bool bpf_has_kernel_btf(void)
{
  struct btf *btf;
  int err;

  btf = btf__parse_raw("/sys/kernel/btf/vmlinux");
  err = libbpf_get_error(btf);
  if (err)
    return false;

  btf__free(btf);
  return true;
}

static int find_member_by_name(struct btf *btf, const struct btf_type *btf_type, const char *field_name) {
  const struct btf_member *btf_member = btf_members(btf_type);
  int i;

  for (i = 0; i < btf_vlen(btf_type); i++, btf_member++) {
    const char *name = btf__name_by_offset(btf, btf_member->name_off);
    if (!strcmp(name, field_name)) {
      return 1;
    } else if (name[0] == '\0') {
      if (find_member_by_name(btf, btf__type_by_id(btf, btf_member->type), field_name))
        return 1;
    }
  }
  return 0;
}

int kernel_struct_has_field(const char *struct_name, const char *field_name)
{
  const struct btf_type *btf_type;
  struct btf *btf;
  int ret, btf_id;

  btf = btf__load_vmlinux_btf();
  ret = libbpf_get_error(btf);
  if (ret)
    return -1;

  btf_id = btf__find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
  if (btf_id < 0) {
    ret = -1;
    goto cleanup;
  }

  btf_type = btf__type_by_id(btf, btf_id);
  ret = find_member_by_name(btf, btf_type, field_name);

cleanup:
  btf__free(btf);
  return ret;
}

int bpf_attach_kfunc(int prog_fd)
{
  int ret;

  ret = bpf_raw_tracepoint_open(NULL, prog_fd);
  if (ret < 0)
    fprintf(stderr, "bpf_attach_raw_tracepoint (kfunc): %s\n", strerror(errno));
  return ret;
}

int bpf_attach_lsm(int prog_fd)
{
  int ret;

  ret = bpf_raw_tracepoint_open(NULL, prog_fd);
  if (ret < 0)
    fprintf(stderr, "bpf_attach_raw_tracepoint (lsm): %s\n", strerror(errno));
  return ret;
}

void * bpf_open_perf_buffer(perf_reader_raw_cb raw_cb,
                            perf_reader_lost_cb lost_cb, void *cb_cookie,
                            int pid, int cpu, int page_cnt)
{
  struct bcc_perf_buffer_opts opts = {
    .pid = pid,
    .cpu = cpu,
    .wakeup_events = 1,
  };

  return bpf_open_perf_buffer_opts(raw_cb, lost_cb, cb_cookie, page_cnt, &opts);
}

void * bpf_open_perf_buffer_opts(perf_reader_raw_cb raw_cb,
                            perf_reader_lost_cb lost_cb, void *cb_cookie,
                            int page_cnt, struct bcc_perf_buffer_opts *opts)
{
  int pfd, pid = opts->pid, cpu = opts->cpu;
  struct perf_event_attr attr = {};
  struct perf_reader *reader = NULL;

  reader = perf_reader_new(raw_cb, lost_cb, cb_cookie, page_cnt);
  if (!reader)
    goto error;

  attr.config = 10;//PERF_COUNT_SW_BPF_OUTPUT;
  attr.type = PERF_TYPE_SOFTWARE;
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.sample_period = 1;
  attr.wakeup_events = opts->wakeup_events;
  pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
  if (pfd < 0) {
    fprintf(stderr, "perf_event_open: %s\n", strerror(errno));
    fprintf(stderr, "   (check your kernel for PERF_COUNT_SW_BPF_OUTPUT support, 4.4 or newer)\n");
    goto error;
  }
  perf_reader_set_fd(reader, pfd);

  if (perf_reader_mmap(reader) < 0)
    goto error;

  if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    goto error;
  }

  return reader;

error:
  if (reader)
    perf_reader_free(reader);

  return NULL;
}

static int invalid_perf_config(uint32_t type, uint64_t config) {
  switch (type) {
  case PERF_TYPE_HARDWARE:
    if (config >= PERF_COUNT_HW_MAX) {
      fprintf(stderr, "HARDWARE perf event config out of range\n");
      goto is_invalid;
    }
    return 0;
  case PERF_TYPE_SOFTWARE:
    if (config >= PERF_COUNT_SW_MAX) {
      fprintf(stderr, "SOFTWARE perf event config out of range\n");
      goto is_invalid;
    } else if (config == 10 /* PERF_COUNT_SW_BPF_OUTPUT */) {
      fprintf(stderr, "Unable to open or attach perf event for BPF_OUTPUT\n");
      goto is_invalid;
    }
    return 0;
  case PERF_TYPE_HW_CACHE:
    if (((config >> 16) >= PERF_COUNT_HW_CACHE_RESULT_MAX) ||
        (((config >> 8) & 0xff) >= PERF_COUNT_HW_CACHE_OP_MAX) ||
        ((config & 0xff) >= PERF_COUNT_HW_CACHE_MAX)) {
      fprintf(stderr, "HW_CACHE perf event config out of range\n");
      goto is_invalid;
    }
    return 0;
  case PERF_TYPE_TRACEPOINT:
  case PERF_TYPE_BREAKPOINT:
    fprintf(stderr,
            "Unable to open or attach TRACEPOINT or BREAKPOINT events\n");
    goto is_invalid;
  default:
    return 0;
  }
is_invalid:
  fprintf(stderr, "Invalid perf event type %" PRIu32 " config %" PRIu64 "\n",
          type, config);
  return 1;
}

int bpf_open_perf_event(uint32_t type, uint64_t config, int pid, int cpu) {
  int fd;
  struct perf_event_attr attr = {};

  if (invalid_perf_config(type, config)) {
    return -1;
  }

  attr.sample_period = LONG_MAX;
  attr.type = type;
  attr.config = config;

  fd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "perf_event_open: %s\n", strerror(errno));
    return -1;
  }

  if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    close(fd);
    return -1;
  }

  return fd;
}

int bpf_attach_xdp(const char *dev_name, int progfd, uint32_t flags) {
  int ifindex = if_nametoindex(dev_name);
  char err_buf[256];
  int ret = -1;

  if (ifindex == 0) {
    fprintf(stderr, "bpf: Resolving device name to index: %s\n", strerror(errno));
    return -1;
  }

  ret = bpf_xdp_attach(ifindex, progfd, flags, NULL);
  if (ret) {
    libbpf_strerror(ret, err_buf, sizeof(err_buf));
    fprintf(stderr, "bpf: Attaching prog to %s: %s\n", dev_name, err_buf);
    return -1;
  }

  return 0;
}

int bpf_attach_perf_event_raw(int progfd, void *perf_event_attr, pid_t pid,
                              int cpu, int group_fd, unsigned long extra_flags) {
  int fd = syscall(__NR_perf_event_open, perf_event_attr, pid, cpu, group_fd,
                   PERF_FLAG_FD_CLOEXEC | extra_flags);
  if (fd < 0) {
    perror("perf_event_open failed");
    return -1;
  }
  if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, progfd) != 0) {
    perror("ioctl(PERF_EVENT_IOC_SET_BPF) failed");
    close(fd);
    return -1;
  }
  if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE) failed");
    close(fd);
    return -1;
  }

  return fd;
}

int bpf_attach_perf_event(int progfd, uint32_t ev_type, uint32_t ev_config,
                          uint64_t sample_period, uint64_t sample_freq,
                          pid_t pid, int cpu, int group_fd) {
  if (invalid_perf_config(ev_type, ev_config)) {
    return -1;
  }
  if (!((sample_period > 0) ^ (sample_freq > 0))) {
    fprintf(
      stderr, "Exactly one of sample_period / sample_freq should be set\n"
    );
    return -1;
  }

  struct perf_event_attr attr = {};
  attr.type = ev_type;
  attr.config = ev_config;
  if (pid > 0)
    attr.inherit = 1;
  if (sample_freq > 0) {
    attr.freq = 1;
    attr.sample_freq = sample_freq;
  } else {
    attr.sample_period = sample_period;
  }

  return bpf_attach_perf_event_raw(progfd, &attr, pid, cpu, group_fd, 0);
}

int bpf_close_perf_event_fd(int fd) {
  int res, error = 0;
  if (fd >= 0) {
    res = ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    if (res != 0) {
      perror("ioctl(PERF_EVENT_IOC_DISABLE) failed");
      error = res;
    }
    res = close(fd);
    if (res != 0) {
      perror("close perf event FD failed");
      error = (res && !error) ? res : error;
    }
  }
  return error;
}

/* Create a new ringbuf manager to manage ringbuf associated with
 * map_fd, associating it with callback sample_cb. */
void * bpf_new_ringbuf(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx) {
    return ring_buffer__new(map_fd, sample_cb, ctx, NULL);
}

/* Free the ringbuf manager rb and all ring buffers associated with it. */
void bpf_free_ringbuf(struct ring_buffer *rb) {
    ring_buffer__free(rb);
}

/* Add a new ring buffer associated with map_fd to the ring buffer manager rb,
 * associating it with callback sample_cb. */
int bpf_add_ringbuf(struct ring_buffer *rb, int map_fd,
                    ring_buffer_sample_fn sample_cb, void *ctx) {
    return ring_buffer__add(rb, map_fd, sample_cb, ctx);
}

/* Poll for available data and consume, if data is available.  Returns number
 * of records consumed, or a negative number if any callbacks returned an
 * error. */
int bpf_poll_ringbuf(struct ring_buffer *rb, int timeout_ms) {
    return ring_buffer__poll(rb, timeout_ms);
}

/* Consume available data _without_ polling. Good for use cases where low
 * latency is desired over performance impact.  Returns number of records
 * consumed, or a negative number if any callbacks returned an error. */
int bpf_consume_ringbuf(struct ring_buffer *rb) {
    return ring_buffer__consume(rb);
}

int bcc_iter_attach(int prog_fd, union bpf_iter_link_info *link_info,
                    uint32_t link_info_len)
{
    DECLARE_LIBBPF_OPTS(bpf_link_create_opts, link_create_opts);

    link_create_opts.iter_info = link_info;
    link_create_opts.iter_info_len = link_info_len;
    return bpf_link_create(prog_fd, 0, BPF_TRACE_ITER, &link_create_opts);
}

int bcc_iter_create(int link_fd)
{
    return bpf_iter_create(link_fd);
}

int bcc_make_parent_dir(const char *path) {
  int   err = 0;
  char *dname, *dir;

  dname = strdup(path);
  if (dname == NULL)
    return -ENOMEM;

  dir = dirname(dname);
  if (mkdir(dir, 0700) && errno != EEXIST)
    err = -errno;

  free(dname);
  if (err)
    fprintf(stderr, "failed to mkdir %s: %s\n", path, strerror(-err));

  return err;
}

int bcc_check_bpffs_path(const char *path) {
  struct statfs st_fs;
  char  *dname, *dir;
  int    err = 0;

  if (path == NULL)
    return -EINVAL;

  dname = strdup(path);
  if (dname == NULL)
    return -ENOMEM;

  dir = dirname(dname);
  if (statfs(dir, &st_fs)) {
    err = -errno;
    fprintf(stderr, "failed to statfs %s: %s\n", path, strerror(-err));
  }

  free(dname);
  if (!err && st_fs.f_type != BPF_FS_MAGIC) {
    err = -EINVAL;
    fprintf(stderr, "specified path %s is not on BPF FS\n", path);
  }

  return err;
}
```