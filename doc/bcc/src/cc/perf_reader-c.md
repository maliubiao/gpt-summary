Response:
### 功能列举与执行顺序（10步）

1. **初始化 Reader**  
   - 调用 `perf_reader_new` 创建 `perf_reader` 结构体，配置回调函数和环形缓冲区参数（如页数）。

2. **设置文件描述符 (FD)**  
   - 通过 `perf_reader_set_fd` 将 `perf_event_open` 返回的 FD 绑定到 Reader，后续通过此 FD 操作事件。

3. **内存映射环形缓冲区**  
   - 调用 `perf_reader_mmap` 使用 `mmap` 将内核环形缓冲区映射到用户空间，支持高效读取。

4. **启用 Perf 事件**  
   - 通过 `ioctl(fd, PERF_EVENT_IOC_ENABLE)`（代码中未直接显示，但隐含在 BCC 工具链中）启动事件采样。

5. **事件轮询或消费**  
   - 使用 `perf_reader_poll` 或 `perf_reader_consume` 主动检查或等待事件到来，触发数据读取。

6. **读取事件数据**  
   - `perf_reader_event_read` 读取环形缓冲区，处理边界回绕，将数据拷贝到连续内存（如需要）。

7. **解析事件类型**  
   - 根据 `PERF_RECORD_SAMPLE` 或 `PERF_RECORD_LOST` 类型，调用对应的解析函数（如 `parse_sw`）。

8. **回调用户处理逻辑**  
   - 通过 `raw_cb` 传递有效数据（如进程 PID、文件路径），通过 `lost_cb` 通知丢失事件数。

9. **更新缓冲区指针**  
   - 调用 `write_data_tail` 更新缓冲区尾部指针，通知内核空间数据已消费。

10. **资源释放**  
    - 调用 `perf_reader_free` 解除内存映射、关闭 FD、释放内存，确保无内存泄漏。

---

### eBPF Hook 点与信息提取

1. **Hook 点**  
   - **类型**: 由 `perf_event_open` 配置决定（如 tracepoint、kprobe、uprobe）。
   - **示例函数**: `sys_open`（跟踪文件打开）、`tcp_sendmsg`（网络流量监控）。
   
2. **有效信息示例**  
   - **进程 PID**: 通过 `struct perf_sample_trace_common` 的 `pid` 字段获取。
   - **文件路径**: 若 Hook `sys_open`，eBPF 程序捕获 `filename` 参数，通过 `raw_cb` 传递。
   - **调用栈/IP 地址**: `struct perf_sample_trace_kprobe` 中的 `ip` 字段表示指令指针。

---

### 逻辑推理：输入与输出示例

1. **输入假设**  
   - eBPF 程序 Hook `sys_open`，捕获进程打开文件的路径。
   - 用户定义 `raw_cb` 打印文件路径和 PID。

2. **输出示例**  
   ```c
   void raw_cb(void *ctx, void *data, size_t size) {
       char *filename = (char *)data;
       int pid = ((struct perf_sample_trace_common *)data)->pid;
       printf("PID %d opened file: %s\n", pid, filename);
   }
   ```

---

### 常见使用错误

1. **未处理丢失事件**  
   - **错误示例**: 不设置 `lost_cb`，导致无法感知采样丢失。
   - **后果**: 统计数据不准确，无法评估系统负载。

2. **多线程竞争**  
   - **错误示例**: 在多线程中同时调用 `perf_reader_event_read`。
   - **后果**: `rb_use_state` 状态竞争，数据损坏或程序崩溃。

3. **缓冲区过小**  
   - **错误示例**: 初始化时 `page_cnt` 设置过小。
   - **后果**: 频繁丢失事件，或需频繁拷贝回绕数据，性能下降。

---

### Syscall 调试线索

1. **触发路径**  
   - **用户层**: 调用 `perf_event_open` 创建 FD → 传递给 `perf_reader_set_fd`。
   - **内核层**: 事件触发（如系统调用）→ 数据写入环形缓冲区。
   - **用户层**: `poll` 检测 FD 可读 → 调用 `perf_reader_event_read` 解析数据。

2. **调试检查点**  
   - **FD 有效性**: 确认 `perf_event_open` 成功，且 FD 被正确设置到 Reader。
   - **MMAP 状态**: 检查 `perf_reader_mmap` 是否成功，`base` 指针非 `MAP_FAILED`。
   - **事件类型匹配**: 确保内核事件类型（如 `PERF_RECORD_SAMPLE`）与解析逻辑一致。

---

### 总结

此文件是 BCC 中处理 Perf 环形缓冲区的核心模块，负责高效读取 eBPF 程序采集的内核事件。通过合理配置回调函数和缓冲区参数，可实现低开销的实时监控。常见陷阱包括线程安全、丢失事件处理和缓冲区大小调优。调试时需关注 FD 生命周期和内存映射状态。
Prompt: 
```
这是目录为bcc/src/cc/perf_reader.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

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

#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/perf_event.h>

#include "libbpf.h"
#include "perf_reader.h"

enum {
  RB_NOT_USED = 0, // ring buffer not usd
  RB_USED_IN_MUNMAP = 1, // used in munmap
  RB_USED_IN_READ = 2, // used in read
};

struct perf_reader {
  perf_reader_raw_cb raw_cb;
  perf_reader_lost_cb lost_cb;
  void *cb_cookie; // to be returned in the cb
  void *buf; // for keeping segmented data
  size_t buf_size;
  void *base;
  int rb_use_state;
  pid_t rb_read_tid;
  int page_size;
  int page_cnt;
  int fd;
};

struct perf_reader * perf_reader_new(perf_reader_raw_cb raw_cb,
                                     perf_reader_lost_cb lost_cb,
                                     void *cb_cookie, int page_cnt) {
  struct perf_reader *reader = calloc(1, sizeof(struct perf_reader));
  if (!reader)
    return NULL;
  reader->raw_cb = raw_cb;
  reader->lost_cb = lost_cb;
  reader->cb_cookie = cb_cookie;
  reader->fd = -1;
  reader->page_size = getpagesize();
  reader->page_cnt = page_cnt;
  return reader;
}

void perf_reader_free(void *ptr) {
  if (ptr) {
    struct perf_reader *reader = ptr;
    pid_t tid = syscall(__NR_gettid);
    while (!__sync_bool_compare_and_swap(&reader->rb_use_state, RB_NOT_USED, RB_USED_IN_MUNMAP)) {
      // If the same thread, it is called from call back handler, no locking needed
      if (tid == reader->rb_read_tid)
        break;
    }
    munmap(reader->base, reader->page_size * (reader->page_cnt + 1));
    if (reader->fd >= 0) {
      ioctl(reader->fd, PERF_EVENT_IOC_DISABLE, 0);
      close(reader->fd);
    }
    free(reader->buf);
    free(ptr);
  }
}

int perf_reader_mmap(struct perf_reader *reader) {
  int mmap_size = reader->page_size * (reader->page_cnt + 1);

  if (reader->fd < 0) {
    fprintf(stderr, "%s: reader fd is not set\n", __FUNCTION__);
    return -1;
  }

  reader->base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, reader->fd, 0);
  if (reader->base == MAP_FAILED) {
    perror("mmap");
    return -1;
  }

  return 0;
}

struct perf_sample_trace_common {
  uint16_t id;
  uint8_t flags;
  uint8_t preempt_count;
  int pid;
};

struct perf_sample_trace_kprobe {
  struct perf_sample_trace_common common;
  uint64_t ip;
};

static void parse_sw(struct perf_reader *reader, void *data, int size) {
  uint8_t *ptr = data;
  struct perf_event_header *header = (void *)data;

  struct {
      uint32_t size;
      char data[0];
  } *raw = NULL;

  ptr += sizeof(*header);
  if (ptr > (uint8_t *)data + size) {
    fprintf(stderr, "%s: corrupt sample header\n", __FUNCTION__);
    return;
  }

  raw = (void *)ptr;
  ptr += sizeof(raw->size) + raw->size;
  if (ptr > (uint8_t *)data + size) {
    fprintf(stderr, "%s: corrupt raw sample\n", __FUNCTION__);
    return;
  }

  // sanity check
  if (ptr != (uint8_t *)data + size) {
    fprintf(stderr, "%s: extra data at end of sample\n", __FUNCTION__);
    return;
  }

  if (reader->raw_cb)
    reader->raw_cb(reader->cb_cookie, raw->data, raw->size);
}

static uint64_t read_data_head(volatile struct perf_event_mmap_page *perf_header) {
  uint64_t data_head = perf_header->data_head;
  asm volatile("" ::: "memory");
  return data_head;
}

static void write_data_tail(volatile struct perf_event_mmap_page *perf_header, uint64_t data_tail) {
  asm volatile("" ::: "memory");
  perf_header->data_tail = data_tail;
}

void perf_reader_event_read(struct perf_reader *reader) {
  volatile struct perf_event_mmap_page *perf_header = reader->base;
  uint64_t buffer_size = (uint64_t)reader->page_size * reader->page_cnt;
  uint64_t data_head;
  uint8_t *base = (uint8_t *)reader->base + reader->page_size;
  uint8_t *sentinel = (uint8_t *)reader->base + buffer_size + reader->page_size;
  uint8_t *begin, *end;

  reader->rb_read_tid = syscall(__NR_gettid);
  if (!__sync_bool_compare_and_swap(&reader->rb_use_state, RB_NOT_USED, RB_USED_IN_READ))
    return;

  // Consume all the events on this ring, calling the cb function for each one.
  // The message may fall on the ring boundary, in which case copy the message
  // into a malloced buffer.
  for (data_head = read_data_head(perf_header); perf_header->data_tail != data_head;
      data_head = read_data_head(perf_header)) {
    uint64_t data_tail = perf_header->data_tail;
    uint8_t *ptr;

    begin = base + data_tail % buffer_size;
    // event header is u64, won't wrap
    struct perf_event_header *e = (void *)begin;
    ptr = begin;
    end = base + (data_tail + e->size) % buffer_size;
    if (end < begin) {
      // perf event wraps around the ring, make a contiguous copy
      reader->buf = realloc(reader->buf, e->size);
      size_t len = sentinel - begin;
      memcpy(reader->buf, begin, len);
      memcpy((void *)((unsigned long)reader->buf + len), base, e->size - len);
      ptr = reader->buf;
    }

    if (e->type == PERF_RECORD_LOST) {
      /*
       * struct {
       *    struct perf_event_header    header;
       *    u64                id;
       *    u64                lost;
       *    struct sample_id        sample_id;
       * };
       */
      uint64_t lost = *(uint64_t *)(ptr + sizeof(*e) + sizeof(uint64_t));
      if (reader->lost_cb) {
        reader->lost_cb(reader->cb_cookie, lost);
      } else {
        fprintf(stderr, "Possibly lost %" PRIu64 " samples\n", lost);
      }
    } else if (e->type == PERF_RECORD_SAMPLE) {
      parse_sw(reader, ptr, e->size);
    } else {
      fprintf(stderr, "%s: unknown sample type %d\n", __FUNCTION__, e->type);
    }

    write_data_tail(perf_header, perf_header->data_tail + e->size);
  }
  reader->rb_use_state = RB_NOT_USED;
  __sync_synchronize();
  reader->rb_read_tid = 0;
}

int perf_reader_poll(int num_readers, struct perf_reader **readers, int timeout) {
  struct pollfd pfds[num_readers];
  int i;

  for (i = 0; i <num_readers; ++i) {
    pfds[i].fd = readers[i]->fd;
    pfds[i].events = POLLIN;
  }

  if (poll(pfds, num_readers, timeout) > 0) {
    for (i = 0; i < num_readers; ++i) {
      if (pfds[i].revents & POLLIN)
        perf_reader_event_read(readers[i]);
    }
  }
  return 0;
}

int perf_reader_consume(int num_readers, struct perf_reader **readers) {
  int i;
  for (i = 0; i < num_readers; ++i) {
    perf_reader_event_read(readers[i]);
  }
  return 0;
}

void perf_reader_set_fd(struct perf_reader *reader, int fd) {
  reader->fd = fd;
}

int perf_reader_fd(struct perf_reader *reader) {
  return reader->fd;
}

"""

```