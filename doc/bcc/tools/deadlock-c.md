Response:
### 功能列举
1. **检测潜在死锁**：通过跟踪互斥锁的获取顺序，构建锁依赖图并检测循环依赖。
2. **线程锁持有跟踪**：记录每个线程当前持有的所有互斥锁地址。
3. **锁依赖图构建**：维护一个全局的锁依赖图（边表），记录锁之间的获取顺序。
4. **堆栈追踪**：捕获线程创建、锁获取时的用户态堆栈信息。
5. **线程创建关系跟踪**：记录父线程创建子线程时的调用关系。
6. **递归锁过滤**：避免对同一锁重复获取导致的误报。
7. **资源限制处理**：处理哈希表容量不足时的错误场景。
8. **用户态进程跟踪**：通过用户态堆栈追踪定位代码位置。
9. **进程信息记录**：记录进程名称(comm字段)用于调试。
10. **性能优化**：使用循环展开避免BPF验证器失败。

---

### 执行顺序（10步）
1. **线程创建**：通过`trace_clone()`跟踪新线程创建，记录父线程信息。
2. **锁获取事件**：当线程调用`pthread_mutex_lock()`时触发`trace_mutex_acquire()`。
3. **检查递归锁**：遍历已持有锁列表，过滤重复获取。
4. **记录新锁信息**：将新锁地址和堆栈ID存入线程的持有锁列表。
5. **构建依赖边**：为新锁与所有已持有锁创建`N->M`边，存入全局边表。
6. **锁释放事件**：当调用`pthread_mutex_unlock()`时触发`trace_mutex_release()`。
7. **清理持有锁列表**：从线程的持有锁列表中移除释放的锁。
8. **周期性检测**：（隐含逻辑）用户态程序定期读取边表检测循环。
9. **循环依赖分析**：在用户态对边表进行拓扑排序或DFS检测环路。
10. **结果报告**：输出检测到的死锁环路及关联堆栈信息。

---

### eBPF Hook点及信息
| Hook点                     | 函数名               | 读取的有效信息                              | 示例值                          |
|---------------------------|---------------------|------------------------------------------|-------------------------------|
| `pthread_mutex_lock`入口   | `trace_mutex_acquire` | - 互斥锁地址(`mutex_addr`)<br>- 线程PID<br>- 用户态堆栈ID | `mutex_addr=0x7ffd4a1b8e00`<br>`pid=1234`<br>`stack_id=42` |
| `pthread_mutex_unlock`入口 | `trace_mutex_release` | - 释放的锁地址<br>- 线程PID                  | `mutex_addr=0x7ffd4a1b8e00`<br>`pid=1234` |
| `clone`系统调用返回        | `trace_clone`        | - 子线程PID<br>- 父线程PID<br>- 创建堆栈ID    | `child_pid=5678`<br>`parent_pid=1234`<br>`stack_id=15` |

---

### 逻辑推理示例
**假设输入（两个线程操作锁的顺序）：**
- 线程T1顺序：获取锁A → 尝试获取锁B
- 线程T2顺序：获取锁B → 尝试获取锁A

**程序输出：**
1. 边表中记录 `A→B` (来自T1) 和 `B→A` (来自T2)
2. 用户态检测到循环依赖 `A→B→A`
3. 报告包含：
   - 锁地址A/B
   - T1/T2的进程名（如`my_proc`）
   - 获取锁时的用户态堆栈

---

### 常见使用错误示例
1. **递归锁误报**：  
   ```c
   pthread_mutex_lock(&mutex);
   pthread_mutex_lock(&mutex); // 递归获取未使用递归锁
   ```
   程序会过滤第二个获取操作，但实际应产生错误（真实死锁）。

2. **超过MAX_HELD_MUTEXES限制**：  
   线程持有17个锁时，第17个锁无法记录，导致依赖边缺失。

3. **未配对lock/unlock**：  
   ```c
   pthread_mutex_lock(&mutex);
   // 忘记解锁
   ```
   导致后续所有相关锁操作被错误关联。

---

### Syscall到达路径（调试线索）
1. **用户调用**：  
   `pthread_mutex_lock() -> glibc包装 -> futex()系统调用`

2. **内核路径**：  
   `SYSCALL_futex() -> futex_wait() -> 锁竞争处理`

3. **eBPF Hook点**：  
   - uprobe在`pthread_mutex_lock()`函数入口
   - kprobe在`sys_futex()`（但此代码实际使用用户态函数hook）

4. **上下文捕获**：  
   通过`pt_regs *ctx`获取寄存器参数，提取第一个参数作为`mutex_addr`。

---

### 关键调试数据
1. **thread_to_held_mutexes**：查看某线程当前持有的所有锁地址。
2. **edges**：检查锁依赖边的完整性和循环。
3. **stack_traces**：通过`stack_id`解析具体代码位置。
4. **thread_to_parent**：验证线程创建关系是否正常记录。
Prompt: 
```
这是目录为bcc/tools/deadlock.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，举例说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
/*
 * deadlock.c  Detects potential deadlocks in a running process.
 *             For Linux, uses BCC, eBPF. See .py file.
 *
 * Copyright 2017 Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 1-Feb-2016   Kenny Yu   Created this.
 */

#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

// Maximum number of mutexes a single thread can hold at once.
// If the number is too big, the unrolled loops wil cause the stack
// to be too big, and the bpf verifier will fail.
#define MAX_HELD_MUTEXES 16

// Info about held mutexes. `mutex` will be 0 if not held.
struct held_mutex_t {
  u64 mutex;
  u64 stack_id;
};

// List of mutexes that a thread is holding. Whenever we loop over this array,
// we need to force the compiler to unroll the loop, otherwise the bcc verifier
// will fail because the loop will create a backwards edge.
struct thread_to_held_mutex_leaf_t {
  struct held_mutex_t held_mutexes[MAX_HELD_MUTEXES];
};

// Map of thread ID -> array of (mutex addresses, stack id)
BPF_HASH(thread_to_held_mutexes, u32, struct thread_to_held_mutex_leaf_t, MAX_THREADS);

// Key type for edges. Represents an edge from mutex1 => mutex2.
struct edges_key_t {
  u64 mutex1;
  u64 mutex2;
};

// Leaf type for edges. Holds information about where each mutex was acquired.
struct edges_leaf_t {
  u64 mutex1_stack_id;
  u64 mutex2_stack_id;
  u32 thread_pid;
  char comm[TASK_COMM_LEN];
};

// Represents all edges currently in the mutex wait graph.
BPF_HASH(edges, struct edges_key_t, struct edges_leaf_t, MAX_EDGES);

// Info about parent thread when a child thread is created.
struct thread_created_leaf_t {
  u64 stack_id;
  u32 parent_pid;
  char comm[TASK_COMM_LEN];
};

// Map of child thread pid -> info about parent thread.
BPF_HASH(thread_to_parent, u32, struct thread_created_leaf_t);

// Stack traces when threads are created and when mutexes are locked/unlocked.
BPF_STACK_TRACE(stack_traces, MAX_TRACES);

// The first argument to the user space function we are tracing
// is a pointer to the mutex M held by thread T.
//
// For all mutexes N held by mutexes_held[T]
//   add edge N => M (held by T)
// mutexes_held[T].add(M)
int trace_mutex_acquire(struct pt_regs *ctx, void *mutex_addr) {
  // Higher 32 bits is process ID, Lower 32 bits is thread ID
  u32 pid = bpf_get_current_pid_tgid();
  u64 mutex = (u64)mutex_addr;

  struct thread_to_held_mutex_leaf_t empty_leaf = {};
  struct thread_to_held_mutex_leaf_t *leaf =
      thread_to_held_mutexes.lookup_or_try_init(&pid, &empty_leaf);
  if (!leaf) {
    bpf_trace_printk(
        "could not add thread_to_held_mutex key, thread: %d, mutex: %p\n", pid,
        mutex);
    return 1; // Could not insert, no more memory
  }

  // Recursive mutexes lock the same mutex multiple times. We cannot tell if
  // the mutex is recursive after the mutex is already created. To avoid noisy
  // reports, disallow self edges. Do one pass to check if we are already
  // holding the mutex, and if we are, do nothing.
  #pragma unroll
  for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
    if (leaf->held_mutexes[i].mutex == mutex) {
      return 1; // Disallow self edges
    }
  }

  u64 stack_id =
      stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

  int added_mutex = 0;
  #pragma unroll
  for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
    // If this is a free slot, see if we can insert.
    if (!leaf->held_mutexes[i].mutex) {
      if (!added_mutex) {
        leaf->held_mutexes[i].mutex = mutex;
        leaf->held_mutexes[i].stack_id = stack_id;
        added_mutex = 1;
      }
      continue; // Nothing to do for a free slot
    }

    // Add edges from held mutex => current mutex
    struct edges_key_t edge_key = {};
    edge_key.mutex1 = leaf->held_mutexes[i].mutex;
    edge_key.mutex2 = mutex;

    struct edges_leaf_t edge_leaf = {};
    edge_leaf.mutex1_stack_id = leaf->held_mutexes[i].stack_id;
    edge_leaf.mutex2_stack_id = stack_id;
    edge_leaf.thread_pid = pid;
    bpf_get_current_comm(&edge_leaf.comm, sizeof(edge_leaf.comm));

    // Returns non-zero on error
    int result = edges.update(&edge_key, &edge_leaf);
    if (result) {
      bpf_trace_printk("could not add edge key %p, %p, error: %d\n",
                       edge_key.mutex1, edge_key.mutex2, result);
      continue; // Could not insert, no more memory
    }
  }

  // There were no free slots for this mutex.
  if (!added_mutex) {
    bpf_trace_printk("could not add mutex %p, added_mutex: %d\n", mutex,
                     added_mutex);
    return 1;
  }
  return 0;
}

// The first argument to the user space function we are tracing
// is a pointer to the mutex M held by thread T.
//
// mutexes_held[T].remove(M)
int trace_mutex_release(struct pt_regs *ctx, void *mutex_addr) {
  // Higher 32 bits is process ID, Lower 32 bits is thread ID
  u32 pid = bpf_get_current_pid_tgid();
  u64 mutex = (u64)mutex_addr;

  struct thread_to_held_mutex_leaf_t *leaf =
      thread_to_held_mutexes.lookup(&pid);
  if (!leaf) {
    // If the leaf does not exist for the pid, then it means we either missed
    // the acquire event, or we had no more memory and could not add it.
    bpf_trace_printk(
        "could not find thread_to_held_mutex, thread: %d, mutex: %p\n", pid,
        mutex);
    return 1;
  }

  // For older kernels without "Bpf: allow access into map value arrays"
  // (https://lkml.org/lkml/2016/8/30/287) the bpf verifier will fail with an
  // invalid memory access on `leaf->held_mutexes[i]` below. On newer kernels,
  // we can avoid making this extra copy in `value` and use `leaf` directly.
  struct thread_to_held_mutex_leaf_t value = {};
  bpf_probe_read_user(&value, sizeof(struct thread_to_held_mutex_leaf_t), leaf);

  #pragma unroll
  for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
    // Find the current mutex (if it exists), and clear it.
    // Note: Can't use `leaf->` in this if condition, see comment above.
    if (value.held_mutexes[i].mutex == mutex) {
      leaf->held_mutexes[i].mutex = 0;
      leaf->held_mutexes[i].stack_id = 0;
    }
  }

  return 0;
}

// Trace return from clone() syscall in the child thread (return value > 0).
int trace_clone(struct pt_regs *ctx, unsigned long flags, void *child_stack,
                void *ptid, void *ctid, struct pt_regs *regs) {
  u32 child_pid = PT_REGS_RC(ctx);
  if (child_pid <= 0) {
    return 1;
  }

  struct thread_created_leaf_t thread_created_leaf = {};
  thread_created_leaf.parent_pid = bpf_get_current_pid_tgid();
  thread_created_leaf.stack_id =
      stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
  bpf_get_current_comm(&thread_created_leaf.comm,
                       sizeof(thread_created_leaf.comm));

  struct thread_created_leaf_t *insert_result =
      thread_to_parent.lookup_or_try_init(&child_pid, &thread_created_leaf);
  if (!insert_result) {
    bpf_trace_printk(
        "could not add thread_created_key, child: %d, parent: %d\n", child_pid,
        thread_created_leaf.parent_pid);
    return 1; // Could not insert, no more memory
  }
  return 0;
}

"""

```