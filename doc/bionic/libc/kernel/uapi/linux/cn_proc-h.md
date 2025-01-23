Response:
Let's break down the thought process to answer the user's request about `cn_proc.h`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `cn_proc.h` header file within the context of Android's Bionic library. The prompt specifically asks for:

* Functionality listing.
* Relevance to Android with examples.
* Detailed explanation of libc functions (though the file itself doesn't *define* libc functions, it defines *data structures* used by kernel APIs that *might* be interacted with by libc functions). This needs clarification in the answer.
* Dynamic linker implications (also less direct, but related to process creation/execution, so worth considering).
* Logical reasoning with examples.
* Common usage errors.
* How Android framework/NDK reach this code, with a Frida hook example.

**2. Initial Analysis of the Header File:**

The first step is to read the header file and identify its key components:

* **Include Guard:** `#ifndef _UAPICN_PROC_H`...`#endif` - Standard practice to prevent multiple inclusions.
* **Includes:** `#include <linux/types.h>` - Basic Linux data types.
* **Enums:**
    * `proc_cn_mcast_op`: Defines operations for multicast communication (LISTEN/IGNORE).
    * `proc_cn_event`:  Defines different types of process events (FORK, EXEC, UID, etc.). The bitmask nature of `PROC_EVENT_ALL` is important.
* **Structs:**
    * `proc_input`:  Structure for specifying which events to listen for.
    * `proc_event`:  The main structure containing information about a specific process event. The `union` is crucial as it holds data specific to the event type.

**3. Identifying the Core Functionality:**

The enums and structs clearly point to a mechanism for receiving notifications about process-related events. The "cn" likely stands for "connector," suggesting an interface for communication, probably between the kernel and user-space.

**4. Relating to Android:**

Since this is within Bionic (Android's libc), it's highly likely this header is used by Android components to monitor process activities. Examples that come to mind are:

* **Activity Manager:** Tracking app launches, crashes, etc.
* **Process Stats:**  Collecting data for battery usage or performance monitoring.
* **Security Components:**  Monitoring for suspicious process behavior.
* **Debuggers/Profilers:** Getting notifications about process events for debugging.

**5. Addressing the "libc Function" Question:**

The header file *doesn't* contain libc function definitions. It defines *data structures* that would be used *in conjunction with* system calls and potentially libc wrapper functions. The answer needs to clarify this distinction. Examples of relevant system calls would be `socket`, `bind`, `connect`, `send`, `recv` (for the underlying netlink socket used by the connector), and potentially functions related to process management (though the connector itself is primarily for *notification*).

**6. Considering Dynamic Linker Implications:**

While not directly involved, the dynamic linker (`linker64` or `linker`) is responsible for starting processes. Therefore, the `PROC_EVENT_FORK` and `PROC_EVENT_EXEC` events are indirectly related to its actions. The linker sets up the process environment before the `execve` system call triggers the `PROC_EVENT_EXEC` notification. A simple SO layout example can demonstrate the basic structure of a dynamically linked executable.

**7. Logical Reasoning and Examples:**

Think about how a component might use this. For example, to monitor for crashes (`PROC_EVENT_EXIT` with a non-zero exit code), you'd listen for that specific event. To track process creation, you'd listen for `PROC_EVENT_FORK` and `PROC_EVENT_EXEC`. Provide hypothetical input (what you configure the `proc_input` struct to be) and the expected output (the `proc_event` structure content).

**8. Common Usage Errors:**

Potential mistakes include:

* Incorrectly setting the bitmask in `proc_input.event_type`.
* Not handling different `proc_event.what` types correctly in the `union`.
* Forgetting to handle the underlying socket communication properly.

**9. Tracing the Path from Framework/NDK:**

This requires understanding Android's architecture.

* **Framework:** High-level Java code interacts with native services (often through JNI). These services might use the connector.
* **NDK:** Native code can directly use the relevant system calls and structures defined in this header.

A key is to identify *which Android components* are likely to use this. System services are a good starting point.

**10. Frida Hook Example:**

A Frida hook should target a point where this header's data structures are being used. Since it's about kernel notifications, hooking a system call related to the connector (like `recvmsg` on the relevant socket) would be a good approach. Alternatively, hooking a known Android service that utilizes this mechanism could work. The example should show how to intercept the data and interpret the `proc_event` structure.

**11. Structuring the Answer:**

Organize the answer logically, addressing each point in the user's request. Use clear headings and examples. Start with a summary of the file's purpose. Be precise in terminology.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on direct libc function definitions. **Correction:** Realized the header defines data structures used *with* system calls and potentially libc wrappers, not the functions themselves.
* **Initial thought:**  Overcomplicating the dynamic linker explanation. **Correction:** Simplified it to the connection to process startup and the relevant events.
* **Frida Hook:** Initially considered hooking a user-space function. **Correction:**  Decided hooking a lower-level system call or a service known to use this mechanism would be more effective for demonstrating the kernel interaction.

By following this thought process, breaking down the request, analyzing the code, connecting it to Android concepts, and anticipating potential questions, a comprehensive and accurate answer can be constructed.
这是一个定义了Linux Netlink Connector中进程事件相关数据结构的头文件。它并非直接包含C标准库 (libc) 函数的实现代码，而是定义了用于在内核空间和用户空间之间传递进程事件信息的接口。Bionic 是 Android 的 C 库，这个头文件是 Bionic 中与内核接口的一部分。

**功能列举:**

这个头文件定义了以下内容，用于进程事件通知：

1. **`enum proc_cn_mcast_op`**:  定义了 Netlink Connector 多播操作的枚举，包括 `PROC_CN_MCAST_LISTEN` (监听) 和 `PROC_CN_MCAST_IGNORE` (忽略)。这允许用户空间的程序订阅或取消订阅特定的进程事件通知。

2. **`PROC_EVENT_ALL`**:  定义了一个宏，包含了所有可监听的进程事件类型的按位或组合。

3. **`enum proc_cn_event`**: 定义了各种进程事件类型的枚举，例如：
    * `PROC_EVENT_FORK`: 进程 fork 事件。
    * `PROC_EVENT_EXEC`: 进程执行新的程序 (exec) 事件。
    * `PROC_EVENT_UID`: 进程用户 ID (UID) 变更事件。
    * `PROC_EVENT_GID`: 进程组 ID (GID) 变更事件。
    * `PROC_EVENT_SID`: 进程会话 ID (SID) 变更事件。
    * `PROC_EVENT_PTRACE`: 进程被 ptrace 跟踪的事件。
    * `PROC_EVENT_COMM`: 进程命令名 (comm) 变更事件。
    * `PROC_EVENT_NONZERO_EXIT`: 进程以非零退出码退出的事件。
    * `PROC_EVENT_COREDUMP`: 进程发生 core dump 的事件。
    * `PROC_EVENT_EXIT`: 进程退出的事件。

4. **`struct proc_input`**: 定义了用户空间程序向内核发送的控制信息结构体，用于指定要监听的事件类型和多播操作。

5. **`struct proc_event`**: 定义了内核向用户空间发送的进程事件信息的结构体，包含了事件类型、发生事件的 CPU、时间戳以及与具体事件相关的数据 (通过 `union` 实现)。

**与 Android 功能的关系及举例说明:**

这个头文件定义的机制是 Android 系统监控进程活动的重要组成部分。Android 的许多核心功能都依赖于了解进程的生命周期和状态变化。以下是一些例子：

* **Activity Manager (AMS):** AMS 负责管理 Android 的应用程序生命周期。它可能使用这些事件来跟踪应用程序的启动、停止和崩溃等情况。例如，当一个应用程序启动时，会发生 `PROC_EVENT_FORK` 和 `PROC_EVENT_EXEC` 事件，AMS 可以接收到这些通知。当应用程序崩溃时，会发生 `PROC_EVENT_EXIT` 或 `PROC_EVENT_COREDUMP` 事件。

* **Process Stats / Battery Stats:** Android 系统需要跟踪每个进程的资源使用情况（例如 CPU 使用率、内存占用）。`PROC_EVENT_FORK` 和 `PROC_EVENT_EXIT` 事件可以帮助系统准确地记录进程的开始和结束时间，从而计算资源消耗。

* **Security 组件:** 安全相关的组件可能会监听 `PROC_EVENT_PTRACE` 事件来检测是否有进程正在被调试，这可能是恶意行为的迹象。监听 UID/GID 变更事件可以帮助跟踪权限变化。

* **Debuggers 和 Profilers:**  Android 的调试器 (例如 `adb shell gdbserver`) 和性能分析工具 (例如 Simpleperf) 会利用 `PROC_EVENT_FORK`, `PROC_EVENT_EXEC`, `PROC_EVENT_EXIT` 等事件来跟踪目标进程的执行流程。

**libc 函数的功能实现:**

这个头文件本身 **不包含** libc 函数的实现。它定义了内核与用户空间通信的数据结构。用户空间的程序需要使用底层的系统调用，如 `socket`, `bind`, `connect`, `send`, `recv` 等，来建立与 Netlink Connector 的连接，并发送和接收这些结构体定义的数据。

Bionic 的 libc 中可能存在封装这些系统调用的函数，方便 Android 开发者使用。例如，可能会有函数来初始化 Netlink Connector 连接，设置监听的事件类型，以及接收和解析 `proc_event` 结构体。但这些函数的具体实现不在这个头文件中。

**涉及 dynamic linker 的功能:**

`PROC_EVENT_FORK` 和 `PROC_EVENT_EXEC` 事件与 dynamic linker 的工作密切相关。当一个新进程被 fork 出来后，dynamic linker 负责加载和链接新进程所需的共享库。当新进程执行 (`execve`) 时，dynamic linker 会被激活。

**so 布局样本:**

假设一个简单的 Android 应用程序 `my_app` 依赖于两个共享库 `liba.so` 和 `libb.so`。

```
/system/bin/my_app  (可执行文件)
/system/lib64/liba.so
/system/lib64/libb.so
/apex/com.android.runtime/lib64/bionic/libc.so  (Bionic 的 libc)
/apex/com.android.runtime/lib64/bionic/libdl.so  (Bionic 的 dynamic linker)
```

**链接的处理过程:**

1. **Fork:** 当 `my_app` 进程被 fork 时，内核会创建一个新的进程，父进程的数据和状态会被复制到子进程。此时会触发 `PROC_EVENT_FORK` 事件，其中包含父进程和子进程的 PID 和 TGID。

   **假设输入 (内核):**  用户发起一个 fork 系统调用。
   **假设输出 (内核发送的 proc_event):**
   ```
   what = PROC_EVENT_FORK
   cpu = ...
   timestamp_ns = ...
   event_data.fork.parent_pid = <父进程 PID>
   event_data.fork.parent_tgid = <父进程 TGID>
   event_data.fork.child_pid = <子进程 PID>
   event_data.fork.child_tgid = <子进程 TGID>
   ```

2. **Exec:**  子进程 (或父进程) 调用 `execve` 系统调用来执行 `my_app` 的可执行文件。

3. **Dynamic Linker 启动:** 内核会加载 `my_app` 的可执行文件，并根据其 ELF 头部的指示，启动 dynamic linker (`/apex/com.android.runtime/lib64/bionic/libdl.so`)。

4. **加载共享库:** dynamic linker 解析 `my_app` 的 ELF 文件，找出它依赖的共享库 (`liba.so`, `libb.so` 等)。然后，它会加载这些共享库到进程的内存空间。

5. **符号解析和重定位:** dynamic linker 解析共享库的符号表，并将 `my_app` 中对共享库函数的调用重定向到共享库的实际地址。

6. **执行 `main` 函数:**  链接完成后，dynamic linker 将控制权转移到 `my_app` 的 `main` 函数。

7. **触发 `PROC_EVENT_EXEC`:**  当进程成功执行新的程序时，内核会触发 `PROC_EVENT_EXEC` 事件。

   **假设输入 (内核):**  进程成功执行 `execve` 系统调用。
   **假设输出 (内核发送的 proc_event):**
   ```
   what = PROC_EVENT_EXEC
   cpu = ...
   timestamp_ns = ...
   event_data.exec.process_pid = <进程 PID>
   event_data.exec.process_tgid = <进程 TGID>
   ```

**逻辑推理的假设输入与输出:**

假设一个监控程序监听了 `PROC_EVENT_FORK` 和 `PROC_EVENT_EXIT` 事件。

**场景 1: 进程 fork 并成功退出**

* **假设输入 (操作系统):**  一个进程 (PID 1000) fork 了一个新进程 (PID 1001)，然后 PID 1001 正常退出，退出码为 0。
* **输出 (监控程序接收到的 proc_event):**
    1. `proc_event` (类型: `PROC_EVENT_FORK`):
       ```
       what = PROC_EVENT_FORK
       event_data.fork.parent_pid = 1000
       event_data.fork.child_pid = 1001
       ```
    2. `proc_event` (类型: `PROC_EVENT_EXIT`):
       ```
       what = PROC_EVENT_EXIT
       event_data.exit.process_pid = 1001
       event_data.exit.exit_code = 0
       ```

**场景 2: 进程崩溃 (非零退出码)**

* **假设输入 (操作系统):** 一个进程 (PID 2000) 崩溃退出，退出信号为 SIGSEGV (段错误)，退出码通常会反映信号。
* **输出 (监控程序接收到的 proc_event):**
    1. 如果在 fork 之后崩溃，可能会有 `PROC_EVENT_FORK` 事件。
    2. `proc_event` (类型: `PROC_EVENT_EXIT`):
       ```
       what = PROC_EVENT_EXIT
       event_data.exit.process_pid = 2000
       event_data.exit.exit_signal = <表示 SIGSEGV 的值>
       event_data.exit.exit_code = <通常是根据信号计算出的退出码>
       ```

**用户或编程常见的使用错误:**

1. **未正确设置监听的事件类型:** 如果 `proc_input.event_type` 设置不正确，程序可能收不到期望的事件通知。例如，只想监听 `PROC_EVENT_EXIT`，但设置了 `PROC_EVENT_ALL`，会导致接收到大量不必要的事件。

2. **未正确处理 `proc_event` 结构体的 `union`:**  `event_data` 是一个 `union`，需要根据 `proc_event.what` 的值来确定使用哪个成员。如果访问了错误的成员，会导致数据解析错误。

   ```c
   struct proc_event event;
   // ... 接收到事件 ...
   if (event.what == PROC_EVENT_FORK) {
       printf("Forked: parent=%d, child=%d\n", event.event_data.fork.parent_pid, event.event_data.fork.child_pid);
   } else if (event.what == PROC_EVENT_EXIT) {
       printf("Exited: pid=%d, code=%d\n", event.event_data.exit.process_pid, event.event_data.exit.exit_code);
   } else {
       // 错误：尝试访问 fork 成员，但事件不是 fork
       // printf("Parent PID: %d\n", event.event_data.fork.parent_pid); // 可能会崩溃或产生垃圾数据
   }
   ```

3. **忘记处理 Netlink Connector 的连接和消息接收:** 用户需要编写代码来创建 Netlink socket，绑定地址，并循环接收来自内核的消息。如果这些步骤处理不当，可能无法接收到任何事件。

4. **资源泄漏:** 在不再需要监听事件时，需要正确地关闭 Netlink socket，否则可能导致资源泄漏。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java 层):**  Android Framework 中的某些系统服务（例如 ActivityManagerService, ProcessStatsService）需要监控进程活动。这些服务通常通过 JNI (Java Native Interface) 调用到 Native 层。

2. **Native 层 (C/C++):** 在 Native 层，可能会有 C/C++ 代码使用系统调用与内核的 Netlink Connector 进行交互。

3. **Bionic Libc:**  Bionic libc 提供了与内核交互的基础设施。虽然这个头文件本身不是 libc 函数，但 libc 中可能会有辅助函数来简化 Netlink Connector 的使用。

4. **系统调用:**  最终，用户空间的程序需要使用诸如 `socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)`, `bind`, `sendto`, `recvfrom` 等系统调用来与内核通信。

**Frida Hook 示例调试步骤:**

可以使用 Frida Hook 来拦截和查看传递的 `proc_event` 结构体。以下是一个示例，演示如何 hook `recvfrom` 系统调用，以便在接收到进程事件时打印相关信息：

```python
import frida
import struct

# 定义 proc_event 结构体的格式 (根据头文件)
proc_event_format = "<I IQ I"  # what, cpu, timestamp_ns, union tag (隐式)

# 根据不同的事件类型定义 union 内部的结构体格式
fork_event_format = "<IIII"
exec_event_format = "<II"
exit_event_format = "<IIIIII"
comm_event_format = "<II16s"  # 16s 表示 16 字节的字符数组

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        print(f"Received message: {payload}")
        # 解析 proc_event 头部
        header_size = struct.calcsize(proc_event_format)
        if len(data) >= header_size:
            header_data = data[:header_size]
            what, cpu, timestamp_ns, _ = struct.unpack(proc_event_format, header_data)
            print(f"  Event Type: {what:#x}, CPU: {cpu}, Timestamp: {timestamp_ns}")

            # 根据事件类型解析 union 数据
            if what == 0x00000001:  # PROC_EVENT_FORK
                fork_data = struct.unpack(fork_event_format, data[header_size:header_size + struct.calcsize(fork_event_format)])
                print(f"    Fork: parent_pid={fork_data[0]}, parent_tgid={fork_data[1]}, child_pid={fork_data[2]}, child_tgid={fork_data[3]}")
            elif what == 0x00000002:  # PROC_EVENT_EXEC
                exec_data = struct.unpack(exec_event_format, data[header_size:header_size + struct.calcsize(exec_event_format)])
                print(f"    Exec: process_pid={exec_data[0]}, process_tgid={exec_data[1]}")
            elif what == 0x80000000:  # PROC_EVENT_EXIT
                exit_data = struct.unpack(exit_event_format, data[header_size:header_size + struct.calcsize(exit_event_format)])
                print(f"    Exit: process_pid={exit_data[0]}, process_tgid={exit_data[1]}, exit_code={exit_data[2]}, exit_signal={exit_data[3]}, parent_pid={exit_data[4]}, parent_tgid={exit_data[5]}")
            elif what == 0x00000200: # PROC_EVENT_COMM
                comm_data = struct.unpack(comm_event_format, data[header_size:header_size + struct.calcsize(comm_event_format)])
                comm_str = comm_data[2].decode('utf-8').rstrip('\x00')
                print(f"    Comm: process_pid={comm_data[0]}, process_tgid={comm_data[1]}, comm='{comm_str}'")

def main():
    device = frida.get_usb_device()
    # 替换为目标进程的名称或 PID
    pid = device.spawn(["com.example.myapp"])
    session = device.attach(pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName(null, "recvfrom"), {
            onEnter: function(args) {
                // args[0]: sockfd
                // args[1]: buf
                // args[2]: len
                // args[3]: flags
                // args[4]: src_addr
                // args[5]: addrlen

                // 检查是否是 Netlink socket (假设我们知道目标进程如何创建的)
                // 可以根据 sockfd 的值或者其他特征来判断

                this.buf = args[1];
                this.len = ptr(args[2]).readUInt();
            },
            onLeave: function(retval) {
                if (retval.toInt() > 0) {
                    var data = this.buf.readByteArray(retval.toInt());
                    send({ type: 'send', payload: 'Data received on recvfrom' }, data);
                }
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    input() # 让脚本保持运行

if __name__ == '__main__':
    main()
```

**使用步骤:**

1. **安装 Frida 和 Python 绑定:** 确保你的系统上安装了 Frida 和 Python 的 Frida 绑定。
2. **找到目标进程:** 确定你想要监控的 Android 应用程序或系统服务的进程名称或 PID。
3. **运行 Frida 脚本:** 将上面的 Python 代码保存为一个文件 (例如 `hook_proc_event.py`)，并将 `device.spawn(["com.example.myapp"])` 中的 `com.example.myapp` 替换为你要监控的应用程序的包名，或者使用 `device.attach(PID)` 并替换为实际的 PID。
4. **运行设备上的应用:** 启动或操作你想要监控的 Android 应用或系统功能，以触发进程事件。
5. **查看输出:** Frida 脚本会拦截 `recvfrom` 调用，并在接收到数据时打印 `proc_event` 结构体的相关信息。你需要根据 `what` 字段的值来解析 `union` 中的数据。

**注意:**

* 上面的 Frida 脚本是一个简化的示例，可能需要根据目标进程的具体实现进行调整，例如更精确地判断是否是 Netlink Connector 的 socket。
* 需要 root 权限才能在 Android 设备上运行 Frida 并 hook 系统调用。
* 解析 `union` 时需要非常小心，确保根据 `proc_event.what` 的值来访问正确的成员。

通过以上分析和示例，你应该对 `bionic/libc/kernel/uapi/linux/cn_proc.handroid` 这个头文件的功能以及它在 Android 系统中的作用有了更深入的理解。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/cn_proc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPICN_PROC_H
#define _UAPICN_PROC_H
#include <linux/types.h>
enum proc_cn_mcast_op {
  PROC_CN_MCAST_LISTEN = 1,
  PROC_CN_MCAST_IGNORE = 2
};
#define PROC_EVENT_ALL (PROC_EVENT_FORK | PROC_EVENT_EXEC | PROC_EVENT_UID | PROC_EVENT_GID | PROC_EVENT_SID | PROC_EVENT_PTRACE | PROC_EVENT_COMM | PROC_EVENT_NONZERO_EXIT | PROC_EVENT_COREDUMP | PROC_EVENT_EXIT)
enum proc_cn_event {
  PROC_EVENT_NONE = 0x00000000,
  PROC_EVENT_FORK = 0x00000001,
  PROC_EVENT_EXEC = 0x00000002,
  PROC_EVENT_UID = 0x00000004,
  PROC_EVENT_GID = 0x00000040,
  PROC_EVENT_SID = 0x00000080,
  PROC_EVENT_PTRACE = 0x00000100,
  PROC_EVENT_COMM = 0x00000200,
  PROC_EVENT_NONZERO_EXIT = 0x20000000,
  PROC_EVENT_COREDUMP = 0x40000000,
  PROC_EVENT_EXIT = 0x80000000
};
struct proc_input {
  enum proc_cn_mcast_op mcast_op;
  enum proc_cn_event event_type;
};
struct proc_event {
  enum proc_cn_event what;
  __u32 cpu;
  __u64 __attribute__((aligned(8))) timestamp_ns;
  union {
    struct {
      __u32 err;
    } ack;
    struct fork_proc_event {
      __kernel_pid_t parent_pid;
      __kernel_pid_t parent_tgid;
      __kernel_pid_t child_pid;
      __kernel_pid_t child_tgid;
    } fork;
    struct exec_proc_event {
      __kernel_pid_t process_pid;
      __kernel_pid_t process_tgid;
    } exec;
    struct id_proc_event {
      __kernel_pid_t process_pid;
      __kernel_pid_t process_tgid;
      union {
        __u32 ruid;
        __u32 rgid;
      } r;
      union {
        __u32 euid;
        __u32 egid;
      } e;
    } id;
    struct sid_proc_event {
      __kernel_pid_t process_pid;
      __kernel_pid_t process_tgid;
    } sid;
    struct ptrace_proc_event {
      __kernel_pid_t process_pid;
      __kernel_pid_t process_tgid;
      __kernel_pid_t tracer_pid;
      __kernel_pid_t tracer_tgid;
    } ptrace;
    struct comm_proc_event {
      __kernel_pid_t process_pid;
      __kernel_pid_t process_tgid;
      char comm[16];
    } comm;
    struct coredump_proc_event {
      __kernel_pid_t process_pid;
      __kernel_pid_t process_tgid;
      __kernel_pid_t parent_pid;
      __kernel_pid_t parent_tgid;
    } coredump;
    struct exit_proc_event {
      __kernel_pid_t process_pid;
      __kernel_pid_t process_tgid;
      __u32 exit_code, exit_signal;
      __kernel_pid_t parent_pid;
      __kernel_pid_t parent_tgid;
    } exit;
  } event_data;
};
#endif
```