Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Request:**

The fundamental request is to analyze the provided C header file (`perf_event.h`) from the Android bionic library and explain its purpose, relation to Android, implementation details (where applicable), dynamic linking aspects, common usage errors, and how it's accessed by higher-level Android components.

**2. Identifying Key Areas:**

Based on the request, I can identify several key areas that need to be addressed:

* **File Purpose and Functionality:**  What does this header file define? What are its core concepts?
* **Android Relevance:** How does `perf_event.h` relate to Android's functionality?
* **Implementation Details of libc Functions:** This is a bit of a trick question. Header files don't *implement* functions; they *declare* them. So, the focus should shift to how the *concepts* defined in the header are implemented in the kernel.
* **Dynamic Linking:**  Does this header file directly involve dynamic linking? If not, what are the connections to dynamic linking in the broader context of using perf_event?
* **Logic and Examples:** Provide concrete examples to illustrate the concepts.
* **Common Errors:** What mistakes might developers make when using perf_event?
* **Android Framework/NDK Interaction:** How does the Android ecosystem utilize these definitions?
* **Frida Hooking:** Demonstrate how to use Frida to observe these components in action.

**3. Initial Analysis of the Header File:**

My first pass at the header file reveals the following:

* **Perf Events:** The core subject is "perf_event," suggesting it's about performance monitoring and profiling.
* **Enums and Defines:** The file is full of enumerations (`enum`) and preprocessor definitions (`#define`). This indicates it's defining constants and types related to perf events.
* **Structure Definitions:** Structures like `perf_event_attr`, `perf_event_header`, etc., define the data structures used to configure and report performance events.
* **IOCTLs:**  The `#define PERF_EVENT_IOC_*` definitions clearly indicate interaction with a device driver using ioctl calls. This is a strong indicator of kernel interaction.
* **Sample Formats and Types:**  There are definitions related to how perf event data is sampled and the types of events that can be monitored (hardware, software, cache, etc.).

**4. Deep Dive into Each Key Area:**

* **Functionality:** I'll describe the purpose of `perf_event.h` as providing the user-space interface to the Linux perf subsystem. I'll list the main categories of definitions (event types, sample formats, attributes, ioctls).

* **Android Relevance:** I need to connect `perf_event` to Android's performance monitoring capabilities. Examples include CPU profiling, memory access analysis, and power optimization. I can mention tools like `simpleperf` and system tracing.

* **libc Function Implementation:** Realizing the header doesn't contain function implementations, I'll reframe this to discuss how the *kernel* implements the performance monitoring functionality that these definitions represent. I'll explain that the `perf_event_open` syscall (though not directly in this header) is the entry point and how the kernel uses the provided attributes to set up monitoring.

* **Dynamic Linking:** This header doesn't directly involve dynamic linking in the way a shared library would. However, the *use* of perf_event often involves tools that are dynamically linked. I'll explain that tools like `simpleperf` are dynamically linked and provide a basic `simpleperf` SO layout example and how the linker resolves dependencies. The link process will involve finding symbols in the dependency chain.

* **Logic and Examples:** I'll provide a simple example of configuring a `perf_event_attr` structure to count CPU cycles. This demonstrates how the defined constants are used. I'll also provide a hypothetical scenario of using ioctl to enable and disable the counter.

* **Common Errors:** I'll list common mistakes like incorrect attribute configuration, failure to handle errors from `ioctl`, and misinterpreting the event data.

* **Android Framework/NDK Interaction:** I'll explain the layers: Android framework (using system services), NDK (using direct syscalls or wrappers like `libbase`), and finally, the kernel interface defined in the header. I'll provide examples of how `simpleperf` (NDK) and potentially framework components (less directly visible) utilize perf_event.

* **Frida Hooking:** I'll demonstrate how to hook the `syscall` function (since `perf_event_open` is a syscall) or potentially a higher-level function in `libbase` or `simpleperf` to observe the interaction with the perf subsystem. The example will show how to intercept the call and log the arguments, including the `perf_event_attr` structure.

**5. Structuring the Response:**

I'll organize the response logically, addressing each point in the request. I'll use clear headings and bullet points to improve readability. I'll ensure the language is accessible and avoid overly technical jargon where possible.

**6. Iteration and Refinement:**

During the process, I might realize that certain aspects need further clarification or that my initial understanding was slightly off. For example, I might initially focus too much on libc *functions* and then correct myself to focus on the kernel implementation of the *concepts*. I'll review and refine my answer to ensure accuracy and completeness.

**Self-Correction Example:**

Initially, I might have thought about detailing specific libc wrappers for `ioctl`. However, on closer inspection of the header, I see it primarily defines constants and structures for use with the `perf_event_open` syscall (which isn't even directly in this header). Therefore, I'd adjust my focus to how those constants are used in the syscall context and how higher-level libraries might abstract the syscall. This prevents me from going down a rabbit hole of non-existent libc functions related *specifically* to this header.

By following this structured approach, breaking down the problem into manageable parts, and constantly refining my understanding, I can construct a comprehensive and accurate answer to the complex request.
这是一个定义 Linux `perf_event` 子系统的用户空间 API 的头文件。它位于 Android Bionic 库中，意味着 Android 系统使用 Linux 的性能监控功能。

**功能列举：**

该头文件定义了用于配置和控制 Linux `perf_event` 子系统的各种常量、枚举和结构体。`perf_event` 是一个强大的内核工具，允许用户空间程序对各种系统和硬件事件进行性能监控和分析。其主要功能包括：

1. **定义事件类型:**  定义了可以监控的各种事件类型，例如硬件事件 (CPU 周期、指令数、缓存访问等)、软件事件 (上下文切换、缺页中断等)、tracepoint 事件、硬件缓存事件、原始事件和断点事件。
2. **定义事件 ID:**  为每种事件类型定义了具体的 ID，例如 `PERF_COUNT_HW_CPU_CYCLES` 代表 CPU 周期计数。
3. **定义采样格式:**  规定了当事件发生时，可以收集哪些信息，例如指令指针 (IP)、线程 ID (TID)、时间戳、内存地址、寄存器值、调用栈等。
4. **定义分支采样类型:**  允许监控程序指定要记录哪些类型的分支指令，例如用户空间/内核空间的分支、调用/返回指令、条件/无条件分支等。
5. **定义事务类型:**  用于监控事务相关的事件，例如事务的开始、结束、冲突等。
6. **定义读取格式:**  指定了从 perf 文件描述符读取数据时的格式，可以包含事件计数、使能时间和运行时间、事件 ID 等信息。
7. **定义事件属性结构体 `perf_event_attr`:**  这是配置性能监控事件的核心结构体，包含了事件类型、大小、配置、采样频率/周期、采样类型、读取格式、各种标志位 (是否禁用、是否继承、是否独占等) 以及与断点、kprobe/uprobe 相关的配置。
8. **定义 IO 控制命令:**  定义了与 perf 文件描述符进行交互的各种 IO 控制命令，例如使能/禁用事件、重置计数、设置输出目标、设置过滤器、获取事件 ID、设置 BPF 程序等。
9. **定义内存映射页结构体 `perf_event_mmap_page`:**  定义了用于用户空间和内核空间共享的内存映射页的结构，包含了性能计数器、时间信息、数据缓冲区头尾指针等。
10. **定义事件记录头结构体 `perf_event_header`:**  定义了从 perf 文件描述符读取到的每个事件记录的头部信息，包含事件类型、其他信息和大小。
11. **定义各种事件记录类型:**  定义了从 perf 文件描述符读取到的各种事件记录类型，例如 MMAP (内存映射)、LOST (丢失事件)、COMM (进程名)、EXIT (进程退出)、FORK (进程创建)、READ (读取计数器值)、SAMPLE (采样事件) 等。
12. **定义辅助缓冲区相关的标志和结构体。**

**与 Android 功能的关系及举例说明：**

`perf_event` 是 Android 性能分析和优化的重要基础。Android 系统和开发者可以使用它来：

* **CPU 性能分析:**  监控 CPU 周期、指令数、分支预测等硬件事件，帮助定位 CPU 瓶颈。例如，可以使用 `simpleperf` 工具 (一个 Android 上的性能分析工具，基于 `perf_event`) 来分析应用的 CPU 使用情况，找出占用 CPU 时间最多的函数。
* **内存访问分析:**  监控缓存命中率、TLB 命中率等硬件事件，以及缺页中断等软件事件，帮助优化内存访问模式。例如，可以使用 `simpleperf` 分析应用是否存在过多的缓存未命中，从而调整数据结构或算法。
* **电源优化:**  虽然 `perf_event` 本身不直接控制电源，但可以通过监控某些硬件事件来间接了解功耗情况，例如 CPU 的 idle 状态。
* **系统调用跟踪:**  通过 tracepoint 事件监控系统调用，了解应用与内核的交互情况。
* **热点代码识别:**  通过采样事件，可以识别出程序中执行频率最高的代码片段，从而进行针对性优化。

**举例说明：**

假设你想监控一个 Android 应用的 CPU 周期数。你可以使用 `simpleperf` 工具：

```bash
adb shell simpleperf stat -e cpu-cycles -p <进程ID>
```

这个命令内部会使用 `perf_event_open` 系统调用，并根据 `-e cpu-cycles` 参数配置 `perf_event_attr` 结构体，将 `type` 设置为 `PERF_TYPE_HARDWARE`，`config` 设置为 `PERF_COUNT_HW_CPU_CYCLES`。内核会创建一个 perf 事件，当指定进程的 CPU 周期发生时，会记录相关信息。`simpleperf` 会读取这些信息并展示出来。

**libc 函数的功能实现：**

这个头文件本身并不包含 libc 函数的实现，它只是定义了与内核 `perf_event` 子系统交互所需的数据结构和常量。用户空间的程序需要通过系统调用 (例如 `perf_event_open`) 与内核交互来创建和控制 perf 事件。

Bionic libc 中可能存在一些辅助函数或封装，用于更方便地使用 `perf_event`，但这取决于具体的 Android 版本和 Bionic 的实现。通常，开发者会直接使用底层的系统调用或者使用如 `libbase` 这样的库提供的封装。

**涉及 dynamic linker 的功能：**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker 的主要职责是加载共享库，并解析和重定位符号。

然而，当使用基于 `perf_event` 的性能分析工具 (例如 `simpleperf`) 时，dynamic linker 会参与到工具本身的加载和运行过程中。

**so 布局样本 (以 `simpleperf` 为例)：**

```
/system/bin/simpleperf  (主执行文件)
/apex/com.android.runtime/bin/linker64 (或 linker)
/apex/com.android.runtime/lib64/bionic/libc.so
/apex/com.android.runtime/lib64/bionic/libm.so
/apex/com.android.runtime/lib64/bionic/libdl.so
/system/lib64/libbase.so          (simpleperf 可能依赖)
/system/lib64/libcutils.so
... (其他依赖的共享库)
```

**链接的处理过程：**

1. 当 `simpleperf` 被执行时，内核会加载其代码段和数据段。
2. Dynamic linker (`linker64` 或 `linker`) 被启动。
3. Dynamic linker 解析 `simpleperf` 的 ELF 头，查找其依赖的共享库列表。
4. Dynamic linker 按照依赖关系依次加载共享库 (例如 `libc.so`, `libbase.so` 等)。
5. 对于每个加载的共享库，Dynamic linker 会解析其符号表和重定位表。
6. Dynamic linker 会将 `simpleperf` 中引用的外部符号 (例如 `open`, `ioctl`, `perf_event_open` 等) 与已加载的共享库中的符号定义进行匹配和绑定。这可能涉及到查找符号表，并更新 `simpleperf` 中的相应地址。
7. 重定位过程会修改 `simpleperf` 和其依赖的共享库中的指令和数据，使其能够正确访问外部函数和数据。

**逻辑推理、假设输入与输出 (以配置 `perf_event_attr` 为例)：**

假设我们要配置一个 perf 事件来统计 CPU 周期，并且希望每发生 10000 个周期就产生一个采样事件。

**假设输入:**

* `type` = `PERF_TYPE_HARDWARE`
* `config` = `PERF_COUNT_HW_CPU_CYCLES`
* `sample_period` = 10000

**逻辑推理:**

根据这些输入，内核在创建 perf 事件时，会配置硬件计数器来跟踪 CPU 周期。当计数器达到 10000 时，内核会生成一个采样事件，并将相关信息 (根据 `sample_type` 的设置) 写入到 perf 缓冲区中。

**假设输出 (perf 缓冲区中的一个采样事件，部分信息):**

```
struct perf_event_header {
  type = PERF_RECORD_SAMPLE;
  ...
};
// 如果 PERF_SAMPLE_IP 被设置
__u64 ip;  // 发生事件时的指令指针
// 如果 PERF_SAMPLE_TID 被设置
__u32 pid, tid; // 进程 ID 和线程 ID
// 如果 PERF_SAMPLE_TIME 被设置
__u64 time; // 时间戳
...
```

**用户或编程常见的使用错误：**

1. **权限不足:**  访问 perf_event 可能需要 root 权限或特定的 capabilities。普通应用可能无法直接创建某些类型的 perf 事件。
2. **错误的事件类型或 ID:**  配置了不存在或不支持的事件类型或 ID，导致 `perf_event_open` 调用失败。
3. **错误的 `sample_type` 配置:**  没有根据需要设置 `sample_type`，导致采样事件缺少必要的信息。
4. **忘记 mmap perf 缓冲区:**  创建 perf 事件后，需要使用 `mmap` 将内核缓冲区映射到用户空间，才能读取事件数据。
5. **没有正确处理 `ioctl` 返回值:**  与 perf 文件描述符进行交互的 `ioctl` 调用可能会失败，需要检查返回值并处理错误。
6. **缓冲区溢出:**  如果采样频率过高或缓冲区大小不足，可能导致事件数据丢失。
7. **多线程/多进程竞争:**  在多线程或多进程环境下使用 perf_event 时，需要注意同步和避免竞争条件。
8. **不理解事件语义:**  对不同事件的含义理解不透彻，导致分析结果错误。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤：**

**Android Framework:**

1. **Framework 组件发起性能监控请求:**  例如，System Server 中的某个服务可能需要监控 CPU 使用情况。
2. **调用底层服务:**  Framework 组件可能会通过 Binder IPC 调用更底层的系统服务 (例如 `perfetto` 服务或直接与内核交互的 HAL)。
3. **系统服务或 HAL 调用 NDK 库:**  这些服务或 HAL 可能会使用 NDK 库 (例如 `libbase`, `libcutils`) 中提供的封装或直接使用系统调用。
4. **NDK 库调用 `perf_event_open` 系统调用:**  NDK 库会构造 `perf_event_attr` 结构体，并调用 `syscall(__NR_perf_event_open, ...)`。

**NDK:**

1. **NDK 应用直接使用 `perf_event_open`:**  开发者可以在 NDK 应用中直接包含 `<linux/perf_event.h>` 头文件，并调用 `syscall(__NR_perf_event_open, ...)` 或使用 `libbase` 提供的封装。

**Frida Hook 示例：**

假设我们想 hook `perf_event_open` 系统调用，查看传递的 `perf_event_attr` 参数。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(sys.argv[0]))
        sys.exit(1)

    target = sys.argv[1]
    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        session = frida.spawn(target)
        session.resume()

    script_code = """
    // 获取 perf_event_open 系统调用的编号
    var perf_event_open_nr = -1;
    if (Process.platform === 'linux') {
        var syscallPtr = Module.findExportByName(null, "syscall");
        if (syscallPtr) {
            var syscall = new NativeFunction(syscallPtr, 'int', ['int64', 'uint64', 'uint64', 'uint64', 'uint64', 'uint64']);
            // 尝试调用不同的 syscall 号码来查找 perf_event_open
            for (var i = 0; i < 1024; i++) {
                try {
                    // 传递无效的参数，我们只关心 syscall 的编号
                    syscall(i, 0, 0, 0, 0, 0);
                } catch (e) {
                    if (e.message.includes('function not implemented') || e.message.includes('Bad system call')) {
                        // 假设下一个未实现的系统调用就是 perf_event_open (不一定准确，更可靠的方法是查表)
                        perf_event_open_nr = i;
                        break;
                    }
                }
            }
            console.log("猜测的 perf_event_open syscall number: " + perf_event_open_nr);
        }
    }

    if (perf_event_open_nr !== -1) {
        Interceptor.attach(Module.findExportByName(null, "syscall"), {
            onEnter: function (args) {
                var syscall_number = args[0].toInt32();
                if (syscall_number === perf_event_open_nr) {
                    this.type = Memory.readU32(ptr(args[1]));
                    this.size = Memory.readU32(ptr(args[1]).add(4));
                    this.config = Memory.readU64(ptr(args[1]).add(8));
                    console.log("[-] syscall(__NR_perf_event_open)");
                    console.log("  [-] type:", this.type);
                    console.log("  [-] size:", this.size);
                    console.log("  [-] config:", this.config.toString(16));
                    // 可以根据需要读取更多的 perf_event_attr 字段
                }
            }
        });
    } else {
        console.error("无法确定 perf_event_open 的 syscall number，hook 失败。");
    }
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Frida script loaded. Attach to the process and trigger perf_event_open calls.")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法：**

1. 将上述 Python 代码保存为 `hook_perf_event.py`。
2. 运行 `python hook_perf_event.py <目标进程名或 PID>`。
3. 启动或操作目标 Android 应用，使其调用 `perf_event_open`。
4. Frida 会拦截 `syscall` 函数的调用，并打印出 `perf_event_open` 系统调用的相关信息，包括 `perf_event_attr` 结构体中的 `type`, `size`, `config` 字段。

**注意：**

* 上述 Frida 脚本中获取 `perf_event_open` 系统调用号的方式是通过尝试调用不同的 syscall 并捕获异常来猜测的，这并不总是可靠的。更可靠的方法是查询目标设备的系统调用表。
* Hook 系统调用需要 root 权限或特定的 capabilities。
* 可以根据需要扩展 Frida 脚本来读取 `perf_event_attr` 结构体中的更多字段。

这个头文件是 Android 系统进行性能监控和分析的关键组成部分，理解其定义对于进行深入的性能优化至关重要。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/perf_event.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_PERF_EVENT_H
#define _UAPI_LINUX_PERF_EVENT_H
#include <linux/types.h>
#include <linux/ioctl.h>
#include <asm/byteorder.h>
enum perf_type_id {
  PERF_TYPE_HARDWARE = 0,
  PERF_TYPE_SOFTWARE = 1,
  PERF_TYPE_TRACEPOINT = 2,
  PERF_TYPE_HW_CACHE = 3,
  PERF_TYPE_RAW = 4,
  PERF_TYPE_BREAKPOINT = 5,
  PERF_TYPE_MAX,
};
#define PERF_PMU_TYPE_SHIFT 32
#define PERF_HW_EVENT_MASK 0xffffffff
enum perf_hw_id {
  PERF_COUNT_HW_CPU_CYCLES = 0,
  PERF_COUNT_HW_INSTRUCTIONS = 1,
  PERF_COUNT_HW_CACHE_REFERENCES = 2,
  PERF_COUNT_HW_CACHE_MISSES = 3,
  PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4,
  PERF_COUNT_HW_BRANCH_MISSES = 5,
  PERF_COUNT_HW_BUS_CYCLES = 6,
  PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 7,
  PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 8,
  PERF_COUNT_HW_REF_CPU_CYCLES = 9,
  PERF_COUNT_HW_MAX,
};
enum perf_hw_cache_id {
  PERF_COUNT_HW_CACHE_L1D = 0,
  PERF_COUNT_HW_CACHE_L1I = 1,
  PERF_COUNT_HW_CACHE_LL = 2,
  PERF_COUNT_HW_CACHE_DTLB = 3,
  PERF_COUNT_HW_CACHE_ITLB = 4,
  PERF_COUNT_HW_CACHE_BPU = 5,
  PERF_COUNT_HW_CACHE_NODE = 6,
  PERF_COUNT_HW_CACHE_MAX,
};
enum perf_hw_cache_op_id {
  PERF_COUNT_HW_CACHE_OP_READ = 0,
  PERF_COUNT_HW_CACHE_OP_WRITE = 1,
  PERF_COUNT_HW_CACHE_OP_PREFETCH = 2,
  PERF_COUNT_HW_CACHE_OP_MAX,
};
enum perf_hw_cache_op_result_id {
  PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0,
  PERF_COUNT_HW_CACHE_RESULT_MISS = 1,
  PERF_COUNT_HW_CACHE_RESULT_MAX,
};
enum perf_sw_ids {
  PERF_COUNT_SW_CPU_CLOCK = 0,
  PERF_COUNT_SW_TASK_CLOCK = 1,
  PERF_COUNT_SW_PAGE_FAULTS = 2,
  PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
  PERF_COUNT_SW_CPU_MIGRATIONS = 4,
  PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
  PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
  PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
  PERF_COUNT_SW_EMULATION_FAULTS = 8,
  PERF_COUNT_SW_DUMMY = 9,
  PERF_COUNT_SW_BPF_OUTPUT = 10,
  PERF_COUNT_SW_CGROUP_SWITCHES = 11,
  PERF_COUNT_SW_MAX,
};
enum perf_event_sample_format {
  PERF_SAMPLE_IP = 1U << 0,
  PERF_SAMPLE_TID = 1U << 1,
  PERF_SAMPLE_TIME = 1U << 2,
  PERF_SAMPLE_ADDR = 1U << 3,
  PERF_SAMPLE_READ = 1U << 4,
  PERF_SAMPLE_CALLCHAIN = 1U << 5,
  PERF_SAMPLE_ID = 1U << 6,
  PERF_SAMPLE_CPU = 1U << 7,
  PERF_SAMPLE_PERIOD = 1U << 8,
  PERF_SAMPLE_STREAM_ID = 1U << 9,
  PERF_SAMPLE_RAW = 1U << 10,
  PERF_SAMPLE_BRANCH_STACK = 1U << 11,
  PERF_SAMPLE_REGS_USER = 1U << 12,
  PERF_SAMPLE_STACK_USER = 1U << 13,
  PERF_SAMPLE_WEIGHT = 1U << 14,
  PERF_SAMPLE_DATA_SRC = 1U << 15,
  PERF_SAMPLE_IDENTIFIER = 1U << 16,
  PERF_SAMPLE_TRANSACTION = 1U << 17,
  PERF_SAMPLE_REGS_INTR = 1U << 18,
  PERF_SAMPLE_PHYS_ADDR = 1U << 19,
  PERF_SAMPLE_AUX = 1U << 20,
  PERF_SAMPLE_CGROUP = 1U << 21,
  PERF_SAMPLE_DATA_PAGE_SIZE = 1U << 22,
  PERF_SAMPLE_CODE_PAGE_SIZE = 1U << 23,
  PERF_SAMPLE_WEIGHT_STRUCT = 1U << 24,
  PERF_SAMPLE_MAX = 1U << 25,
};
#define PERF_SAMPLE_WEIGHT_TYPE (PERF_SAMPLE_WEIGHT | PERF_SAMPLE_WEIGHT_STRUCT)
enum perf_branch_sample_type_shift {
  PERF_SAMPLE_BRANCH_USER_SHIFT = 0,
  PERF_SAMPLE_BRANCH_KERNEL_SHIFT = 1,
  PERF_SAMPLE_BRANCH_HV_SHIFT = 2,
  PERF_SAMPLE_BRANCH_ANY_SHIFT = 3,
  PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT = 4,
  PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT = 5,
  PERF_SAMPLE_BRANCH_IND_CALL_SHIFT = 6,
  PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT = 7,
  PERF_SAMPLE_BRANCH_IN_TX_SHIFT = 8,
  PERF_SAMPLE_BRANCH_NO_TX_SHIFT = 9,
  PERF_SAMPLE_BRANCH_COND_SHIFT = 10,
  PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT = 11,
  PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT = 12,
  PERF_SAMPLE_BRANCH_CALL_SHIFT = 13,
  PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT = 14,
  PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT = 15,
  PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT = 16,
  PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT = 17,
  PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT = 18,
  PERF_SAMPLE_BRANCH_COUNTERS_SHIFT = 19,
  PERF_SAMPLE_BRANCH_MAX_SHIFT
};
enum perf_branch_sample_type {
  PERF_SAMPLE_BRANCH_USER = 1U << PERF_SAMPLE_BRANCH_USER_SHIFT,
  PERF_SAMPLE_BRANCH_KERNEL = 1U << PERF_SAMPLE_BRANCH_KERNEL_SHIFT,
  PERF_SAMPLE_BRANCH_HV = 1U << PERF_SAMPLE_BRANCH_HV_SHIFT,
  PERF_SAMPLE_BRANCH_ANY = 1U << PERF_SAMPLE_BRANCH_ANY_SHIFT,
  PERF_SAMPLE_BRANCH_ANY_CALL = 1U << PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT,
  PERF_SAMPLE_BRANCH_ANY_RETURN = 1U << PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT,
  PERF_SAMPLE_BRANCH_IND_CALL = 1U << PERF_SAMPLE_BRANCH_IND_CALL_SHIFT,
  PERF_SAMPLE_BRANCH_ABORT_TX = 1U << PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT,
  PERF_SAMPLE_BRANCH_IN_TX = 1U << PERF_SAMPLE_BRANCH_IN_TX_SHIFT,
  PERF_SAMPLE_BRANCH_NO_TX = 1U << PERF_SAMPLE_BRANCH_NO_TX_SHIFT,
  PERF_SAMPLE_BRANCH_COND = 1U << PERF_SAMPLE_BRANCH_COND_SHIFT,
  PERF_SAMPLE_BRANCH_CALL_STACK = 1U << PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT,
  PERF_SAMPLE_BRANCH_IND_JUMP = 1U << PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT,
  PERF_SAMPLE_BRANCH_CALL = 1U << PERF_SAMPLE_BRANCH_CALL_SHIFT,
  PERF_SAMPLE_BRANCH_NO_FLAGS = 1U << PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT,
  PERF_SAMPLE_BRANCH_NO_CYCLES = 1U << PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT,
  PERF_SAMPLE_BRANCH_TYPE_SAVE = 1U << PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT,
  PERF_SAMPLE_BRANCH_HW_INDEX = 1U << PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT,
  PERF_SAMPLE_BRANCH_PRIV_SAVE = 1U << PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT,
  PERF_SAMPLE_BRANCH_COUNTERS = 1U << PERF_SAMPLE_BRANCH_COUNTERS_SHIFT,
  PERF_SAMPLE_BRANCH_MAX = 1U << PERF_SAMPLE_BRANCH_MAX_SHIFT,
};
enum {
  PERF_BR_UNKNOWN = 0,
  PERF_BR_COND = 1,
  PERF_BR_UNCOND = 2,
  PERF_BR_IND = 3,
  PERF_BR_CALL = 4,
  PERF_BR_IND_CALL = 5,
  PERF_BR_RET = 6,
  PERF_BR_SYSCALL = 7,
  PERF_BR_SYSRET = 8,
  PERF_BR_COND_CALL = 9,
  PERF_BR_COND_RET = 10,
  PERF_BR_ERET = 11,
  PERF_BR_IRQ = 12,
  PERF_BR_SERROR = 13,
  PERF_BR_NO_TX = 14,
  PERF_BR_EXTEND_ABI = 15,
  PERF_BR_MAX,
};
enum {
  PERF_BR_SPEC_NA = 0,
  PERF_BR_SPEC_WRONG_PATH = 1,
  PERF_BR_NON_SPEC_CORRECT_PATH = 2,
  PERF_BR_SPEC_CORRECT_PATH = 3,
  PERF_BR_SPEC_MAX,
};
enum {
  PERF_BR_NEW_FAULT_ALGN = 0,
  PERF_BR_NEW_FAULT_DATA = 1,
  PERF_BR_NEW_FAULT_INST = 2,
  PERF_BR_NEW_ARCH_1 = 3,
  PERF_BR_NEW_ARCH_2 = 4,
  PERF_BR_NEW_ARCH_3 = 5,
  PERF_BR_NEW_ARCH_4 = 6,
  PERF_BR_NEW_ARCH_5 = 7,
  PERF_BR_NEW_MAX,
};
enum {
  PERF_BR_PRIV_UNKNOWN = 0,
  PERF_BR_PRIV_USER = 1,
  PERF_BR_PRIV_KERNEL = 2,
  PERF_BR_PRIV_HV = 3,
};
#define PERF_BR_ARM64_FIQ PERF_BR_NEW_ARCH_1
#define PERF_BR_ARM64_DEBUG_HALT PERF_BR_NEW_ARCH_2
#define PERF_BR_ARM64_DEBUG_EXIT PERF_BR_NEW_ARCH_3
#define PERF_BR_ARM64_DEBUG_INST PERF_BR_NEW_ARCH_4
#define PERF_BR_ARM64_DEBUG_DATA PERF_BR_NEW_ARCH_5
#define PERF_SAMPLE_BRANCH_PLM_ALL (PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_KERNEL | PERF_SAMPLE_BRANCH_HV)
enum perf_sample_regs_abi {
  PERF_SAMPLE_REGS_ABI_NONE = 0,
  PERF_SAMPLE_REGS_ABI_32 = 1,
  PERF_SAMPLE_REGS_ABI_64 = 2,
};
enum {
  PERF_TXN_ELISION = (1 << 0),
  PERF_TXN_TRANSACTION = (1 << 1),
  PERF_TXN_SYNC = (1 << 2),
  PERF_TXN_ASYNC = (1 << 3),
  PERF_TXN_RETRY = (1 << 4),
  PERF_TXN_CONFLICT = (1 << 5),
  PERF_TXN_CAPACITY_WRITE = (1 << 6),
  PERF_TXN_CAPACITY_READ = (1 << 7),
  PERF_TXN_MAX = (1 << 8),
  PERF_TXN_ABORT_MASK = (0xffffffffULL << 32),
  PERF_TXN_ABORT_SHIFT = 32,
};
enum perf_event_read_format {
  PERF_FORMAT_TOTAL_TIME_ENABLED = 1U << 0,
  PERF_FORMAT_TOTAL_TIME_RUNNING = 1U << 1,
  PERF_FORMAT_ID = 1U << 2,
  PERF_FORMAT_GROUP = 1U << 3,
  PERF_FORMAT_LOST = 1U << 4,
  PERF_FORMAT_MAX = 1U << 5,
};
#define PERF_ATTR_SIZE_VER0 64
#define PERF_ATTR_SIZE_VER1 72
#define PERF_ATTR_SIZE_VER2 80
#define PERF_ATTR_SIZE_VER3 96
#define PERF_ATTR_SIZE_VER4 104
#define PERF_ATTR_SIZE_VER5 112
#define PERF_ATTR_SIZE_VER6 120
#define PERF_ATTR_SIZE_VER7 128
#define PERF_ATTR_SIZE_VER8 136
struct perf_event_attr {
  __u32 type;
  __u32 size;
  __u64 config;
  union {
    __u64 sample_period;
    __u64 sample_freq;
  };
  __u64 sample_type;
  __u64 read_format;
  __u64 disabled : 1, inherit : 1, pinned : 1, exclusive : 1, exclude_user : 1, exclude_kernel : 1, exclude_hv : 1, exclude_idle : 1, mmap : 1, comm : 1, freq : 1, inherit_stat : 1, enable_on_exec : 1, task : 1, watermark : 1, precise_ip : 2, mmap_data : 1, sample_id_all : 1, exclude_host : 1, exclude_guest : 1, exclude_callchain_kernel : 1, exclude_callchain_user : 1, mmap2 : 1, comm_exec : 1, use_clockid : 1, context_switch : 1, write_backward : 1, namespaces : 1, ksymbol : 1, bpf_event : 1, aux_output : 1, cgroup : 1, text_poke : 1, build_id : 1, inherit_thread : 1, remove_on_exec : 1, sigtrap : 1, __reserved_1 : 26;
  union {
    __u32 wakeup_events;
    __u32 wakeup_watermark;
  };
  __u32 bp_type;
  union {
    __u64 bp_addr;
    __u64 kprobe_func;
    __u64 uprobe_path;
    __u64 config1;
  };
  union {
    __u64 bp_len;
    __u64 kprobe_addr;
    __u64 probe_offset;
    __u64 config2;
  };
  __u64 branch_sample_type;
  __u64 sample_regs_user;
  __u32 sample_stack_user;
  __s32 clockid;
  __u64 sample_regs_intr;
  __u32 aux_watermark;
  __u16 sample_max_stack;
  __u16 __reserved_2;
  __u32 aux_sample_size;
  __u32 __reserved_3;
  __u64 sig_data;
  __u64 config3;
};
struct perf_event_query_bpf {
  __u32 ids_len;
  __u32 prog_cnt;
  __u32 ids[];
};
#define PERF_EVENT_IOC_ENABLE _IO('$', 0)
#define PERF_EVENT_IOC_DISABLE _IO('$', 1)
#define PERF_EVENT_IOC_REFRESH _IO('$', 2)
#define PERF_EVENT_IOC_RESET _IO('$', 3)
#define PERF_EVENT_IOC_PERIOD _IOW('$', 4, __u64)
#define PERF_EVENT_IOC_SET_OUTPUT _IO('$', 5)
#define PERF_EVENT_IOC_SET_FILTER _IOW('$', 6, char *)
#define PERF_EVENT_IOC_ID _IOR('$', 7, __u64 *)
#define PERF_EVENT_IOC_SET_BPF _IOW('$', 8, __u32)
#define PERF_EVENT_IOC_PAUSE_OUTPUT _IOW('$', 9, __u32)
#define PERF_EVENT_IOC_QUERY_BPF _IOWR('$', 10, struct perf_event_query_bpf *)
#define PERF_EVENT_IOC_MODIFY_ATTRIBUTES _IOW('$', 11, struct perf_event_attr *)
enum perf_event_ioc_flags {
  PERF_IOC_FLAG_GROUP = 1U << 0,
};
struct perf_event_mmap_page {
  __u32 version;
  __u32 compat_version;
  __u32 lock;
  __u32 index;
  __s64 offset;
  __u64 time_enabled;
  __u64 time_running;
  union {
    __u64 capabilities;
    struct {
      __u64 cap_bit0 : 1, cap_bit0_is_deprecated : 1, cap_user_rdpmc : 1, cap_user_time : 1, cap_user_time_zero : 1, cap_user_time_short : 1, cap_____res : 58;
    };
  };
  __u16 pmc_width;
  __u16 time_shift;
  __u32 time_mult;
  __u64 time_offset;
  __u64 time_zero;
  __u32 size;
  __u32 __reserved_1;
  __u64 time_cycles;
  __u64 time_mask;
  __u8 __reserved[116 * 8];
  __u64 data_head;
  __u64 data_tail;
  __u64 data_offset;
  __u64 data_size;
  __u64 aux_head;
  __u64 aux_tail;
  __u64 aux_offset;
  __u64 aux_size;
};
#define PERF_RECORD_MISC_CPUMODE_MASK (7 << 0)
#define PERF_RECORD_MISC_CPUMODE_UNKNOWN (0 << 0)
#define PERF_RECORD_MISC_KERNEL (1 << 0)
#define PERF_RECORD_MISC_USER (2 << 0)
#define PERF_RECORD_MISC_HYPERVISOR (3 << 0)
#define PERF_RECORD_MISC_GUEST_KERNEL (4 << 0)
#define PERF_RECORD_MISC_GUEST_USER (5 << 0)
#define PERF_RECORD_MISC_PROC_MAP_PARSE_TIMEOUT (1 << 12)
#define PERF_RECORD_MISC_MMAP_DATA (1 << 13)
#define PERF_RECORD_MISC_COMM_EXEC (1 << 13)
#define PERF_RECORD_MISC_FORK_EXEC (1 << 13)
#define PERF_RECORD_MISC_SWITCH_OUT (1 << 13)
#define PERF_RECORD_MISC_EXACT_IP (1 << 14)
#define PERF_RECORD_MISC_SWITCH_OUT_PREEMPT (1 << 14)
#define PERF_RECORD_MISC_MMAP_BUILD_ID (1 << 14)
#define PERF_RECORD_MISC_EXT_RESERVED (1 << 15)
struct perf_event_header {
  __u32 type;
  __u16 misc;
  __u16 size;
};
struct perf_ns_link_info {
  __u64 dev;
  __u64 ino;
};
enum {
  NET_NS_INDEX = 0,
  UTS_NS_INDEX = 1,
  IPC_NS_INDEX = 2,
  PID_NS_INDEX = 3,
  USER_NS_INDEX = 4,
  MNT_NS_INDEX = 5,
  CGROUP_NS_INDEX = 6,
  NR_NAMESPACES,
};
enum perf_event_type {
  PERF_RECORD_MMAP = 1,
  PERF_RECORD_LOST = 2,
  PERF_RECORD_COMM = 3,
  PERF_RECORD_EXIT = 4,
  PERF_RECORD_THROTTLE = 5,
  PERF_RECORD_UNTHROTTLE = 6,
  PERF_RECORD_FORK = 7,
  PERF_RECORD_READ = 8,
  PERF_RECORD_SAMPLE = 9,
  PERF_RECORD_MMAP2 = 10,
  PERF_RECORD_AUX = 11,
  PERF_RECORD_ITRACE_START = 12,
  PERF_RECORD_LOST_SAMPLES = 13,
  PERF_RECORD_SWITCH = 14,
  PERF_RECORD_SWITCH_CPU_WIDE = 15,
  PERF_RECORD_NAMESPACES = 16,
  PERF_RECORD_KSYMBOL = 17,
  PERF_RECORD_BPF_EVENT = 18,
  PERF_RECORD_CGROUP = 19,
  PERF_RECORD_TEXT_POKE = 20,
  PERF_RECORD_AUX_OUTPUT_HW_ID = 21,
  PERF_RECORD_MAX,
};
enum perf_record_ksymbol_type {
  PERF_RECORD_KSYMBOL_TYPE_UNKNOWN = 0,
  PERF_RECORD_KSYMBOL_TYPE_BPF = 1,
  PERF_RECORD_KSYMBOL_TYPE_OOL = 2,
  PERF_RECORD_KSYMBOL_TYPE_MAX
};
#define PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER (1 << 0)
enum perf_bpf_event_type {
  PERF_BPF_EVENT_UNKNOWN = 0,
  PERF_BPF_EVENT_PROG_LOAD = 1,
  PERF_BPF_EVENT_PROG_UNLOAD = 2,
  PERF_BPF_EVENT_MAX,
};
#define PERF_MAX_STACK_DEPTH 127
#define PERF_MAX_CONTEXTS_PER_STACK 8
enum perf_callchain_context {
  PERF_CONTEXT_HV = (__u64) - 32,
  PERF_CONTEXT_KERNEL = (__u64) - 128,
  PERF_CONTEXT_USER = (__u64) - 512,
  PERF_CONTEXT_GUEST = (__u64) - 2048,
  PERF_CONTEXT_GUEST_KERNEL = (__u64) - 2176,
  PERF_CONTEXT_GUEST_USER = (__u64) - 2560,
  PERF_CONTEXT_MAX = (__u64) - 4095,
};
#define PERF_AUX_FLAG_TRUNCATED 0x01
#define PERF_AUX_FLAG_OVERWRITE 0x02
#define PERF_AUX_FLAG_PARTIAL 0x04
#define PERF_AUX_FLAG_COLLISION 0x08
#define PERF_AUX_FLAG_PMU_FORMAT_TYPE_MASK 0xff00
#define PERF_AUX_FLAG_CORESIGHT_FORMAT_CORESIGHT 0x0000
#define PERF_AUX_FLAG_CORESIGHT_FORMAT_RAW 0x0100
#define PERF_FLAG_FD_NO_GROUP (1UL << 0)
#define PERF_FLAG_FD_OUTPUT (1UL << 1)
#define PERF_FLAG_PID_CGROUP (1UL << 2)
#define PERF_FLAG_FD_CLOEXEC (1UL << 3)
#ifdef __LITTLE_ENDIAN_BITFIELD
union perf_mem_data_src {
  __u64 val;
  struct {
    __u64 mem_op : 5, mem_lvl : 14, mem_snoop : 5, mem_lock : 2, mem_dtlb : 7, mem_lvl_num : 4, mem_remote : 1, mem_snoopx : 2, mem_blk : 3, mem_hops : 3, mem_rsvd : 18;
  };
};
#elif defined(__BIG_ENDIAN_BITFIELD)
union perf_mem_data_src {
  __u64 val;
  struct {
    __u64 mem_rsvd : 18, mem_hops : 3, mem_blk : 3, mem_snoopx : 2, mem_remote : 1, mem_lvl_num : 4, mem_dtlb : 7, mem_lock : 2, mem_snoop : 5, mem_lvl : 14, mem_op : 5;
  };
};
#else
#error "Unknown endianness"
#endif
#define PERF_MEM_OP_NA 0x01
#define PERF_MEM_OP_LOAD 0x02
#define PERF_MEM_OP_STORE 0x04
#define PERF_MEM_OP_PFETCH 0x08
#define PERF_MEM_OP_EXEC 0x10
#define PERF_MEM_OP_SHIFT 0
#define PERF_MEM_LVL_NA 0x01
#define PERF_MEM_LVL_HIT 0x02
#define PERF_MEM_LVL_MISS 0x04
#define PERF_MEM_LVL_L1 0x08
#define PERF_MEM_LVL_LFB 0x10
#define PERF_MEM_LVL_L2 0x20
#define PERF_MEM_LVL_L3 0x40
#define PERF_MEM_LVL_LOC_RAM 0x80
#define PERF_MEM_LVL_REM_RAM1 0x100
#define PERF_MEM_LVL_REM_RAM2 0x200
#define PERF_MEM_LVL_REM_CCE1 0x400
#define PERF_MEM_LVL_REM_CCE2 0x800
#define PERF_MEM_LVL_IO 0x1000
#define PERF_MEM_LVL_UNC 0x2000
#define PERF_MEM_LVL_SHIFT 5
#define PERF_MEM_REMOTE_REMOTE 0x01
#define PERF_MEM_REMOTE_SHIFT 37
#define PERF_MEM_LVLNUM_L1 0x01
#define PERF_MEM_LVLNUM_L2 0x02
#define PERF_MEM_LVLNUM_L3 0x03
#define PERF_MEM_LVLNUM_L4 0x04
#define PERF_MEM_LVLNUM_L2_MHB 0x05
#define PERF_MEM_LVLNUM_MSC 0x06
#define PERF_MEM_LVLNUM_UNC 0x08
#define PERF_MEM_LVLNUM_CXL 0x09
#define PERF_MEM_LVLNUM_IO 0x0a
#define PERF_MEM_LVLNUM_ANY_CACHE 0x0b
#define PERF_MEM_LVLNUM_LFB 0x0c
#define PERF_MEM_LVLNUM_RAM 0x0d
#define PERF_MEM_LVLNUM_PMEM 0x0e
#define PERF_MEM_LVLNUM_NA 0x0f
#define PERF_MEM_LVLNUM_SHIFT 33
#define PERF_MEM_SNOOP_NA 0x01
#define PERF_MEM_SNOOP_NONE 0x02
#define PERF_MEM_SNOOP_HIT 0x04
#define PERF_MEM_SNOOP_MISS 0x08
#define PERF_MEM_SNOOP_HITM 0x10
#define PERF_MEM_SNOOP_SHIFT 19
#define PERF_MEM_SNOOPX_FWD 0x01
#define PERF_MEM_SNOOPX_PEER 0x02
#define PERF_MEM_SNOOPX_SHIFT 38
#define PERF_MEM_LOCK_NA 0x01
#define PERF_MEM_LOCK_LOCKED 0x02
#define PERF_MEM_LOCK_SHIFT 24
#define PERF_MEM_TLB_NA 0x01
#define PERF_MEM_TLB_HIT 0x02
#define PERF_MEM_TLB_MISS 0x04
#define PERF_MEM_TLB_L1 0x08
#define PERF_MEM_TLB_L2 0x10
#define PERF_MEM_TLB_WK 0x20
#define PERF_MEM_TLB_OS 0x40
#define PERF_MEM_TLB_SHIFT 26
#define PERF_MEM_BLK_NA 0x01
#define PERF_MEM_BLK_DATA 0x02
#define PERF_MEM_BLK_ADDR 0x04
#define PERF_MEM_BLK_SHIFT 40
#define PERF_MEM_HOPS_0 0x01
#define PERF_MEM_HOPS_1 0x02
#define PERF_MEM_HOPS_2 0x03
#define PERF_MEM_HOPS_3 0x04
#define PERF_MEM_HOPS_SHIFT 43
#define PERF_MEM_S(a,s) (((__u64) PERF_MEM_ ##a ##_ ##s) << PERF_MEM_ ##a ##_SHIFT)
struct perf_branch_entry {
  __u64 from;
  __u64 to;
  __u64 mispred : 1, predicted : 1, in_tx : 1, abort : 1, cycles : 16, type : 4, spec : 2, new_type : 4, priv : 3, reserved : 31;
};
#define PERF_BRANCH_ENTRY_INFO_BITS_MAX 33
union perf_sample_weight {
  __u64 full;
#ifdef __LITTLE_ENDIAN_BITFIELD
  struct {
    __u32 var1_dw;
    __u16 var2_w;
    __u16 var3_w;
  };
#elif defined(__BIG_ENDIAN_BITFIELD)
  struct {
    __u16 var3_w;
    __u16 var2_w;
    __u32 var1_dw;
  };
#else
#error "Unknown endianness"
#endif
};
#endif
```