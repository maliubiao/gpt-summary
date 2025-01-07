Response:
Let's break down the thought process for analyzing this C header file.

**1. Initial Scan and Purpose Identification:**

The first thing I noticed is the file path: `bionic/libc/kernel/uapi/linux/userfaultfd.handroid`. This immediately tells me:

* **`bionic`:** This relates to Android's core C library.
* **`libc`:**  Confirms it's part of the standard C library implementation within Android.
* **`kernel`:**  Indicates that this code interacts directly with the Linux kernel.
* **`uapi`:**  Specifically, it's a *user-space API* for interacting with kernel features. This means user-space programs will use these definitions to communicate with the kernel.
* **`linux`:**  Confirms this is a Linux-specific API, which makes sense for Android.
* **`userfaultfd`:** This is the key term. I recognize this as a Linux feature related to handling page faults in user space.
* **`.handroid`:** This suffix strongly suggests Android-specific modifications or configurations to the standard Linux `userfaultfd` interface. It's a hint that there might be slight variations or additions compared to a vanilla Linux kernel.

The comment at the top reinforces this: "This file is auto-generated. Modifications will be lost." and the link to the bionic repository confirm it's part of the Android build process.

**2. Identifying Core Functionality:**

My next step is to look for key definitions and structures. I see:

* **`#define USERFAULTFD_IOC ...` and related `_IO`, `_IOWR`, `_IOR` macros:**  These strongly indicate the use of `ioctl` system calls. `ioctl` is a fundamental mechanism for user-space programs to send control commands and data to kernel drivers or subsystems. The `USERFAULTFD_IOC` values are the command numbers for these `ioctl`s.
* **`struct uffd_msg`:**  This looks like the structure used for asynchronous communication *from* the kernel *to* user space. The `event` field suggests different types of notifications.
* **`struct uffdio_api`, `uffdio_range`, `uffdio_register`, etc.:** These structures are clearly used as arguments to the `ioctl` calls. They define the parameters and data exchanged between user space and the kernel.
* **`#define UFFD_EVENT_...`:** These define the different events that can be reported in the `uffd_msg`.
* **`#define UFFDIO_REGISTER_MODE_...`, `#define UFFDIO_COPY_MODE_...`:** These are bit flags that control the behavior of the various `ioctl` operations.

From these observations, I deduce the core functionality:  `userfaultfd` allows a user-space process to register a range of memory and be notified by the kernel when a page fault occurs within that range. The process can then handle the page fault itself (e.g., by populating the page with data).

**3. Connecting to Android:**

Knowing that this is part of Android, I start thinking about where this might be used. Common scenarios involving memory management in Android include:

* **Memory Mapping (mmap):**  `userfaultfd` could be used to implement custom demand-paging behavior.
* **Graphics (SurfaceFlinger, Vulkan):** Efficient memory management is crucial for graphics. `userfaultfd` could be used for lazy allocation or for interacting with hardware-backed buffers.
* **Virtualization/Containers:**  `userfaultfd` is sometimes used in these contexts for memory sharing or efficient resource management.
* **Memory Compaction/Reclamation:**  Android has various mechanisms for managing memory pressure. `userfaultfd` could potentially play a role in more advanced memory management strategies.

**4. Explaining `libc` Functions and Dynamic Linking:**

The header file itself *doesn't* define `libc` functions directly. It defines structures and macros that are *used by* `libc` functions (specifically, functions that wrap the `ioctl` system call). Therefore, the explanation focuses on how a `libc` function like `ioctl()` would be used with the defined constants and structures.

Regarding dynamic linking, this header file primarily defines *data structures*. Dynamic linking is about resolving function calls between shared libraries. While the *use* of `userfaultfd` might involve libraries, the header itself doesn't directly dictate dynamic linking behavior. The example SO layout focuses on how a hypothetical library using `userfaultfd` might be structured.

**5. Logical Reasoning, Assumptions, and Error Handling:**

For logical reasoning, I consider the flow of events: a process registers memory, a page fault occurs, the kernel sends a message, the process handles it. I formulate a simple input/output scenario to illustrate this.

For common errors, I think about the types of mistakes developers might make when using a low-level API like this: incorrect usage of `ioctl`, invalid memory ranges, race conditions, and not handling events properly.

**6. Tracing the Path from Framework/NDK:**

I consider the typical layers in Android:

* **Framework (Java/Kotlin):**  High-level APIs.
* **NDK (C/C++):**  Lower-level access to system features.
* **Bionic (libc):**  The core C library implementation.
* **Kernel:** The underlying operating system.

The path would typically involve a framework component (perhaps related to memory management or graphics) calling an NDK API, which in turn uses `libc` functions that eventually invoke the `ioctl` system call with the constants defined in this header file.

**7. Frida Hooking:**

Finally, I consider how to use Frida to observe the interaction with `userfaultfd`. The key is to hook the `ioctl` system call and filter for the specific `USERFAULTFD_IOC` values. Hooking functions within `libc` that might wrap these `ioctl` calls is also a good strategy.

**Self-Correction/Refinement:**

Throughout this process, I constantly review and refine my understanding. For instance:

* **Initial thought:**  "Are there specific `libc` wrappers for these `ioctl`s?"  **Correction:**  While there might be convenience wrappers in some higher-level libraries, the core interaction goes through `ioctl`.
* **Initial thought:** "Does this header define the events themselves?" **Correction:** It defines the *codes* for the events, and the `uffd_msg` structure to carry them. The actual event triggering happens within the kernel.
* **Initial thought:** "How detailed should the SO layout be?" **Correction:** Focus on the relevant aspects of how a library *using* this functionality might be structured, not a complete deep dive into ELF format.

By following this structured approach, breaking down the code into smaller parts, and connecting it to the broader Android context, I can arrive at a comprehensive explanation like the example provided in the prompt.
这是一个定义Linux `userfaultfd` (用户缺页处理) 功能的头文件，专用于 Android 的 Bionic C 库。它提供了用户空间程序处理缺页错误的机制。

**功能列举:**

这个头文件定义了与 `userfaultfd` 机制交互所需的常量、数据结构和 ioctl 命令。其核心功能是允许用户空间程序注册一段内存区域，当内核在该区域发生缺页错误时，不是直接发送 `SIGSEGV` 信号终止进程，而是通知用户空间程序，由用户程序决定如何处理这个缺页错误。

具体来说，它定义了：

* **ioctl 命令:**  用于用户空间程序与内核 `userfaultfd` 驱动进行通信，例如注册、注销内存区域，唤醒等待的线程等。
* **数据结构:**  用于在用户空间和内核之间传递信息，例如注册的内存范围、缺页错误的信息、以及用于控制 `userfaultfd` 行为的各种参数。
* **事件类型:** 定义了内核通知用户空间程序的各种事件，例如缺页错误、进程 fork、内存 remap、内存 remove、内存 unmap 等。
* **特性标志:**  定义了 `userfaultfd` 支持的各种特性。

**与 Android 功能的关系及举例说明:**

`userfaultfd` 是一个底层的 Linux 内核特性，Android 利用它来实现一些高级的内存管理和优化功能。以下是一些可能的应用场景：

1. **延迟分配 (Lazy Allocation):**  Android 可以使用 `userfaultfd` 来实现内存的延迟分配。当应用首次访问某块内存时，会触发缺页错误，然后用户空间的 `userfaultfd` 处理程序可以按需分配和初始化这块内存。这可以减少启动时间和内存占用。

   **例子：** 假设一个应用启动时需要分配一大块内存，但不是所有内存都会立即被使用。使用 `userfaultfd`，可以先注册这块内存区域，当应用真正访问到某个页面时，`userfaultfd` 处理程序才分配这个页面。

2. **内存去重 (Memory Deduplication):**  在多个进程共享相同数据的情况下，可以使用 `userfaultfd` 来实现内存去重。当一个进程尝试写入共享内存页时，会触发写保护缺页错误，`userfaultfd` 处理程序可以复制该页面，使得每个进程拥有自己的私有副本，从而避免相互干扰。

   **例子：**  Android 中的 Zygote 进程孵化新的应用进程时，很多共享库的代码段是相同的。`userfaultfd` 可以用于管理这些共享内存，当一个进程尝试修改共享代码段时，触发写保护错误，将其复制一份。

3. **用户态的内存管理:**  某些高级的内存管理库或虚拟机 (例如 ART - Android Runtime) 可以利用 `userfaultfd` 来实现更精细的内存控制，例如自定义的垃圾回收机制或者内存压缩。

   **例子：** ART 虚拟机可能使用 `userfaultfd` 来监控堆内存的访问情况，当垃圾回收器需要移动对象时，可以先设置内存页的写保护，当应用尝试访问这些页面时，触发缺页错误，然后垃圾回收器可以更新指针并重新映射页面。

**libc 函数的功能实现:**

这个头文件本身并没有定义 `libc` 函数的实现，它只是定义了与 `userfaultfd` 交互所需的常量和数据结构。用户空间程序需要使用标准的 `libc` 系统调用接口 (例如 `open`, `close`, `ioctl`, `read`) 来与内核 `userfaultfd` 驱动进行交互。

具体来说，与 `userfaultfd` 相关的操作通常会用到 `ioctl` 系统调用。`ioctl` 的功能是向设备驱动程序发送控制命令并传递数据。

例如，要注册一个内存区域以进行用户缺页处理，用户空间程序会：

1. 使用 `open` 系统调用打开 `/dev/userfaultfd` 设备文件，获得一个文件描述符。
2. 填充 `uffdio_register` 结构体，指定要注册的内存范围和模式。
3. 调用 `ioctl` 系统调用，并将打开的文件描述符和 `UFFDIO_REGISTER` 命令以及指向 `uffdio_register` 结构体的指针作为参数传递给内核。

内核 `userfaultfd` 驱动程序接收到 `ioctl` 调用后，会根据提供的参数，将指定的内存区域与打开的文件描述符关联起来。

**涉及 dynamic linker 的功能:**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载共享库，并解析和绑定符号。

然而，`userfaultfd` 可以在某些场景下与 dynamic linker 间接交互，例如在延迟加载共享库时。

**假设场景:** 假设一个应用使用了某种延迟加载共享库的机制，该机制基于 `userfaultfd` 实现。

**SO 布局样本：**

```
# 假设的延迟加载共享库 libdelayed.so

LOAD 0x0000007000000000 0x0000007000000000 00001000 00001000 RW  # 可读写段
LOAD 0x0000007000001000 0x0000007000001000 00001000 00001000 R E # 可读可执行段
```

**链接的处理过程：**

1. **应用启动:** 应用启动后，dynamic linker 加载应用本身的可执行文件。
2. **遇到未解析符号:** 应用的代码中可能存在对 `libdelayed.so` 中函数的调用，但由于是延迟加载，dynamic linker 此时并未加载该库。
3. **触发缺页错误:** 当应用首次执行到调用 `libdelayed.so` 中函数的代码时，由于该库的代码页尚未加载到内存，会触发缺页错误。
4. **userfaultfd 处理:** 如果应用注册了包含该代码地址的内存区域的 `userfaultfd` 处理程序，内核会将缺页事件通知该处理程序。
5. **加载共享库:** `userfaultfd` 处理程序接收到缺页事件后，可以决定加载 `libdelayed.so`，并将其映射到内存中。
6. **修复缺页:** 处理程序可以使用 `UFFDIO_COPY` 或 `UFFDIO_ZEROPAGE` 等 ioctl 命令来填充缺页的内存页。
7. **继续执行:**  缺页错误被修复后，应用可以继续执行，这次可以成功调用 `libdelayed.so` 中的函数。

**逻辑推理、假设输入与输出：**

**假设输入：**

1. 用户空间程序打开 `/dev/userfaultfd` 获得文件描述符 `ufd`。
2. 程序调用 `ioctl(ufd, UFFDIO_REGISTER, &reg)` 注册地址范围 `reg.range.start` 到 `reg.range.start + reg.range.len`，模式为 `UFFDIO_REGISTER_MODE_MISSING`。
3. 程序尝试访问注册范围内的某个地址，例如 `reg.range.start + offset`，该地址尚未映射到物理内存。

**输出：**

1. 内核检测到缺页错误。
2. 内核向 `ufd` 文件描述符写入一个 `uffd_msg` 结构体，其 `event` 字段为 `UFFD_EVENT_PAGEFAULT`，`arg.pagefault.address` 字段为触发缺页的地址 `reg.range.start + offset`。
3. 用户空间程序从 `ufd` 读取到该消息，并根据消息内容执行相应的处理。

**用户或编程常见的使用错误：**

1. **未正确处理 `userfaultfd` 事件:**  用户空间程序必须及时且正确地处理从 `userfaultfd` 文件描述符读取到的事件。如果处理不当（例如，处理程序阻塞、崩溃或忽略事件），可能导致程序hang住或出现未定义的行为。
2. **注册了错误的内存范围:**  注册的内存范围必须是有效的，并且与实际需要处理缺页的内存区域匹配。如果注册的范围不正确，可能导致缺页事件无法被捕获，或者捕获到错误的事件。
3. **竞态条件:**  在多线程环境下使用 `userfaultfd` 时，需要小心处理竞态条件。例如，当一个线程触发缺页错误时，另一个线程可能正在修改相关的内存映射。
4. **错误地使用 ioctl 命令:**  传递给 `ioctl` 的参数必须正确，否则会导致 `ioctl` 调用失败或者产生意外的结果。例如，`uffdio_copy` 的源地址和目标地址不能重叠，且必须在注册的范围内。
5. **忘记注销内存区域:**  在不再需要用户缺页处理的内存区域上，应该使用 `UFFDIO_UNREGISTER` 命令注销，否则可能会导致不必要的开销。

**Android framework 或 ndk 如何一步步的到达这里:**

1. **Android Framework (Java/Kotlin):**  Android Framework 通常不会直接使用 `userfaultfd`，因为它是一个底层的内核特性。Framework 可能会使用一些更高层次的抽象，例如 `MemoryFile` 或 `SharedMemory`，这些抽象的实现可能会在底层利用 `userfaultfd`。

2. **NDK (C/C++):**  NDK 开发者可以直接使用 `userfaultfd` 相关的系统调用，通过 `libc` 提供的接口。

3. **libc (Bionic):**  Bionic 库提供了与内核交互的系统调用接口，包括 `open`, `close`, `ioctl`, `read` 等。开发者可以使用这些函数来操作 `/dev/userfaultfd` 设备，并发送 `userfaultfd` 相关的 ioctl 命令。

**步骤示例 (假设 NDK 应用使用 `userfaultfd`):**

1. **NDK 应用代码:**  开发者编写 C/C++ 代码，使用 `open("/dev/userfaultfd", O_RDWR)` 打开 `userfaultfd` 设备。
2. **ioctl 调用:**  开发者填充 `uffdio_register` 结构体，并调用 `ioctl(fd, UFFDIO_REGISTER, &reg)` 注册需要监控的内存区域。
3. **内存访问触发缺页:**  当应用尝试访问注册区域内尚未映射的内存时，内核触发缺页错误。
4. **内核通知:**  内核将缺页事件信息写入到 `userfaultfd` 的文件描述符中。
5. **读取事件:**  NDK 应用通过 `read(fd, &msg, sizeof(msg))` 读取 `uffd_msg` 结构体，获取缺页事件的详细信息。
6. **处理缺页:**  应用根据事件信息，例如缺页地址，执行相应的操作，例如分配物理内存，并将数据填充到该内存页。
7. **ioctl 继续执行:**  应用调用 `ioctl(fd, UFFDIO_CONTINUE, &cont)` 告诉内核可以继续执行触发缺页的线程。

**Frida Hook 示例调试步骤:**

```python
import frida
import sys

# 要 hook 的进程名称或 PID
package_name = "your.app.package"

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[*] Error: {message['stack']}")

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found.")
    sys.exit(1)

script_code = """
// hook open 系统调用，查看是否打开了 /dev/userfaultfd
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        const pathname = Memory.readUtf8String(args[0]);
        if (pathname.includes("userfaultfd")) {
            console.log("[*] open(\"" + pathname + "\", " + args[1] + ")");
        }
    },
    onLeave: function(retval) {
    }
});

// hook ioctl 系统调用，查看是否调用了 userfaultfd 相关的 ioctl 命令
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 检查是否是 UFFDIO_MAGIC (0xAA << 8)
        if ((request >> 8) == 0xAA) {
            console.log("[*] ioctl(fd=" + fd + ", request=0x" + request.toString(16) + ")");
            if (request == 0xaa00) { // _UFFDIO_REGISTER
                const uffdio_register_ptr = ptr(args[2]);
                const range_start = uffdio_register_ptr.readU64();
                const range_len = uffdio_register_ptr.add(8).readU64();
                const mode = uffdio_register_ptr.add(16).readU64();
                const ioctls = uffdio_register_ptr.add(24).readU64();
                console.log("    UFFDIO_REGISTER: start=0x" + range_start.toString(16) + ", len=0x" + range_len.toString(16) + ", mode=0x" + mode.toString(16) + ", ioctls=0x" + ioctls.toString(16));
            } else if (request == 0xaa02) { // _UFFDIO_WAKE
                const uffdio_range_ptr = ptr(args[2]);
                const range_start = uffdio_range_ptr.readU64();
                const range_len = uffdio_range_ptr.add(8).readU64();
                console.log("    UFFDIO_WAKE: start=0x" + range_start.toString(16) + ", len=0x" + range_len.toString(16));
            } // 可以添加其他 UFFDIO_* 命令的解析
        }
    },
    onLeave: function(retval) {
    }
});

// hook read 系统调用，查看是否读取了 userfaultfd 的事件
Interceptor.attach(Module.findExportByName(null, "read"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.fd >= 0) { // 假设 userfaultfd 的 fd 是正数
            const buf = ptr(arguments[0]);
            if (retval.toInt32() > 0) {
                try {
                    const event_type = buf.readU8();
                    if (event_type == 0x12) {
                        const address = buf.add(8).readU64();
                        console.log("[*] read from userfaultfd: UFFD_EVENT_PAGEFAULT, address=0x" + address.toString(16));
                    } else if (event_type == 0x13) {
                        console.log("[*] read from userfaultfd: UFFD_EVENT_FORK");
                    } // 可以添加其他 UFFD_EVENT_* 的解析
                } catch (e) {
                    console.log("[*] read from userfaultfd, but cannot parse event: " + e);
                }
            }
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个 Frida 脚本会 hook `open`, `ioctl`, 和 `read` 系统调用，并过滤与 `userfaultfd` 相关的操作，打印出调用的参数和读取到的事件信息，从而帮助调试 `userfaultfd` 的使用过程。你需要将 `your.app.package` 替换为你要调试的 Android 应用的包名。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/userfaultfd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _LINUX_USERFAULTFD_H
#define _LINUX_USERFAULTFD_H
#include <linux/types.h>
#define USERFAULTFD_IOC 0xAA
#define USERFAULTFD_IOC_NEW _IO(USERFAULTFD_IOC, 0x00)
#define UFFD_API ((__u64) 0xAA)
#define UFFD_API_REGISTER_MODES (UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP | UFFDIO_REGISTER_MODE_MINOR)
#define UFFD_API_FEATURES (UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_EVENT_FORK | UFFD_FEATURE_EVENT_REMAP | UFFD_FEATURE_EVENT_REMOVE | UFFD_FEATURE_EVENT_UNMAP | UFFD_FEATURE_MISSING_HUGETLBFS | UFFD_FEATURE_MISSING_SHMEM | UFFD_FEATURE_SIGBUS | UFFD_FEATURE_THREAD_ID | UFFD_FEATURE_MINOR_HUGETLBFS | UFFD_FEATURE_MINOR_SHMEM | UFFD_FEATURE_EXACT_ADDRESS | UFFD_FEATURE_WP_HUGETLBFS_SHMEM | UFFD_FEATURE_WP_UNPOPULATED | UFFD_FEATURE_POISON | UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_MOVE)
#define UFFD_API_IOCTLS ((__u64) 1 << _UFFDIO_REGISTER | (__u64) 1 << _UFFDIO_UNREGISTER | (__u64) 1 << _UFFDIO_API)
#define UFFD_API_RANGE_IOCTLS ((__u64) 1 << _UFFDIO_WAKE | (__u64) 1 << _UFFDIO_COPY | (__u64) 1 << _UFFDIO_ZEROPAGE | (__u64) 1 << _UFFDIO_MOVE | (__u64) 1 << _UFFDIO_WRITEPROTECT | (__u64) 1 << _UFFDIO_CONTINUE | (__u64) 1 << _UFFDIO_POISON)
#define UFFD_API_RANGE_IOCTLS_BASIC ((__u64) 1 << _UFFDIO_WAKE | (__u64) 1 << _UFFDIO_COPY | (__u64) 1 << _UFFDIO_WRITEPROTECT | (__u64) 1 << _UFFDIO_CONTINUE | (__u64) 1 << _UFFDIO_POISON)
#define _UFFDIO_REGISTER (0x00)
#define _UFFDIO_UNREGISTER (0x01)
#define _UFFDIO_WAKE (0x02)
#define _UFFDIO_COPY (0x03)
#define _UFFDIO_ZEROPAGE (0x04)
#define _UFFDIO_MOVE (0x05)
#define _UFFDIO_WRITEPROTECT (0x06)
#define _UFFDIO_CONTINUE (0x07)
#define _UFFDIO_POISON (0x08)
#define _UFFDIO_API (0x3F)
#define UFFDIO 0xAA
#define UFFDIO_API _IOWR(UFFDIO, _UFFDIO_API, struct uffdio_api)
#define UFFDIO_REGISTER _IOWR(UFFDIO, _UFFDIO_REGISTER, struct uffdio_register)
#define UFFDIO_UNREGISTER _IOR(UFFDIO, _UFFDIO_UNREGISTER, struct uffdio_range)
#define UFFDIO_WAKE _IOR(UFFDIO, _UFFDIO_WAKE, struct uffdio_range)
#define UFFDIO_COPY _IOWR(UFFDIO, _UFFDIO_COPY, struct uffdio_copy)
#define UFFDIO_ZEROPAGE _IOWR(UFFDIO, _UFFDIO_ZEROPAGE, struct uffdio_zeropage)
#define UFFDIO_MOVE _IOWR(UFFDIO, _UFFDIO_MOVE, struct uffdio_move)
#define UFFDIO_WRITEPROTECT _IOWR(UFFDIO, _UFFDIO_WRITEPROTECT, struct uffdio_writeprotect)
#define UFFDIO_CONTINUE _IOWR(UFFDIO, _UFFDIO_CONTINUE, struct uffdio_continue)
#define UFFDIO_POISON _IOWR(UFFDIO, _UFFDIO_POISON, struct uffdio_poison)
struct uffd_msg {
  __u8 event;
  __u8 reserved1;
  __u16 reserved2;
  __u32 reserved3;
  union {
    struct {
      __u64 flags;
      __u64 address;
      union {
        __u32 ptid;
      } feat;
    } pagefault;
    struct {
      __u32 ufd;
    } fork;
    struct {
      __u64 from;
      __u64 to;
      __u64 len;
    } remap;
    struct {
      __u64 start;
      __u64 end;
    } remove;
    struct {
      __u64 reserved1;
      __u64 reserved2;
      __u64 reserved3;
    } reserved;
  } arg;
} __attribute__((__packed__));
#define UFFD_EVENT_PAGEFAULT 0x12
#define UFFD_EVENT_FORK 0x13
#define UFFD_EVENT_REMAP 0x14
#define UFFD_EVENT_REMOVE 0x15
#define UFFD_EVENT_UNMAP 0x16
#define UFFD_PAGEFAULT_FLAG_WRITE (1 << 0)
#define UFFD_PAGEFAULT_FLAG_WP (1 << 1)
#define UFFD_PAGEFAULT_FLAG_MINOR (1 << 2)
struct uffdio_api {
  __u64 api;
#define UFFD_FEATURE_PAGEFAULT_FLAG_WP (1 << 0)
#define UFFD_FEATURE_EVENT_FORK (1 << 1)
#define UFFD_FEATURE_EVENT_REMAP (1 << 2)
#define UFFD_FEATURE_EVENT_REMOVE (1 << 3)
#define UFFD_FEATURE_MISSING_HUGETLBFS (1 << 4)
#define UFFD_FEATURE_MISSING_SHMEM (1 << 5)
#define UFFD_FEATURE_EVENT_UNMAP (1 << 6)
#define UFFD_FEATURE_SIGBUS (1 << 7)
#define UFFD_FEATURE_THREAD_ID (1 << 8)
#define UFFD_FEATURE_MINOR_HUGETLBFS (1 << 9)
#define UFFD_FEATURE_MINOR_SHMEM (1 << 10)
#define UFFD_FEATURE_EXACT_ADDRESS (1 << 11)
#define UFFD_FEATURE_WP_HUGETLBFS_SHMEM (1 << 12)
#define UFFD_FEATURE_WP_UNPOPULATED (1 << 13)
#define UFFD_FEATURE_POISON (1 << 14)
#define UFFD_FEATURE_WP_ASYNC (1 << 15)
#define UFFD_FEATURE_MOVE (1 << 16)
  __u64 features;
  __u64 ioctls;
};
struct uffdio_range {
  __u64 start;
  __u64 len;
};
struct uffdio_register {
  struct uffdio_range range;
#define UFFDIO_REGISTER_MODE_MISSING ((__u64) 1 << 0)
#define UFFDIO_REGISTER_MODE_WP ((__u64) 1 << 1)
#define UFFDIO_REGISTER_MODE_MINOR ((__u64) 1 << 2)
  __u64 mode;
  __u64 ioctls;
};
struct uffdio_copy {
  __u64 dst;
  __u64 src;
  __u64 len;
#define UFFDIO_COPY_MODE_DONTWAKE ((__u64) 1 << 0)
#define UFFDIO_COPY_MODE_WP ((__u64) 1 << 1)
  __u64 mode;
  __s64 copy;
};
struct uffdio_zeropage {
  struct uffdio_range range;
#define UFFDIO_ZEROPAGE_MODE_DONTWAKE ((__u64) 1 << 0)
  __u64 mode;
  __s64 zeropage;
};
struct uffdio_writeprotect {
  struct uffdio_range range;
#define UFFDIO_WRITEPROTECT_MODE_WP ((__u64) 1 << 0)
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE ((__u64) 1 << 1)
  __u64 mode;
};
struct uffdio_continue {
  struct uffdio_range range;
#define UFFDIO_CONTINUE_MODE_DONTWAKE ((__u64) 1 << 0)
#define UFFDIO_CONTINUE_MODE_WP ((__u64) 1 << 1)
  __u64 mode;
  __s64 mapped;
};
struct uffdio_poison {
  struct uffdio_range range;
#define UFFDIO_POISON_MODE_DONTWAKE ((__u64) 1 << 0)
  __u64 mode;
  __s64 updated;
};
struct uffdio_move {
  __u64 dst;
  __u64 src;
  __u64 len;
#define UFFDIO_MOVE_MODE_DONTWAKE ((__u64) 1 << 0)
#define UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES ((__u64) 1 << 1)
  __u64 mode;
  __s64 move;
};
#define UFFD_USER_MODE_ONLY 1
#endif

"""

```