Response:
Let's break down the thought process for analyzing this header file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `fsl_hypervisor.h` header file, specifically within the context of Android's Bionic library. This means focusing on what the file *does*, how it interacts with Android, its implementation details (even though the header doesn't *contain* the implementation), how dynamic linking might be involved, potential errors, and how Android uses it.

**2. Initial Scan and Keyword Identification:**

A quick scan reveals keywords like "hypervisor," "ioctl," "partition," "restart," "status," "start," "stop," "memcpy," "doorbell," and "prop."  These immediately suggest that this header defines structures and constants for interacting with a Freescale (FSL) hypervisor. The "ioctl" keyword is a strong indicator of kernel-level communication.

**3. Functionality Deduction:**

Based on the structure names, I can infer the general purpose of each ioctl command:

* `fsl_hv_ioctl_restart`:  Likely used to restart a partition within the hypervisor.
* `fsl_hv_ioctl_status`: Used to get the status of a partition.
* `fsl_hv_ioctl_start`:  Used to start a partition, potentially with an entry point and load address.
* `fsl_hv_ioctl_stop`:  Used to stop a partition.
* `fsl_hv_ioctl_memcpy`: Used for memory copying between the host and a guest partition.
* `fsl_hv_ioctl_doorbell`:  A mechanism for inter-partition communication, signaling an event.
* `fsl_hv_ioctl_prop`:  Used to get or set properties within the hypervisor environment.

**4. Connecting to Android:**

The crucial connection is understanding *why* Android might need to interact with a hypervisor. The prompt mentions Bionic, which is fundamental to Android. Hypervisors are often used for virtualization and isolation. This leads to the hypothesis that this header is related to Android devices that might be running a hypervisor for various reasons (security, multiple OS instances, etc.).

**5. Implementation Details (Header File Limitation):**

The header file *doesn't* contain the implementation of these functions. It only defines the data structures used to communicate with the kernel driver. Therefore, the explanation of "how each libc function is implemented" needs to clarify this distinction. The corresponding libc functions would likely be wrappers around the `ioctl()` system call.

**6. Dynamic Linking (Likely Indirect):**

While this specific header doesn't directly involve dynamic linking, the context of Bionic means that any code *using* these structures would be part of a larger process that involves dynamic linking. The interaction would happen when an application or system service (dynamically linked) makes the `ioctl()` call.

**7. Hypothetical Input/Output:**

To illustrate how these structures are used, I can create a simple scenario. For example, calling `FSL_HV_IOCTL_PARTITION_START` requires setting the `partition`, `entry_point`, and `load` fields. The kernel would then return a value in the `ret` field.

**8. Common Usage Errors:**

Thinking about how a programmer might misuse these structures brings up potential errors: incorrect partition IDs, invalid addresses, incorrect sizes for `memcpy`, etc. These tie into the importance of understanding the underlying hypervisor documentation.

**9. Android Framework/NDK Usage:**

Tracing the path from the Android Framework/NDK to these low-level kernel structures involves understanding the layers of the Android system. An application might indirectly trigger these ioctls through higher-level APIs related to virtualization or hardware management. The NDK allows direct system call access, making it a more direct path.

**10. Frida Hooking:**

To demonstrate how to observe these interactions, a Frida hook targeting the `ioctl()` system call and filtering for the specific `FSL_HV_IOCTL_TYPE` would be the way to go. The hook would allow inspecting the arguments passed to `ioctl()`.

**11. Structuring the Answer:**

Finally, I organize the information into logical sections as requested by the prompt: Functionality, Android Relationship, Libc Implementation (clarifying the header's role), Dynamic Linking, Logic Inference, Common Errors, and Android Framework/NDK Usage with Frida. This structured approach ensures all aspects of the prompt are addressed clearly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe there are specific libc functions mentioned in the header. **Correction:**  Realized the header only defines structures and macros for ioctl, not the libc functions themselves. The libc part would be the `ioctl()` system call itself and potentially wrapper functions.
* **Initial thought:**  Focus heavily on the dynamic linker aspects directly within this file. **Correction:**  Recognized that the dynamic linking is relevant in the context of *using* this header, not directly defined *by* it. Shifted focus to how a dynamically linked component would use these structures.
* **Consideration:** Should I try to guess the exact purpose of each field? **Decision:** Stick to general interpretations based on the field names and the overall context of a hypervisor. Avoid making overly specific assumptions without more context.

By following this thought process, combining knowledge of operating systems, kernel interactions, Android architecture, and dynamic linking, I can generate a comprehensive and accurate answer to the user's request.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/fsl_hypervisor.handroid` 这个头文件。

**功能列举:**

这个头文件定义了用于与 Freescale (FSL) Hypervisor 交互的ioctl命令和相关的数据结构。它主要提供了以下功能：

1. **分区管理 (Partition Management):**
   - **重启分区 (`FSL_HV_IOCTL_PARTITION_RESTART`):**  允许重启一个指定的 hypervisor 分区。
   - **获取分区状态 (`FSL_HV_IOCTL_PARTITION_GET_STATUS`):** 获取指定 hypervisor 分区的当前状态。
   - **启动分区 (`FSL_HV_IOCTL_PARTITION_START`):**  启动一个指定的 hypervisor 分区，并可以指定入口点和加载地址。
   - **停止分区 (`FSL_HV_IOCTL_PARTITION_STOP`):** 停止一个指定的 hypervisor 分区。

2. **内存操作 (Memory Operation):**
   - **内存拷贝 (`FSL_HV_IOCTL_MEMCPY`):**  允许在宿主机和 hypervisor 分区之间进行内存拷贝。

3. **事件通知 (Event Notification):**
   - **门铃 (`FSL_HV_IOCTL_DOORBELL`):** 提供一种机制，用于向 hypervisor 发送事件通知。

4. **属性管理 (Property Management):**
   - **获取属性 (`FSL_HV_IOCTL_GETPROP`):**  从 hypervisor 获取指定的属性。
   - **设置属性 (`FSL_HV_IOCTL_SETPROP`):**  设置 hypervisor 的指定属性。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android Bionic 库的一部分，这意味着它旨在为 Android 系统提供与特定硬件或虚拟化环境交互的能力。  由于文件名中包含 "fsl_hypervisor"，可以推断出这与使用了 Freescale (NXP) 芯片并运行 hypervisor 的 Android 设备有关。

**举例说明:**

* **系统启动和关机:** Android 系统可能使用 `FSL_HV_IOCTL_PARTITION_RESTART`, `FSL_HV_IOCTL_PARTITION_START`, 和 `FSL_HV_IOCTL_PARTITION_STOP` 来管理在 hypervisor 中运行的不同的 Android 分区或者其他操作系统/环境。 例如，某些车载 Android 系统可能会利用 hypervisor 同时运行信息娱乐系统和仪表盘系统，这些操作可能需要启动、停止或重启对应的分区。

* **资源隔离和安全:** Hypervisor 的存在允许在不同的分区之间进行资源隔离。 Android 系统可能利用 `FSL_HV_IOCTL_MEMCPY` 在安全的环境（hypervisor 控制的 Guest OS）和主系统之间安全地传输数据，避免直接内存访问带来的安全风险。

* **硬件抽象层 (HAL):**  Android 的 HAL 层可能会使用这些 ioctl 命令来与底层的 hypervisor 交互。 例如，一个自定义的 HAL 模块可能需要控制 hypervisor 分区的生命周期或者查询其状态。

* **系统属性:**  `FSL_HV_IOCTL_GETPROP` 和 `FSL_HV_IOCTL_SETPROP`  可能允许 Android 系统或运行在 hypervisor 中的其他环境读取或设置 hypervisor 的配置信息或者状态信息。 这可能用于诊断、监控或配置 hypervisor 的行为。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并没有定义 libc 函数的实现。它定义的是内核层面的接口 (ioctl 命令)。  Android 的 libc (Bionic) 中与这些功能相关的代码，会使用标准的 `ioctl()` 系统调用来与内核驱动进行通信。

**以 `FSL_HV_IOCTL_PARTITION_START` 为例：**

1. **用户空间代码 (例如，Android Framework 或 NDK 开发的应用/服务):**  会调用一个 Bionic 库提供的包装函数，或者直接使用 `ioctl()` 系统调用。
2. **Bionic 库:**  相关的 Bionic 库函数（如果存在）会将用户提供的参数（如分区号、入口点、加载地址）填充到 `struct fsl_hv_ioctl_start` 结构体中。
3. **`ioctl()` 系统调用:**  Bionic 库函数最终会调用 `ioctl()` 系统调用，并将以下参数传递给内核：
   - 文件描述符 (指向与 hypervisor 驱动关联的设备文件，例如 `/dev/fsl_hv`)
   - ioctl 命令码 (`FSL_HV_IOCTL_PARTITION_START`)
   - 指向 `struct fsl_hv_ioctl_start` 结构体的指针。
4. **内核驱动:**  Linux 内核中负责处理 hypervisor 交互的驱动程序会接收到这个 ioctl 调用。驱动程序会解析 `struct fsl_hv_ioctl_start` 中的数据，并执行相应的 hypervisor 操作，例如启动指定的分区。
5. **结果返回:**  hypervisor 操作的结果会写入到 `struct fsl_hv_ioctl_start` 的 `ret` 字段中。内核驱动会将结果返回给用户空间的 `ioctl()` 调用。

**涉及 dynamic linker 的功能、so 布局样本和链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker 的功能。它定义的是内核接口。 然而，任何使用这些 ioctl 命令的用户空间代码都必然会通过动态链接器加载到进程空间中。

**so 布局样本:**

假设有一个名为 `libfslhv.so` 的动态链接库，它封装了对这些 ioctl 命令的调用：

```
libfslhv.so:
    .init          # 初始化段
    .plt           # 程序链接表 (Procedure Linkage Table)
    .text          # 代码段，包含调用 ioctl 的函数
    .rodata        # 只读数据段
    .data          # 数据段
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息
    .symtab        # 符号表
    .strtab        # 字符串表
    ...
```

**链接的处理过程:**

1. **编译时:**  当开发者编译使用 `libfslhv.so` 的应用程序时，编译器会记录下对 `libfslhv.so` 中函数的外部引用。
2. **链接时:**  链接器会将应用程序的目标文件和 `libfslhv.so` 链接在一起。 然而，对于动态链接库，实际的符号解析和地址绑定会延迟到运行时。
3. **运行时:**
   - 当应用程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被调用。
   - dynamic linker 会加载应用程序依赖的所有动态链接库，包括 `libfslhv.so`。
   - dynamic linker 会解析应用程序中对 `libfslhv.so` 中函数的符号引用。 这通常通过查看 `libfslhv.so` 的 `.symtab` 和 `.strtab` 来完成。
   - dynamic linker 会在内存中为 `libfslhv.so` 分配空间，并加载其各个段（`.text`, `.data` 等）。
   - dynamic linker 会修改应用程序的 `.plt` (Procedure Linkage Table)，使其指向 `libfslhv.so` 中对应函数的实际地址。  第一次调用这些函数时，会通过 PLT 跳转到 dynamic linker 的代码，dynamic linker 会找到函数的实际地址并更新 PLT 表项，后续调用将直接跳转到函数地址。

**假设输入与输出 (针对 `FSL_HV_IOCTL_PARTITION_START`):**

**假设输入:**

* 文件描述符 `fd`: 指向 `/dev/fsl_hv` 设备文件的有效文件描述符。
* `partition`:  要启动的分区 ID，例如 `1`。
* `entry_point`:  分区的入口点地址，例如 `0x10000000`。
* `load`: 分区的加载地址，例如 `0x20000000`。

**对应的 `struct fsl_hv_ioctl_start` 结构体内容:**

```c
struct fsl_hv_ioctl_start start_args;
start_args.ret = 0; // 初始值通常为 0
start_args.partition = 1;
start_args.entry_point = 0x10000000;
start_args.load = 0x20000000;
```

**假设输出 (ioctl 返回值):**

* 如果启动成功，`ioctl()` 系统调用可能返回 `0`，并且 `start_args.ret` 字段可能被内核设置为表示成功的特定值（但这通常不作为主要返回值，`ioctl` 的返回值更重要）。
* 如果启动失败，`ioctl()` 系统调用可能返回 `-1`，并且 `errno` 会被设置为相应的错误码（例如 `EPERM` 表示权限不足，`EINVAL` 表示参数无效等）。 `start_args.ret` 字段可能会包含内核定义的错误码。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **无效的文件描述符:**  在调用 `ioctl()` 之前，没有正确打开与 hypervisor 驱动关联的设备文件（例如 `/dev/fsl_hv`）。这会导致 `ioctl()` 调用失败，并返回 `-1`，`errno` 通常设置为 `EBADF` (Bad file descriptor)。

   ```c
   int fd = open("/dev/fsl_hv", O_RDWR);
   if (fd < 0) {
       perror("open /dev/fsl_hv failed");
       return -1;
   }
   // ... 后续调用 ioctl ...
   close(fd);
   ```

2. **错误的 ioctl 命令码:**  使用了错误的宏定义，例如将 `FSL_HV_IOCTL_PARTITION_START` 误写为其他值。 这会导致 `ioctl()` 调用失败，并返回 `-1`，`errno` 通常设置为 `EINVAL` (Invalid argument)。

3. **传递了无效的参数:**  例如，传递了一个不存在的分区 ID，或者入口点和加载地址超出了允许的范围。 内核驱动会检查这些参数的有效性，如果无效，`ioctl()` 会返回错误，`errno` 可能是 `EINVAL`。

   ```c
   struct fsl_hv_ioctl_start start_args;
   start_args.partition = 999; // 假设分区 999 不存在
   // ... 调用 ioctl ...
   if (ioctl(fd, FSL_HV_IOCTL_PARTITION_START, &start_args) < 0) {
       perror("ioctl FSL_HV_IOCTL_PARTITION_START failed");
       // 检查 errno
   }
   ```

4. **权限问题:**  调用 `ioctl()` 的进程可能没有足够的权限执行相关的 hypervisor 操作。 这会导致 `ioctl()` 调用失败，并返回 `-1`，`errno` 通常设置为 `EPERM` (Operation not permitted)。

5. **数据结构填充错误:**  在填充 ioctl 命令相关的数据结构时，字段赋值错误或者遗漏赋值。 例如，忘记设置 `partition` 字段的值。 这可能导致内核驱动解析数据失败，从而导致 `ioctl()` 返回错误。

6. **竞态条件:**  在多线程或多进程环境中，如果没有适当的同步机制，多个进程或线程可能同时尝试操作 hypervisor，导致状态不一致或操作失败。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤 (理论上的路径，实际可能更复杂):**

1. **Android Framework (Java 层):** 某个系统服务或应用程序可能需要与 hypervisor 进行交互。 这可能通过调用 Android 系统 API 完成，例如，如果存在与虚拟化或特定硬件管理相关的 API。
2. **System Server (Java 层):**  Framework 的 API 调用通常会传递到 System Server 中的某个服务。
3. **Native 代码 (C++/JNI):** System Server 中的服务可能会通过 JNI (Java Native Interface) 调用 Native 代码来实现与底层硬件或内核的交互。
4. **HAL (Hardware Abstraction Layer):**  Native 代码可能会调用特定的 HAL 模块。 针对 Freescale hypervisor，可能会有一个自定义的 HAL 模块负责处理这些操作。
5. **Bionic 库和 ioctl 系统调用:** HAL 模块会使用 Bionic 库提供的函数，最终调用 `ioctl()` 系统调用，并传递相应的 ioctl 命令码和数据结构（如本文件定义的）。
6. **Linux 内核驱动:**  内核中的 hypervisor 驱动程序接收并处理 `ioctl()` 调用。

**NDK 到达这里的步骤:**

1. **NDK 应用 (C/C++):**  使用 NDK 开发的应用程序可以直接调用 Bionic 库提供的函数，包括 `ioctl()`。
2. **Bionic 库和 ioctl 系统调用:**  NDK 应用可以直接调用 `ioctl()` 函数，并传递相应的参数，直接与内核驱动进行交互。

**Frida Hook 示例调试这些步骤:**

我们可以使用 Frida hook `ioctl` 系统调用，并过滤出与 `FSL_HV_IOCTL_TYPE` 相关的调用，以观察参数和返回值。

```python
import frida
import sys

# 要 hook 的设备文件路径 (假设)
device_path = "/dev/fsl_hv"

# FSL_HV_IOCTL_TYPE 的值
FSL_HV_IOCTL_TYPE = 0xAF

# ioctl 命令码
FSL_HV_IOCTL_PARTITION_RESTART = (ord('r') << _IOC_TYPEBITS) | (FSL_HV_IOCTL_TYPE << _IOC_NRBITS) | (1 << _IOC_SIZEBITS) | _IOC_READ|_IOC_WRITE
FSL_HV_IOCTL_PARTITION_GET_STATUS = (ord('r') << _IOC_TYPEBITS) | (FSL_HV_IOCTL_TYPE << _IOC_NRBITS) | (2 << _IOC_SIZEBITS) | _IOC_READ|_IOC_WRITE
FSL_HV_IOCTL_PARTITION_START = (ord('r') << _IOC_TYPEBITS) | (FSL_HV_IOCTL_TYPE << _IOC_NRBITS) | (3 << _IOC_SIZEBITS) | _IOC_READ|_IOC_WRITE
FSL_HV_IOCTL_PARTITION_STOP = (ord('r') << _IOC_TYPEBITS) | (FSL_HV_IOCTL_TYPE << _IOC_NRBITS) | (4 << _IOC_SIZEBITS) | _IOC_READ|_IOC_WRITE
FSL_HV_IOCTL_MEMCPY = (ord('r') << _IOC_TYPEBITS) | (FSL_HV_IOCTL_TYPE << _IOC_NRBITS) | (5 << _IOC_SIZEBITS) | _IOC_READ|_IOC_WRITE
FSL_HV_IOCTL_DOORBELL = (ord('r') << _IOC_TYPEBITS) | (FSL_HV_IOCTL_TYPE << _IOC_NRBITS) | (6 << _IOC_SIZEBITS) | _IOC_READ|_IOC_WRITE
FSL_HV_IOCTL_GETPROP = (ord('r') << _IOC_TYPEBITS) | (FSL_HV_IOCTL_TYPE << _IOC_NRBITS) | (7 << _IOC_SIZEBITS) | _IOC_READ|_IOC_WRITE
FSL_HV_IOCTL_SETPROP = (ord('r') << _IOC_TYPEBITS) | (FSL_HV_IOCTL_TYPE << _IOC_NRBITS) | (8 << _IOC_SIZEBITS) | _IOC_READ|_IOC_WRITE

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 检查是否是与 fsl_hypervisor 相关的 ioctl 调用
        if ((request >> 8) & 0xff == %d) {
            console.log("ioctl called with fd:", fd, "request:", request);
            this.request = request;

            // 根据不同的 ioctl 命令码，解析参数 (需要根据结构体定义进行解析)
            if (request == %d) {
                console.log("  FSL_HV_IOCTL_PARTITION_START");
                const argp = ptr(args[2]);
                console.log("    ret:", argp.readU32());
                console.log("    partition:", argp.add(4).readU32());
                console.log("    entry_point:", argp.add(8).readU32());
                console.log("    load:", argp.add(12).readU32());
            } else if (request == %d) {
                console.log("  FSL_HV_IOCTL_PARTITION_GET_STATUS");
                const argp = ptr(args[2]);
                console.log("    ret:", argp.readU32());
                console.log("    partition:", argp.add(4).readU32());
                console.log("    status:", argp.add(8).readU32());
            }
            // ... 可以添加其他 ioctl 命令的处理 ...
        }
    },
    onLeave: function(retval) {
        if (this.request) {
            console.log("ioctl returned:", retval);
            this.request = null;
        }
    }
});
""" % (FSL_HV_IOCTL_TYPE, FSL_HV_IOCTL_PARTITION_START, FSL_HV_IOCTL_PARTITION_GET_STATUS)

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    # 连接到 Android 设备或模拟器
    session = frida.get_usb_device().attach(sys.argv[1])
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, press Ctrl+C to exit")
    sys.stdin.read()
except frida.ServerNotRunningError:
    print("Frida server is not running on the target device.")
except frida.USBDeviceNotFoundError:
    print("Android device not found.")
except frida.ProcessNotFoundError:
    print(f"Process '{sys.argv[1]}' not found.")
except KeyboardInterrupt:
    print("Exiting...")

```

**使用方法:**

1. 将上述 Python 代码保存为 `hook_fsl_hv.py`。
2. 确保你的 Android 设备已连接并通过 USB 调试。
3. 确保 Frida server 正在目标 Android 设备上运行。
4. 运行命令： `python hook_fsl_hv.py <目标进程名称或 PID>`  将 `<目标进程名称或 PID>` 替换为你想要监控的进程的名称（例如 `system_server`）或 PID。

**Frida Hook 的作用:**

这个 Frida 脚本会 hook `ioctl` 系统调用。当有进程调用 `ioctl` 时，脚本会检查 `ioctl` 命令码是否与 `FSL_HV_IOCTL_TYPE` 匹配。如果匹配，它会打印出相关的参数信息，帮助你追踪哪些进程正在与 hypervisor 驱动进行交互，以及传递了哪些参数。

**总结:**

`bionic/libc/kernel/uapi/linux/fsl_hypervisor.handroid` 头文件定义了与 Freescale hypervisor 交互的内核接口。Android 系统通过 Bionic 库提供的 `ioctl` 系统调用，以及可能的 HAL 层封装，来使用这些接口管理 hypervisor 分区、进行内存操作、发送事件通知和管理属性。 理解这些接口对于分析和调试基于 Freescale hypervisor 的 Android 系统至关重要。 使用 Frida 可以动态地观察这些底层的系统调用，帮助我们理解 Android Framework 或 NDK 应用是如何与 hypervisor 进行交互的。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/fsl_hypervisor.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPIFSL_HYPERVISOR_H
#define _UAPIFSL_HYPERVISOR_H
#include <linux/types.h>
struct fsl_hv_ioctl_restart {
  __u32 ret;
  __u32 partition;
};
struct fsl_hv_ioctl_status {
  __u32 ret;
  __u32 partition;
  __u32 status;
};
struct fsl_hv_ioctl_start {
  __u32 ret;
  __u32 partition;
  __u32 entry_point;
  __u32 load;
};
struct fsl_hv_ioctl_stop {
  __u32 ret;
  __u32 partition;
};
struct fsl_hv_ioctl_memcpy {
  __u32 ret;
  __u32 source;
  __u32 target;
  __u32 reserved;
  __u64 local_vaddr;
  __u64 remote_paddr;
  __u64 count;
};
struct fsl_hv_ioctl_doorbell {
  __u32 ret;
  __u32 doorbell;
};
struct fsl_hv_ioctl_prop {
  __u32 ret;
  __u32 handle;
  __u64 path;
  __u64 propname;
  __u64 propval;
  __u32 proplen;
  __u32 reserved;
};
#define FSL_HV_IOCTL_TYPE 0xAF
#define FSL_HV_IOCTL_PARTITION_RESTART _IOWR(FSL_HV_IOCTL_TYPE, 1, struct fsl_hv_ioctl_restart)
#define FSL_HV_IOCTL_PARTITION_GET_STATUS _IOWR(FSL_HV_IOCTL_TYPE, 2, struct fsl_hv_ioctl_status)
#define FSL_HV_IOCTL_PARTITION_START _IOWR(FSL_HV_IOCTL_TYPE, 3, struct fsl_hv_ioctl_start)
#define FSL_HV_IOCTL_PARTITION_STOP _IOWR(FSL_HV_IOCTL_TYPE, 4, struct fsl_hv_ioctl_stop)
#define FSL_HV_IOCTL_MEMCPY _IOWR(FSL_HV_IOCTL_TYPE, 5, struct fsl_hv_ioctl_memcpy)
#define FSL_HV_IOCTL_DOORBELL _IOWR(FSL_HV_IOCTL_TYPE, 6, struct fsl_hv_ioctl_doorbell)
#define FSL_HV_IOCTL_GETPROP _IOWR(FSL_HV_IOCTL_TYPE, 7, struct fsl_hv_ioctl_prop)
#define FSL_HV_IOCTL_SETPROP _IOWR(FSL_HV_IOCTL_TYPE, 8, struct fsl_hv_ioctl_prop)
#endif

"""

```