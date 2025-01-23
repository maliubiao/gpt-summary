Response:
Let's break down the thought process to answer the user's request about the `cxl.h` header file.

**1. Understanding the Request:**

The user wants to understand the functionality of the `cxl.h` file, its relation to Android, detailed explanations of libc functions (although this file doesn't define any libc functions directly, the request is important to address conceptually), the role of the dynamic linker (if applicable), examples of usage errors, and how it's reached from the Android framework/NDK, culminating in a Frida hook example. The key is to dissect the header file itself and infer its purpose.

**2. Analyzing the Header File:**

* **`#ifndef _UAPI_MISC_CXL_H` / `#define _UAPI_MISC_CXL_H`:**  This is a standard header guard, preventing multiple inclusions. It doesn't offer direct functional insights but is good to note.

* **`#include <linux/types.h>` / `#include <linux/ioctl.h>`:** These includes are crucial. They tell us this header is related to the Linux kernel's interface. `linux/types.h` provides basic data types (`__u64`, `__u32`, etc.), and `linux/ioctl.h` is essential for defining ioctl commands. This immediately suggests this file is for interacting with a kernel driver.

* **`struct cxl_ioctl_start_work`:** This structure and the associated `#define CXL_START_WORK_*` macros clearly define the data structure used for a specific ioctl command, likely to initiate some work related to CXL. The flags indicate different options or parameters for this work.

* **`struct cxl_afu_id`:** This structure seems to identify a specific Accelerator Functional Unit (AFU), likely a hardware component. The fields like `card_id`, `afu_offset`, and `afu_mode` point towards this interpretation. The `CXL_AFUID_FLAG_SLAVE` suggests different roles for AFUs.

* **`struct cxl_adapter_image`:**  The names `image`, `data`, and `len` strongly suggest this structure is used to transfer firmware or configuration data to a CXL adapter.

* **`#define CXL_MAGIC 0xCA`:** This is the magic number used to identify CXL-specific ioctl commands.

* **`#define CXL_IOCTL_*`:** These macros define the specific ioctl commands using the `_IOW` and `_IOR` macros from `linux/ioctl.h`. This confirms the interaction with a kernel driver via ioctl.

* **`enum cxl_event_type`:**  This enumeration defines different types of events that the CXL driver can report back to the user space.

* **`struct cxl_event_header`` and subsequent `cxl_event_*` structures:** These define the structure of event data, including a header and different payload types depending on the event.

**3. Inferring Functionality:**

Based on the structures and ioctl definitions, we can infer the following core functionalities:

* **Starting Work on a CXL device:**  `CXL_IOCTL_START_WORK` and `struct cxl_ioctl_start_work`.
* **Getting Process Element Information:** `CXL_IOCTL_GET_PROCESS_ELEMENT`.
* **Getting AFU Identification:** `CXL_IOCTL_GET_AFU_ID` and `struct cxl_afu_id`.
* **Downloading/Validating Adapter Images (Firmware):** `CXL_IOCTL_DOWNLOAD_IMAGE`, `CXL_IOCTL_VALIDATE_IMAGE`, and `struct cxl_adapter_image`.
* **Receiving Events from the CXL device:** `enum cxl_event_type` and `struct cxl_event`.

**4. Connecting to Android:**

The file resides within Bionic's kernel UAPI (User API) directory. This means it's a header file copied from the Linux kernel specifically for use by Android's user-space components. The CXL functionality likely interacts with specific hardware that Android devices *might* have (though it's not a universally present feature). The key link is the use of ioctl, which is a standard Linux system call and thus available in Android.

**5. Addressing Other Parts of the Request:**

* **libc functions:** This header *defines* structures and constants, it doesn't implement libc functions. The *use* of these definitions would involve libc functions like `open()`, `ioctl()`, and `read()`.
* **Dynamic Linker:** This header file itself isn't directly involved in dynamic linking. However, libraries using this header would be subject to the dynamic linker's processes.
* **Usage Errors:**  Focus on incorrect usage of the ioctl calls, such as wrong arguments, insufficient permissions, or incorrect sequencing of operations.
* **Android Framework/NDK:**  Trace the path from higher-level Android APIs (if they exist for CXL - which is unlikely given its specialized nature) down to the kernel level, emphasizing the role of system calls.
* **Frida Hook:**  Demonstrate how to intercept the `ioctl` calls related to CXL.

**6. Structuring the Answer:**

Organize the information logically, following the user's request structure:

* **Functionality:** List the identified functionalities.
* **Android Relation:** Explain the location within Bionic and the use of ioctl. Give a hypothetical example (even if CXL isn't widely used in Android).
* **libc Functions:** Explain that this file *defines* data used *by* libc functions like `ioctl`. Describe the general mechanism of `ioctl`.
* **Dynamic Linker:** Explain that while the header isn't directly linked, libraries using it are. Provide a basic SO layout and describe the linking process in general terms.
* **Logical Reasoning:**  Provide a simple scenario (e.g., starting a work element) and describe the input and expected outcome.
* **Usage Errors:** Give concrete examples of common mistakes when using ioctl with these structures.
* **Android Framework/NDK Path:** Describe the general flow from application to kernel using system calls, even if a specific high-level CXL API doesn't exist in Android.
* **Frida Hook:** Provide a practical Frida script example targeting the `ioctl` system call and filtering for CXL commands.

**7. Refinement and Language:**

Use clear and concise Chinese. Explain technical terms. Ensure the answer addresses all parts of the user's request. Acknowledge limitations or assumptions (e.g., CXL's limited presence in typical Android devices).

By following this thought process, combining detailed analysis of the header file with an understanding of Linux kernel interfaces and Android's architecture, we can generate a comprehensive and accurate answer to the user's request.
这个 `bionic/libc/kernel/uapi/misc/cxl.handroid` 目录下的 `cxl.h` 文件定义了用于与 CXL (Compute Express Link) 设备进行交互的用户空间接口。CXL 是一种高速互连技术，旨在加速 CPU 和各种加速器（例如 GPU、FPGA 和其他专用加速器）之间的数据传输。 由于它位于 `bionic/libc/kernel/uapi` 目录下，这意味着它是由 Linux 内核的头文件自动生成的，目的是为了在 Android 的用户空间代码中与 CXL 驱动程序进行交互。

**功能列举:**

这个头文件主要定义了以下功能相关的结构体、宏和枚举：

1. **ioctl 命令定义:**  定义了与 CXL 设备驱动程序通信的 ioctl 命令，允许用户空间程序控制和管理 CXL 设备。
2. **数据结构定义:** 定义了用于传递给 ioctl 命令以及从 ioctl 命令接收的数据结构，这些结构体描述了 CXL 设备的状态、配置和操作参数。
3. **常量定义:** 定义了与 CXL 设备操作相关的常量，例如标志位、模式值、魔术字等。
4. **事件类型定义:** 定义了 CXL 设备可能产生的事件类型，用于异步通知用户空间应用程序。

**与 Android 功能的关系及举例:**

CXL 技术虽然相对较新，但其目标是提高异构计算的效率，这与 Android 的发展方向（例如，利用 GPU 进行图形渲染和机器学习加速）是一致的。然而，**目前来看，CXL 技术在主流 Android 设备上并不常见。**  这个头文件更可能是为了支持一些特定的、面向高性能计算或数据中心应用的 Android 设备或定制化场景。

**举例说明（假设 Android 设备支持 CXL）：**

假设一个 Android 设备配备了支持 CXL 的加速器。  一个用户空间应用程序可能需要与这个加速器进行交互，以执行某些计算密集型任务。该应用程序会使用这里定义的 ioctl 命令和数据结构来：

* **启动工作 (CXL_IOCTL_START_WORK):**  应用程序可以填充 `cxl_ioctl_start_work` 结构体，指定要执行的工作描述符、中断配置等信息，然后通过 ioctl 系统调用发送给 CXL 驱动程序，以启动加速器上的计算任务。
* **获取 AFU ID (CXL_IOCTL_GET_AFU_ID):** 应用程序可以调用 `CXL_IOCTL_GET_AFU_ID` 来获取连接的 CXL 加速功能单元 (AFU) 的标识信息，例如卡 ID、AFU 偏移、模式等。
* **下载镜像 (CXL_IOCTL_DOWNLOAD_IMAGE):**  应用程序可能需要将固件或配置数据下载到 CXL 适配器，这可以通过填充 `cxl_adapter_image` 结构体并使用 `CXL_IOCTL_DOWNLOAD_IMAGE` 完成。
* **监听事件:** 应用程序可以通过某种机制（通常是轮询或通过文件描述符接收通知）来监听 CXL 驱动程序发出的事件，例如 AFU 中断、数据存储事件或错误事件。`cxl_event` 结构体定义了这些事件的格式。

**libc 函数的功能实现:**

这个头文件本身 **并没有实现任何 libc 函数**。它只是定义了数据结构和常量。  用户空间程序要使用这些定义与内核驱动进行交互，需要使用标准的 libc 函数，例如：

* **`open()`:**  打开 CXL 设备文件（通常位于 `/dev` 目录下，例如 `/dev/cxl0`）。
* **`ioctl()`:**  核心函数，用于向打开的设备文件发送控制命令。应用程序会填充与特定 ioctl 命令相关的结构体，并将其作为参数传递给 `ioctl()`。内核驱动程序会根据 ioctl 命令和传递的数据执行相应的操作。
* **`read()`/`write()` (可能):**  在某些情况下，可能需要使用 `read()` 或 `write()` 函数来与 CXL 设备进行数据传输，但这取决于具体的驱动程序实现和 CXL 设备的功能。
* **`close()`:**  关闭打开的 CXL 设备文件。

**详细解释 `ioctl()` 的功能实现:**

`ioctl()` (input/output control) 是一个系统调用，允许用户空间程序向设备驱动程序发送设备特定的控制命令和数据。它的工作流程如下：

1. **用户空间调用 `ioctl()`:** 应用程序调用 `ioctl()` 函数，并传递以下参数：
   * `fd`:  通过 `open()` 系统调用获得的设备文件描述符。
   * `request`:  一个与特定设备操作相关的请求码，通常由宏定义（如 `CXL_IOCTL_START_WORK`）。这个请求码唯一标识了要执行的操作。
   * `...`:  可选的参数，通常是一个指向数据结构的指针，该结构体包含了传递给驱动程序的数据或用于接收驱动程序返回的数据。

2. **内核处理 `ioctl()` 调用:**
   * 内核接收到 `ioctl()` 系统调用。
   * 内核根据文件描述符 `fd` 找到对应的设备驱动程序。
   * 内核将 `request` 码传递给驱动程序的 `ioctl` 函数处理例程。

3. **驱动程序处理:**
   * 设备驱动程序的 `ioctl` 函数接收到请求码和用户空间传递的数据指针。
   * 驱动程序根据 `request` 码执行相应的操作。例如，对于 `CXL_IOCTL_START_WORK`，驱动程序可能会解析 `cxl_ioctl_start_work` 结构体中的参数，然后配置 CXL 硬件启动工作。
   * 驱动程序可能会修改用户空间传递的数据结构（如果 ioctl 是用来获取信息的），或者返回一个状态码。

4. **内核返回:**
   * 内核将驱动程序的返回值传递给用户空间的 `ioctl()` 函数。

**涉及 dynamic linker 的功能 (本例中不直接涉及):**

这个头文件本身不涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载和链接程序依赖的共享库 (`.so` 文件)。

如果用户空间程序需要使用一个专门的库来与 CXL 设备交互（虽然目前可能不存在这样的标准库），那么 dynamic linker 会参与这个库的加载和链接过程。

**SO 布局样本 (假设存在 CXL 交互库):**

```
# 应用程序可执行文件 (例如: my_cxl_app)
├── libmycxl.so  # 假设的 CXL 交互库
│   ├── .so_header
│   ├── .plt       # Procedure Linkage Table
│   ├── .got.plt   # Global Offset Table (for PLT)
│   ├── .text      # 代码段 (包含与 CXL 交互的函数实现)
│   ├── .rodata    # 只读数据段
│   ├── .data      # 已初始化数据段
│   ├── .bss       # 未初始化数据段
│   ├── ...       # 其他段
├── ...

# 其他共享库 (例如 libc.so, liblog.so)
```

**链接的处理过程 (假设存在 CXL 交互库):**

1. **编译时:** 编译器会将应用程序代码和对 `libmycxl.so` 中 CXL 相关函数的调用链接起来。链接器会在应用程序的可执行文件中生成对 `libmycxl.so` 中函数的未解析引用，并在 PLT 和 GOT 中创建相应的条目。

2. **加载时:** 当应用程序启动时，dynamic linker 会：
   * 加载应用程序的可执行文件到内存。
   * 解析应用程序依赖的共享库，包括 `libmycxl.so`。
   * 将 `libmycxl.so` 加载到内存中。
   * **重定位:**  调整应用程序和 `libmycxl.so` 中的地址，因为它们被加载到内存中的具体位置在运行时才能确定。这包括更新 GOT 中的条目，使其指向 `libmycxl.so` 中函数的实际地址。
   * **符号解析:**  将应用程序中对 `libmycxl.so` 函数的未解析引用与 `libmycxl.so` 中导出的符号表进行匹配，并将 GOT 条目指向正确的函数地址。

**逻辑推理、假设输入与输出 (以 `CXL_IOCTL_START_WORK` 为例):**

**假设输入:**

* 打开 CXL 设备文件描述符 `fd`。
* 一个填充好的 `cxl_ioctl_start_work` 结构体 `start_work_data`:
    * `flags`:  `CXL_START_WORK_AMR | CXL_START_WORK_NUM_IRQS` (例如，指定使用 AMR 和中断数量)
    * `work_element_descriptor`:  指向描述要执行的工作的内存地址 (假设为 `0x1000`)
    * `amr`:  某些 AMR 相关的值 (例如 `0x0001`)
    * `num_interrupts`:  期望的中断数量 (例如 `2`)
    * 其他字段设置为适当的值。

**系统调用:**

```c
#include <sys/ioctl.h>
#include "cxl.h" // 假设头文件路径正确

// ...

int fd = open("/dev/cxl0", O_RDWR);
if (fd < 0) {
    perror("open");
    // 处理错误
}

struct cxl_ioctl_start_work start_work_data = {
    .flags = CXL_START_WORK_AMR | CXL_START_WORK_NUM_IRQS,
    .work_element_descriptor = 0x1000,
    .amr = 0x0001,
    .num_interrupts = 2,
    // ... 其他字段
};

int ret = ioctl(fd, CXL_IOCTL_START_WORK, &start_work_data);
if (ret < 0) {
    perror("ioctl CXL_IOCTL_START_WORK");
    // 处理错误
} else {
    // 工作启动成功
}

close(fd);
```

**预期输出:**

* 如果 `ioctl` 调用成功，`ret` 的值应该为 0 或一个表示成功的正数（取决于驱动程序的实现）。
* CXL 驱动程序会接收到 `CXL_IOCTL_START_WORK` 命令和 `start_work_data` 中的参数。
* 驱动程序会根据 `start_work_data` 中的信息配置 CXL 硬件，启动在地址 `0x1000` 描述的工作。
* 如果设置了中断，CXL 设备在完成工作后可能会触发指定数量的中断。

**用户或编程常见的使用错误:**

1. **未打开设备文件:**  在调用 `ioctl` 之前，必须先使用 `open()` 函数打开 CXL 设备文件。
2. **使用了错误的 ioctl 命令码:**  传递给 `ioctl()` 的 `request` 参数必须是头文件中定义的正确的 CXL ioctl 命令码。
3. **传递了不正确的参数结构体:**  `ioctl()` 的第三个参数必须是指向与特定 ioctl 命令码相匹配的结构体的指针。例如，对于 `CXL_IOCTL_START_WORK`，必须传递 `struct cxl_ioctl_start_work` 的指针。
4. **结构体字段未正确初始化:**  结构体中的字段必须根据驱动程序的要求进行正确的初始化。例如，`flags` 字段需要设置正确的标志位。
5. **权限不足:**  用户可能没有足够的权限访问 CXL 设备文件，导致 `open()` 或 `ioctl()` 调用失败。
6. **设备文件不存在:**  如果 CXL 驱动程序没有正确加载或设备没有被识别，`/dev/cxl0` 等设备文件可能不存在。
7. **在错误的设备文件上调用 ioctl:**  确保在正确的 CXL 设备文件描述符上调用 ioctl。
8. **并发问题:**  如果多个进程或线程同时尝试访问和控制 CXL 设备，可能会导致冲突。需要使用适当的同步机制（例如互斥锁）。
9. **假设 CXL 设备始终存在:** 代码需要处理 CXL 设备不存在或驱动程序未加载的情况。

**Android Framework 或 NDK 如何一步步到达这里:**

由于 CXL 目前在主流 Android 设备上不常见，Android Framework 和 NDK 并没有提供直接的、高级的 CXL API。要使用这里定义的接口，通常需要通过 NDK 进行底层编程，直接调用 libc 的系统调用。

**步骤：**

1. **NDK 开发:**  开发者需要使用 Android NDK (Native Development Kit) 来编写 C/C++ 代码。
2. **包含头文件:**  在 C/C++ 代码中包含 `bionic/libc/kernel/uapi/misc/cxl.h` 头文件。
3. **打开设备文件:** 使用 `open()` 系统调用打开 CXL 设备文件 (例如 `/dev/cxl0`)。
4. **填充数据结构:**  根据需要执行的操作，填充相应的 `cxl_*` 结构体。
5. **调用 `ioctl()`:**  使用 `ioctl()` 系统调用，传入设备文件描述符、CXL ioctl 命令码和指向数据结构的指针。
6. **处理返回值:**  检查 `ioctl()` 的返回值，以确定操作是否成功，并处理可能的错误。
7. **关闭设备文件:**  使用 `close()` 关闭设备文件。

**Frida Hook 示例调试这些步骤:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与 CXL 相关的 ioctl 命令，以观察和修改应用程序与 CXL 驱动程序的交互。

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
        print("Usage: python frida_cxl_hook.py <process name or PID>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            // 定义 CXL 魔术字 (从 cxl.h 中获取)
            const CXL_MAGIC = 0xCA;

            // 提取 ioctl 命令的组号 (magic number)
            const group = (request >> 8) & 0xFF;

            if (group === CXL_MAGIC) {
                console.log("[-] ioctl called with CXL command:");
                console.log("    fd:", fd);
                console.log("    request:", request, "(0x" + request.toString(16) + ")");

                // 可以进一步解析 request 来确定具体的 CXL_IOCTL_* 命令
                if (request === 0xC0084300) { // 假设 CXL_IOCTL_START_WORK 的值为 0xC0084300，需要根据实际情况修改
                    console.log("    Command: CXL_IOCTL_START_WORK");
                    // 可以读取 args[2] 指向的内存，解析 cxl_ioctl_start_work 结构体
                } else if (request === 0xC0044302) { // 假设 CXL_IOCTL_GET_AFU_ID 的值
                    console.log("    Command: CXL_IOCTL_GET_AFU_ID");
                }
                // ... 其他 CXL ioctl 命令

                // 如果需要修改参数，可以在这里进行操作
                // 例如: Memory.writeU64(ptr(args[2]).add(8), 0xnew_value);
            }
        },
        onLeave: function(retval) {
            if (this.group === CXL_MAGIC) {
                console.log("[-] ioctl returned:", retval.toInt32());
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to exit.")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将上述 Python 代码保存为 `frida_cxl_hook.py`。
2. 运行目标 Android 应用程序或指定其进程 PID。
3. 运行 Frida hook 脚本：`python frida_cxl_hook.py <应用程序名称或 PID>`
4. 当目标应用程序调用与 CXL 相关的 `ioctl` 时，Frida 脚本会在终端输出相关信息，包括文件描述符、ioctl 请求码和可能的命令类型。

这个 Frida 示例可以帮助你观察应用程序如何使用 CXL 相关的 ioctl 命令，以及传递的参数。你可以根据需要扩展脚本来解析和显示更详细的结构体内容，或者修改参数来测试不同的场景。

**总结:**

`bionic/libc/kernel/uapi/misc/cxl.handroid/cxl.h` 定义了与 CXL 设备交互的底层接口。虽然 CXL 目前在主流 Android 设备上不常见，但理解这个头文件有助于理解 Android 系统如何与硬件加速器进行交互，以及如何使用底层的系统调用和驱动程序接口。 使用 Frida 可以有效地调试和分析涉及这些接口的应用程序行为。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/misc/cxl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_MISC_CXL_H
#define _UAPI_MISC_CXL_H
#include <linux/types.h>
#include <linux/ioctl.h>
struct cxl_ioctl_start_work {
  __u64 flags;
  __u64 work_element_descriptor;
  __u64 amr;
  __s16 num_interrupts;
  __u16 tid;
  __s32 reserved1;
  __u64 reserved2;
  __u64 reserved3;
  __u64 reserved4;
  __u64 reserved5;
};
#define CXL_START_WORK_AMR 0x0000000000000001ULL
#define CXL_START_WORK_NUM_IRQS 0x0000000000000002ULL
#define CXL_START_WORK_ERR_FF 0x0000000000000004ULL
#define CXL_START_WORK_TID 0x0000000000000008ULL
#define CXL_START_WORK_ALL (CXL_START_WORK_AMR | CXL_START_WORK_NUM_IRQS | CXL_START_WORK_ERR_FF | CXL_START_WORK_TID)
#define CXL_MODE_DEDICATED 0x1
#define CXL_MODE_DIRECTED 0x2
#define CXL_AFUID_FLAG_SLAVE 0x1
struct cxl_afu_id {
  __u64 flags;
  __u32 card_id;
  __u32 afu_offset;
  __u32 afu_mode;
  __u32 reserved1;
  __u64 reserved2;
  __u64 reserved3;
  __u64 reserved4;
  __u64 reserved5;
  __u64 reserved6;
};
#define CXL_AI_NEED_HEADER 0x0000000000000001ULL
#define CXL_AI_ALL CXL_AI_NEED_HEADER
#define CXL_AI_HEADER_SIZE 128
#define CXL_AI_BUFFER_SIZE 4096
#define CXL_AI_MAX_ENTRIES 256
#define CXL_AI_MAX_CHUNK_SIZE (CXL_AI_BUFFER_SIZE * CXL_AI_MAX_ENTRIES)
struct cxl_adapter_image {
  __u64 flags;
  __u64 data;
  __u64 len_data;
  __u64 len_image;
  __u64 reserved1;
  __u64 reserved2;
  __u64 reserved3;
  __u64 reserved4;
};
#define CXL_MAGIC 0xCA
#define CXL_IOCTL_START_WORK _IOW(CXL_MAGIC, 0x00, struct cxl_ioctl_start_work)
#define CXL_IOCTL_GET_PROCESS_ELEMENT _IOR(CXL_MAGIC, 0x01, __u32)
#define CXL_IOCTL_GET_AFU_ID _IOR(CXL_MAGIC, 0x02, struct cxl_afu_id)
#define CXL_IOCTL_DOWNLOAD_IMAGE _IOW(CXL_MAGIC, 0x0A, struct cxl_adapter_image)
#define CXL_IOCTL_VALIDATE_IMAGE _IOW(CXL_MAGIC, 0x0B, struct cxl_adapter_image)
#define CXL_READ_MIN_SIZE 0x1000
enum cxl_event_type {
  CXL_EVENT_RESERVED = 0,
  CXL_EVENT_AFU_INTERRUPT = 1,
  CXL_EVENT_DATA_STORAGE = 2,
  CXL_EVENT_AFU_ERROR = 3,
  CXL_EVENT_AFU_DRIVER = 4,
};
struct cxl_event_header {
  __u16 type;
  __u16 size;
  __u16 process_element;
  __u16 reserved1;
};
struct cxl_event_afu_interrupt {
  __u16 flags;
  __u16 irq;
  __u32 reserved1;
};
struct cxl_event_data_storage {
  __u16 flags;
  __u16 reserved1;
  __u32 reserved2;
  __u64 addr;
  __u64 dsisr;
  __u64 reserved3;
};
struct cxl_event_afu_error {
  __u16 flags;
  __u16 reserved1;
  __u32 reserved2;
  __u64 error;
};
struct cxl_event_afu_driver_reserved {
  __u32 data_size;
  __u8 data[];
};
struct cxl_event {
  struct cxl_event_header header;
  union {
    struct cxl_event_afu_interrupt irq;
    struct cxl_event_data_storage fault;
    struct cxl_event_afu_error afu_error;
    struct cxl_event_afu_driver_reserved afu_driver_event;
  };
};
#endif
```