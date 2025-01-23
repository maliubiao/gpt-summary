Response:
Let's break down the thought process for analyzing this header file.

**1. Understanding the Context:**

The first crucial step is recognizing the context: `bionic/libc/kernel/uapi/linux/virtio_iommu.h`. This tells us several things:

* **`bionic`:** This is part of Android's core C library. It deals with low-level system interactions.
* **`libc`:**  Confirms this is related to the standard C library.
* **`kernel`:** Indicates this file defines interfaces between user-space (like Android applications) and the Linux kernel.
* **`uapi`:**  Stands for "user API." These are the header files exposed to user-space programs to interact with the kernel.
* **`linux`:**  This is a Linux-specific header file.
* **`virtio_iommu.h`:**  This is the key. It relates to `virtio`, a standard for virtual devices, and `IOMMU`, the Input-Output Memory Management Unit. This strongly suggests this file is about how virtualized devices access memory safely and efficiently.

**2. High-Level Functionality Extraction:**

Knowing the context, we can start extracting the high-level functions based on the defined constants and structures:

* **Feature Negotiation:**  The `VIRTIO_IOMMU_F_*` macros (e.g., `VIRTIO_IOMMU_F_INPUT_RANGE`) clearly indicate features that the IOMMU implementation might support. This suggests a handshake process between the guest OS (or virtual machine) and the host.
* **Configuration:** The `virtio_iommu_config` structure holds configuration parameters like page size and address ranges. This is necessary to set up the IOMMU.
* **Request Types:** The `VIRTIO_IOMMU_T_*` macros (e.g., `VIRTIO_IOMMU_T_ATTACH`) define the types of operations that can be performed. These look like commands sent to the IOMMU.
* **Status Codes:** The `VIRTIO_IOMMU_S_*` macros (e.g., `VIRTIO_IOMMU_S_OK`) represent the possible outcomes of the requests.
* **Request Structures:** The `virtio_iommu_req_*` structures define the specific data needed for each request type. For example, attaching a device needs a domain and endpoint.
* **Probing:** The `VIRTIO_IOMMU_T_PROBE` and related structures (`virtio_iommu_probe_*`) suggest a mechanism to discover properties of the IOMMU or devices.
* **Fault Handling:** The `virtio_iommu_fault` structure describes errors that can occur during memory access.

**3. Connecting to Android:**

The prompt specifically asks about the relevance to Android. The key connection is through virtualization. Android devices often run on hypervisors (like KVM) for various purposes:

* **Running Android itself on a virtualized platform.**
* **Running nested virtual machines (less common directly by apps, but possible).**
* **Security features that leverage virtualization.**

Therefore, `virtio_iommu` in the Android kernel is crucial for enabling secure and performant I/O for these virtualized environments. The example given (graphics drivers) is a good illustration of where the IOMMU protects host memory from potentially malicious guest drivers.

**4. libc Function Details (and why it's mostly not here):**

The prompt asks for details about `libc` function implementations. This is where a crucial realization comes in: **This header file *doesn't define any `libc` functions*.** It defines *data structures and constants*. The actual code that *uses* these structures (e.g., opens the virtio device, sends requests) would be *in the kernel driver* or potentially in some user-space libraries that interact with the kernel (though less likely directly for this). Therefore, the answer needs to clarify this distinction. We can talk about *how* `libc` might *be used* in the *broader context* (e.g., `open()`, `ioctl()`) without detailing implementations within this specific file.

**5. Dynamic Linker (and why it's mostly not here either):**

Similarly, this header file isn't directly related to the dynamic linker. The dynamic linker's job is to load and link shared libraries (`.so` files). While drivers might be loaded, this header file describes an interface for memory management *within* the kernel related to virtualization. The answer should explain this lack of direct connection.

**6. Logic Reasoning, Assumptions, and Examples:**

For logic reasoning, the thought process involves taking the definitions and inferring the *intended usage*. For instance:

* **Assumption:**  `VIRTIO_IOMMU_T_ATTACH` is used to associate a virtual device endpoint with an IOMMU domain.
* **Input (hypothetical):** A request to attach endpoint 0x1000 to domain 0x5.
* **Output (hypothetical):**  Success (`VIRTIO_IOMMU_S_OK`) if valid, or an error status if not.

Common usage errors are easier to identify once the purpose of the structures is clear. For example, providing incorrect address ranges in the map/unmap requests is a likely error.

**7. Android Framework/NDK Path and Frida Hooking:**

Tracing the path from the Android framework down to this header file requires understanding the layers involved:

* **Android Framework (Java/Kotlin):**  High-level APIs.
* **NDK (C/C++):**  Allows developers to write native code.
* **HAL (Hardware Abstraction Layer):**  Interfaces between the framework and hardware-specific drivers.
* **Kernel Drivers:** The actual code that interacts with the hardware (in this case, the virtio IOMMU).

The `virtio_iommu.h` file is used *within the kernel driver*. User-space code (even in the NDK) won't directly include this exact header. Instead, it would interact with the kernel through system calls or device-specific ioctl calls. The answer needs to reflect this indirect path.

Frida hooking is a way to dynamically inspect and modify code. The example focuses on hooking a *potential* system call or ioctl related to IOMMU operations, even though we don't know the exact function name from this header file alone. This demonstrates the *concept* of using Frida to investigate this area.

**8. Structure and Language:**

Finally, presenting the information clearly and in Chinese, as requested, is important. Using bullet points, clear headings, and providing illustrative examples enhances readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file defines some wrapper functions around system calls. **Correction:** Realized it's a UAPI header, so it primarily defines structures and constants for kernel-user communication, not function implementations.
* **Initial thought:**  Focus heavily on dynamic linking. **Correction:**  Recognized the lack of direct connection to dynamic linking within this specific file's scope.
* **Initial thought:** Provide very specific Frida hook examples. **Correction:** Realized we don't have the exact system call names from this header alone, so focus on demonstrating the *principle* of hooking related interactions.
这是一个定义 Linux 内核中 virtio IOMMU (Input/Output Memory Management Unit) 子系统的用户空间 API 的头文件。它定义了用于配置、控制和与虚拟化 IOMMU 设备交互的数据结构和常量。由于它是内核 UAPI 头文件，它被设计成用户空间程序（包括 Android 系统服务和某些 HAL 组件）可以用来与内核中的 virtio IOMMU 驱动程序通信。

**它的功能：**

1. **定义 Virtio IOMMU 的特性 (Features):**
   - `VIRTIO_IOMMU_F_INPUT_RANGE`:  IOMMU 支持配置输入地址范围。
   - `VIRTIO_IOMMU_F_DOMAIN_RANGE`: IOMMU 支持配置域 ID 的范围。
   - `VIRTIO_IOMMU_F_MAP_UNMAP`: IOMMU 支持显式的内存映射和取消映射操作。
   - `VIRTIO_IOMMU_F_BYPASS`: IOMMU 支持旁路 (bypass) 功能，允许设备直接访问物理内存，绕过 IOMMU 的转换。
   - `VIRTIO_IOMMU_F_PROBE`: IOMMU 支持探测功能，用于查询 IOMMU 或连接设备的能力。
   - `VIRTIO_IOMMU_F_MMIO`: IOMMU 支持 MMIO (Memory-Mapped I/O) 类型的映射。
   - `VIRTIO_IOMMU_F_BYPASS_CONFIG`: IOMMU 支持旁路功能的配置。

2. **定义 Virtio IOMMU 的配置结构体 (`virtio_iommu_config`):**
   - `page_size_mask`:  支持的页面大小掩码。
   - `input_range`:  IOMMU 管理的输入地址范围。
   - `domain_range`:  可用的域 ID 范围。
   - `probe_size`:  探测操作缓冲区的大小。
   - `bypass`:  指示旁路功能是否启用。

3. **定义 Virtio IOMMU 的请求类型 (Request Types):**
   - `VIRTIO_IOMMU_T_ATTACH`:  将一个端点 (endpoint, 通常指一个虚拟设备) 关联到一个 IOMMU 域。
   - `VIRTIO_IOMMU_T_DETACH`:  将一个端点从一个 IOMMU 域解关联。
   - `VIRTIO_IOMMU_T_MAP`:  在 IOMMU 域中创建一个从虚拟地址到物理地址的映射。
   - `VIRTIO_IOMMU_T_UNMAP`:  移除 IOMMU 域中的一个地址映射。
   - `VIRTIO_IOMMU_T_PROBE`:  探测一个端点的属性。

4. **定义 Virtio IOMMU 的状态码 (Status Codes):**
   - `VIRTIO_IOMMU_S_OK`:  操作成功。
   - `VIRTIO_IOMMU_S_IOERR`:  I/O 错误。
   - `VIRTIO_IOMMU_S_UNSUPP`:  不支持的操作。
   - `VIRTIO_IOMMU_S_DEVERR`:  设备错误。
   - `VIRTIO_IOMMU_S_INVAL`:  无效的参数。
   - `VIRTIO_IOMMU_S_RANGE`:  地址范围错误。
   - `VIRTIO_IOMMU_S_NOENT`:  找不到实体。
   - `VIRTIO_IOMMU_S_FAULT`:  发生了 IOMMU 错误 (fault)。
   - `VIRTIO_IOMMU_S_NOMEM`:  内存不足。

5. **定义 Virtio IOMMU 的请求结构体 (`virtio_iommu_req_*`):**
   - 这些结构体定义了用户空间向内核发送的命令格式，包括请求类型、参数等。例如，`virtio_iommu_req_attach` 用于发送 attach 请求，包含域 ID 和端点 ID。

6. **定义 Virtio IOMMU 的探测 (Probe) 相关结构体:**
   - 用于查询 IOMMU 或设备的属性，例如支持的内存类型。

7. **定义 Virtio IOMMU 的错误 (Fault) 结构体 (`virtio_iommu_fault`):**
   - 当 IOMMU 检测到非法内存访问时，会生成一个 fault，这个结构体描述了 fault 的原因、地址等信息。

**与 Android 功能的关系及举例说明：**

Virtio IOMMU 在 Android 中主要用于增强虚拟化环境的安全性。当 Android 设备运行在虚拟机中，或者运行支持虚拟化的功能时（例如，运行其他操作系统或隔离某些进程），IOMMU 可以保护宿主机的内存不被虚拟机中的恶意或错误的设备驱动程序访问。

**举例说明：**

假设 Android 设备运行在一个 hypervisor (虚拟机监控器) 上。虚拟机中运行的 Android 系统需要访问一些硬件资源，例如 GPU。

1. **分配 IOMMU 域:** Android 系统会使用 `VIRTIO_IOMMU_T_ATTACH` 请求，将虚拟 GPU 设备 (作为一个端点) 关联到一个 IOMMU 域。这个域定义了该虚拟 GPU 可以访问的内存范围。
2. **配置内存映射:** 当虚拟机中的 GPU 驱动程序需要访问物理内存时，它会发起内存映射请求。Android 系统会使用 `VIRTIO_IOMMU_T_MAP` 请求，在 IOMMU 域中创建一个映射，将虚拟机看到的虚拟地址转换为宿主机的物理地址。IOMMU 会确保这个映射在预定义的范围内。
3. **内存访问保护:** 当虚拟机中的 GPU 尝试访问内存时，IOMMU 会拦截这些访问。如果访问的地址不在其被允许的映射范围内，IOMMU 会阻止该访问并可能产生一个 fault (`virtio_iommu_fault`)，从而保护宿主机的内存安全。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个头文件本身并不包含任何 libc 函数的实现。** 它只是定义了数据结构和常量。实际与内核交互的逻辑会发生在内核驱动程序中。用户空间程序（包括 Android 的服务和 HAL）会使用标准的系统调用（例如 `ioctl`）来与内核中的 virtio IOMMU 驱动程序通信，传递这些结构体定义的数据。

例如，一个 Android 服务可能需要配置 IOMMU。它可能会：

1. 打开一个与 virtio IOMMU 设备相关的字符设备文件（例如 `/dev/virtio-iommu`，实际路径可能不同）。
2. 填充一个 `virtio_iommu_req_attach` 结构体，包含要关联的域 ID 和端点 ID。
3. 使用 `ioctl` 系统调用，将 `virtio_iommu_req_attach` 结构体传递给内核驱动程序，请求执行 attach 操作。

内核驱动程序会接收到 `ioctl` 调用，解析传递过来的结构体，并执行相应的 IOMMU 操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个头文件与 dynamic linker (动态链接器) 没有直接关系。** dynamic linker 的主要职责是加载共享库 (`.so` 文件) 并解析符号依赖关系。 Virtio IOMMU 是一个内核子系统，用户空间程序通过系统调用与其交互。

虽然某些用户空间的库或服务可能会使用这个头文件中定义的结构体来与内核交互，但这与 dynamic linker 的加载和链接过程是分开的。

**如果做了逻辑推理，请给出假设输入与输出:**

**假设场景：** 用户空间程序尝试将端点 0x1234 关联到域 0x5。

**假设输入 (`virtio_iommu_req_attach` 结构体的内容):**

```c
struct virtio_iommu_req_attach attach_req;
attach_req.head.type = VIRTIO_IOMMU_T_ATTACH;
// attach_req.head.reserved 未使用，通常为 0
attach_req.domain = 0x00000005; // __le32 类型的 5
attach_req.endpoint = 0x00001234; // __le32 类型的 0x1234
attach_req.flags = 0; // 假设没有设置特殊标志
// attach_req.reserved 未使用，通常为 0
// tail 部分由内核填充
```

**可能的输出 (内核驱动程序返回的状态码):**

* **成功:** `VIRTIO_IOMMU_S_OK` (0x00) - 表示端点已成功关联到域。
* **失败:**
    * `VIRTIO_IOMMU_S_INVAL` (0x04) - 如果域 ID 或端点 ID 无效。
    * `VIRTIO_IOMMU_S_NOENT` (0x06) - 如果指定的端点不存在。
    * 其他错误码，取决于具体情况。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **传递无效的地址范围:** 在使用 `VIRTIO_IOMMU_T_MAP` 或 `VIRTIO_IOMMU_T_UNMAP` 时，如果提供的虚拟地址或物理地址范围不正确，可能会导致 `VIRTIO_IOMMU_S_RANGE` 错误。

   ```c
   struct virtio_iommu_req_map map_req;
   map_req.head.type = VIRTIO_IOMMU_T_MAP;
   map_req.domain = 0x1;
   map_req.virt_start = 0x1000;
   map_req.virt_end = 0x2000;
   map_req.phys_start = 0x3000;
   // 错误：flags 参数可能不正确，例如缺少必要的权限
   map_req.flags = 0;
   ```

2. **尝试映射已映射的区域:**  重复映射同一个地址范围可能会导致错误。

3. **在未 attach 的情况下尝试映射:**  必须先使用 `VIRTIO_IOMMU_T_ATTACH` 将端点关联到域，然后才能在该域中创建映射。

4. **权限不足:** 尝试执行某些操作可能需要特定的权限，如果用户空间程序没有足够的权限，可能会导致操作失败。

5. **字节序错误:**  结构体中的字段使用了 `__le32` 和 `__le64`，表示小端字节序。如果用户空间程序和内核的字节序不一致，可能会导致数据解析错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

虽然 Android Framework 或 NDK 不会直接包含或使用 `bionic/libc/kernel/uapi/linux/virtio_iommu.h` 这个头文件（因为它是一个内核 UAPI 头文件，主要在内核空间使用），但 Android 系统中的某些组件可能会间接地使用它。

**步骤：**

1. **Android Framework (Java/Kotlin):**  Android Framework 中的某些高级服务，例如负责虚拟化或安全相关的功能，可能会调用底层的 native 代码。

2. **Native 代码 (C/C++，可能在 system services 或 HAL 中):** 这些 native 代码可能会使用标准 C 库函数（例如 `open`, `ioctl`) 与内核驱动程序进行交互。这些代码会构造并发送包含 `virtio_iommu_req_*` 结构体的 `ioctl` 命令。

3. **内核空间 (Virtio IOMMU 驱动程序):** 内核中的 Virtio IOMMU 驱动程序会接收到来自用户空间的 `ioctl` 调用，解析传递过来的 `virtio_iommu_req_*` 结构体，并执行相应的 IOMMU 操作。

**Frida Hook 示例：**

由于用户空间代码不会直接调用 `virtio_iommu.h` 中定义的结构体，我们需要 hook 用户空间与内核交互的系统调用，例如 `ioctl`。我们需要找到哪个 `ioctl` 命令号 (ioctl request code) 被用来发送 Virtio IOMMU 的请求。这通常需要查看内核源代码或进行逆向工程。

假设我们通过分析发现，与 Virtio IOMMU 相关的 `ioctl` 命令号是 `VIRTIO_IOMMU_IOCTL_MAGIC` 和 `VIRTIO_IOMMU_IOCTL_CMD` 的组合 (这只是一个假设的例子，实际情况可能不同)。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    device = frida.get_usb_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

    if pid is None:
        session = device.attach('com.android.system_server') # 假设是 system_server 进程
    else:
        session = device.attach(pid)

    script_code = """
    const IOCTL_MAGIC = 0x<your_ioctl_magic>; // 替换为实际的 magic number
    const IOCTL_CMD = 0x<your_ioctl_cmd>;   // 替换为实际的 command number

    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            if ((request & 0xff) === IOCTL_CMD && ((request >> 8) & 0xff) === IOCTL_MAGIC) {
                console.log("[*] ioctl called with fd:", fd, "request:", request.toString(16));

                // 可以进一步解析 arg[2] 指向的数据，根据 virtio_iommu_req_* 结构体定义
                const req_ptr = ptr(args[2]);
                const type = req_ptr.readU8();
                console.log("[*]   Request Type:", type);

                // 根据 type 值进一步解析结构体内容
                if (type === 0x01) { // VIRTIO_IOMMU_T_ATTACH
                    const domain = req_ptr.add(4).readU32();
                    const endpoint = req_ptr.add(8).readU32();
                    console.log("[*]     Domain:", domain, "Endpoint:", endpoint);
                } else if (type === 0x03) { // VIRTIO_IOMMU_T_MAP
                    const domain = req_ptr.add(4).readU32();
                    const virt_start = req_ptr.add(8).readU64();
                    const virt_end = req_ptr.add(16).readU64();
                    const phys_start = req_ptr.add(24).readU64();
                    const flags = req_ptr.add(32).readU32();
                    console.log("[*]     Domain:", domain, "Virt Start:", virt_start.toString(16), "Virt End:", virt_end.toString(16), "Phys Start:", phys_start.toString(16), "Flags:", flags);
                }
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()

if __name__ == '__main__':
    main()
```

**解释 Frida Hook 示例：**

1. **连接到目标进程:**  代码首先连接到 Android 设备上的指定进程 (例如 `com.android.system_server`)。
2. **Hook `ioctl` 系统调用:**  它使用 Frida 的 `Interceptor.attach` API 来 hook `ioctl` 函数。
3. **检查 `ioctl` 命令号:** 在 `onEnter` 函数中，它检查 `ioctl` 的第二个参数（request），判断是否是与 Virtio IOMMU 相关的命令号（你需要替换示例中的 `IOCTL_MAGIC` 和 `IOCTL_CMD` 为实际的值）。
4. **解析请求结构体:** 如果是 Virtio IOMMU 的 `ioctl`，它会尝试解析第三个参数指向的数据，根据 `virtio_iommu_req_*` 结构体的定义，读取请求类型和其他参数。
5. **打印信息:**  它会将解析到的信息打印出来，帮助你观察用户空间是如何与内核中的 Virtio IOMMU 驱动程序交互的。

**注意：**

* 找到正确的 `ioctl` 命令号是关键，这可能需要一些逆向工程或查看内核源代码。
* 你需要根据实际的 `virtio_iommu_req_*` 结构体定义来调整 Frida 脚本中的数据解析部分。
* 这个示例假设了用户空间通过 `ioctl` 与 Virtio IOMMU 交互，实际情况可能更复杂。

这个详细的解释涵盖了 Virtio IOMMU 头文件的功能、与 Android 的关系、可能的用法、常见错误以及如何使用 Frida 进行调试。记住，这是一个内核 UAPI 头文件，它的主要用途是定义内核与用户空间交互的接口，而不是实现具体的 `libc` 函数或与 dynamic linker 直接相关。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/virtio_iommu.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_VIRTIO_IOMMU_H
#define _UAPI_LINUX_VIRTIO_IOMMU_H
#include <linux/types.h>
#define VIRTIO_IOMMU_F_INPUT_RANGE 0
#define VIRTIO_IOMMU_F_DOMAIN_RANGE 1
#define VIRTIO_IOMMU_F_MAP_UNMAP 2
#define VIRTIO_IOMMU_F_BYPASS 3
#define VIRTIO_IOMMU_F_PROBE 4
#define VIRTIO_IOMMU_F_MMIO 5
#define VIRTIO_IOMMU_F_BYPASS_CONFIG 6
struct virtio_iommu_range_64 {
  __le64 start;
  __le64 end;
};
struct virtio_iommu_range_32 {
  __le32 start;
  __le32 end;
};
struct virtio_iommu_config {
  __le64 page_size_mask;
  struct virtio_iommu_range_64 input_range;
  struct virtio_iommu_range_32 domain_range;
  __le32 probe_size;
  __u8 bypass;
  __u8 reserved[3];
};
#define VIRTIO_IOMMU_T_ATTACH 0x01
#define VIRTIO_IOMMU_T_DETACH 0x02
#define VIRTIO_IOMMU_T_MAP 0x03
#define VIRTIO_IOMMU_T_UNMAP 0x04
#define VIRTIO_IOMMU_T_PROBE 0x05
#define VIRTIO_IOMMU_S_OK 0x00
#define VIRTIO_IOMMU_S_IOERR 0x01
#define VIRTIO_IOMMU_S_UNSUPP 0x02
#define VIRTIO_IOMMU_S_DEVERR 0x03
#define VIRTIO_IOMMU_S_INVAL 0x04
#define VIRTIO_IOMMU_S_RANGE 0x05
#define VIRTIO_IOMMU_S_NOENT 0x06
#define VIRTIO_IOMMU_S_FAULT 0x07
#define VIRTIO_IOMMU_S_NOMEM 0x08
struct virtio_iommu_req_head {
  __u8 type;
  __u8 reserved[3];
};
struct virtio_iommu_req_tail {
  __u8 status;
  __u8 reserved[3];
};
#define VIRTIO_IOMMU_ATTACH_F_BYPASS (1 << 0)
struct virtio_iommu_req_attach {
  struct virtio_iommu_req_head head;
  __le32 domain;
  __le32 endpoint;
  __le32 flags;
  __u8 reserved[4];
  struct virtio_iommu_req_tail tail;
};
struct virtio_iommu_req_detach {
  struct virtio_iommu_req_head head;
  __le32 domain;
  __le32 endpoint;
  __u8 reserved[8];
  struct virtio_iommu_req_tail tail;
};
#define VIRTIO_IOMMU_MAP_F_READ (1 << 0)
#define VIRTIO_IOMMU_MAP_F_WRITE (1 << 1)
#define VIRTIO_IOMMU_MAP_F_MMIO (1 << 2)
#define VIRTIO_IOMMU_MAP_F_MASK (VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE | VIRTIO_IOMMU_MAP_F_MMIO)
struct virtio_iommu_req_map {
  struct virtio_iommu_req_head head;
  __le32 domain;
  __le64 virt_start;
  __le64 virt_end;
  __le64 phys_start;
  __le32 flags;
  struct virtio_iommu_req_tail tail;
};
struct virtio_iommu_req_unmap {
  struct virtio_iommu_req_head head;
  __le32 domain;
  __le64 virt_start;
  __le64 virt_end;
  __u8 reserved[4];
  struct virtio_iommu_req_tail tail;
};
#define VIRTIO_IOMMU_PROBE_T_NONE 0
#define VIRTIO_IOMMU_PROBE_T_RESV_MEM 1
#define VIRTIO_IOMMU_PROBE_T_MASK 0xfff
struct virtio_iommu_probe_property {
  __le16 type;
  __le16 length;
};
#define VIRTIO_IOMMU_RESV_MEM_T_RESERVED 0
#define VIRTIO_IOMMU_RESV_MEM_T_MSI 1
struct virtio_iommu_probe_resv_mem {
  struct virtio_iommu_probe_property head;
  __u8 subtype;
  __u8 reserved[3];
  __le64 start;
  __le64 end;
};
struct virtio_iommu_req_probe {
  struct virtio_iommu_req_head head;
  __le32 endpoint;
  __u8 reserved[64];
  __u8 properties[];
};
#define VIRTIO_IOMMU_FAULT_R_UNKNOWN 0
#define VIRTIO_IOMMU_FAULT_R_DOMAIN 1
#define VIRTIO_IOMMU_FAULT_R_MAPPING 2
#define VIRTIO_IOMMU_FAULT_F_READ (1 << 0)
#define VIRTIO_IOMMU_FAULT_F_WRITE (1 << 1)
#define VIRTIO_IOMMU_FAULT_F_EXEC (1 << 2)
#define VIRTIO_IOMMU_FAULT_F_ADDRESS (1 << 8)
struct virtio_iommu_fault {
  __u8 reason;
  __u8 reserved[3];
  __le32 flags;
  __le32 endpoint;
  __u8 reserved2[4];
  __le64 address;
};
#endif
```