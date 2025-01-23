Response:
Let's break down the thought process for answering the request about the `xilinx_sdfec.h` header file.

**1. Understanding the Core Request:**

The main goal is to understand the functionality of the `xilinx_sdfec.h` header file within the Android Bionic context. The request also asks for connections to Android functionality, explanations of libc functions, dynamic linker aspects, usage errors, and the Android framework/NDK path.

**2. Initial Assessment of the Header File:**

Scanning the header file reveals the following:

* **`#ifndef __XILINX_SDFEC_H__`, `#define __XILINX_SDFEC_H__`:** This is a standard include guard, indicating it's a header file.
* **Includes `<linux/types.h>`:**  This strongly suggests it's interacting directly with the Linux kernel. The `uapi` directory location reinforces this.
* **`#define` constants like `XSDFEC_LDPC_SC_TABLE_ADDR_BASE`:** These define memory addresses and depths, hinting at hardware interaction, likely with a Xilinx device. "LDPC" suggests Forward Error Correction (FEC).
* **`enum` definitions (e.g., `xsdfec_code`, `xsdfec_state`):**  These define sets of related constants, likely representing states, modes, or algorithms.
* **`struct` definitions (e.g., `xsdfec_turbo`, `xsdfec_ldpc_params`):** These define data structures used for configuring and interacting with the underlying hardware/driver. The field names provide clues about their purpose (e.g., `n`, `k`, `psize` in `xsdfec_ldpc_params` are common parameters in LDPC codes).
* **`#define XSDFEC_MAGIC 'f'`, `#define XSDFEC_START_DEV _IO(...)`:** These define ioctl commands. The `_IO`, `_IOR`, and `_IOW` macros are standard for defining ioctl commands to interact with device drivers in Linux. The `XSDFEC_MAGIC` acts as a namespace to avoid collisions.

**3. Identifying the Primary Functionality:**

Based on the keywords and structures, the core functionality is clear: **controlling and configuring a Xilinx Soft Decision Forward Error Correction (SDFEC) IP core.**  This involves:

* Selecting coding schemes (Turbo or LDPC).
* Configuring parameters for these codes (e.g., LDPC parameters like block size, code rate).
* Starting and stopping the device.
* Getting status information.
* Setting up interrupt handling.
* Setting bypass modes.
* Retrieving statistics.

**4. Connecting to Android Functionality:**

The `uapi` directory indicates a direct kernel interface. Android's interaction would involve:

* **Kernel Driver:** A corresponding kernel driver for the Xilinx SDFEC hardware is necessary. This header file provides the user-space interface to that driver.
* **HAL (Hardware Abstraction Layer):**  A HAL module would likely exist to provide a more Android-friendly interface on top of the raw ioctl calls. This hides the kernel details from higher-level Android components.
* **Android Framework/NDK:** Applications wouldn't directly use these structures and ioctl calls. Instead, they would interact through the HAL, likely exposed through some higher-level API in the framework or NDK (though a direct NDK interface is possible for very low-level access).

**5. Explaining libc Functions:**

The header file itself doesn't *define* libc functions. It *uses* standard C types like `__u32`, `__u8`, etc., which are likely defined in `<linux/types.h>` or other standard headers that libc includes. The interaction happens when an Android process makes system calls (like `ioctl`) which are handled by the kernel and ultimately invoke the driver. Therefore, the focus should be on *how* libc is used to make the ioctl calls.

**6. Dynamic Linker Aspects:**

This header file is a kernel header. It's not directly involved in the dynamic linking process of user-space libraries. The corresponding kernel driver *is* loaded by the kernel, but that's not the same as user-space dynamic linking. Therefore, a direct SO layout example is not applicable here.

**7. Logical Reasoning and Examples:**

It's important to provide concrete examples. For instance, illustrating how to use the ioctl commands with `open`, `ioctl`, and `close` system calls is key. Also, demonstrating the structure of the data passed to `ioctl` based on the defined structs is necessary.

**8. Common Usage Errors:**

Thinking about common programming errors when interacting with device drivers via ioctl is crucial. Examples include incorrect file descriptor, wrong ioctl command, or passing invalid data structures.

**9. Android Framework/NDK Path and Frida Hooking:**

Tracing the path from the Android framework or NDK down to these ioctl calls requires understanding the Android software stack. Identifying potential places for hooking (like the HAL implementation) using Frida is a valuable addition.

**10. Structuring the Answer:**

A clear and organized structure is vital for a comprehensive answer. Using headings and bullet points helps to break down the information into manageable chunks. Starting with a high-level overview and then drilling down into specifics is a good approach.

**Self-Correction/Refinement during the process:**

* **Initial Thought:** Maybe this directly relates to some specific Android media codec.
* **Correction:** While possible, the generic "SDFEC" and the kernel-level interface suggest a more foundational hardware interaction. The focus should be on the kernel driver and HAL.
* **Initial Thought:**  Detailing every possible libc function.
* **Correction:** The header primarily defines structures and constants. Focus on *how* libc's system call interface is used to interact with the driver, specifically the `ioctl` function.
* **Initial Thought:** Trying to force a dynamic linking example.
* **Correction:** Recognize that this is a kernel header and dynamic linking applies to user-space libraries. Explain the kernel's role in loading the driver.

By following this thought process, combining analysis of the header file with knowledge of the Android architecture and Linux kernel interactions, a comprehensive and accurate answer can be generated.
这是一个定义了与 Xilinx Soft Decision Forward Error Correction (SDFEC) 硬件 IP 核交互的接口的头文件。它位于 Android Bionic 的内核用户空间 API 目录中，这意味着它定义了用户空间程序（如 Android 的 HAL 或 NDK 应用）如何与内核中的 SDFEC 驱动程序进行通信。

**功能列举:**

这个头文件定义了以下功能，用于控制和配置 Xilinx SDFEC 硬件 IP 核：

1. **定义常量:**
   - `XSDFEC_LDPC_SC_TABLE_ADDR_BASE`, `XSDFEC_LDPC_SC_TABLE_ADDR_HIGH` 等：定义了 LDPC 码表在硬件中的地址范围。
   - `XSDFEC_SC_TABLE_DEPTH`, `XSDFEC_LA_TABLE_DEPTH`, `XSDFEC_QC_TABLE_DEPTH`: 定义了这些表的大小。
   - `XSDFEC_MAGIC`: 定义了一个幻数，用于标识与 SDFEC 驱动程序的 ioctl 命令。

2. **定义枚举类型:**
   - `enum xsdfec_code`: 定义了支持的 FEC 编码类型，例如 `XSDFEC_TURBO_CODE` 和 `XSDFEC_LDPC_CODE`。
   - `enum xsdfec_order`: 定义了数据处理的顺序，例如 `XSDFEC_MAINTAIN_ORDER` 和 `XSDFEC_OUT_OF_ORDER`。
   - `enum xsdfec_turbo_alg`: 定义了 Turbo 码算法。
   - `enum xsdfec_state`: 定义了 SDFEC 设备的状态，例如 `XSDFEC_INIT`, `XSDFEC_STARTED`, `XSDFEC_STOPPED` 等。
   - `enum xsdfec_axis_width`: 定义了 AXI Stream 接口的位宽。
   - `enum xsdfec_axis_word_include`: 定义了 AXI Stream 字包含的方式。

3. **定义结构体:**
   - `struct xsdfec_turbo`: 定义了 Turbo 码的配置参数，如算法和缩放因子。
   - `struct xsdfec_ldpc_params`: 定义了 LDPC 码的详细参数，包括码长、信息位长度、校验位大小、层数、QC 矩阵相关参数以及码表地址等。
   - `struct xsdfec_status`: 定义了 SDFEC 设备的状态信息，如当前状态和活动状态。
   - `struct xsdfec_irq`: 定义了中断相关的配置，如是否启用主中断和 ECC 错误中断。
   - `struct xsdfec_config`: 定义了 SDFEC 的通用配置，包括编码类型、数据处理顺序、AXI Stream 接口宽度等。
   - `struct xsdfec_stats`: 定义了 SDFEC 的统计信息，如中断错误计数、可纠正 ECC 错误计数和不可纠正 ECC 错误计数。
   - `struct xsdfec_ldpc_param_table_sizes`: 定义了 LDPC 参数表的大小。

4. **定义 ioctl 命令:**
   - `XSDFEC_START_DEV`, `XSDFEC_STOP_DEV`: 用于启动和停止 SDFEC 设备。
   - `XSDFEC_GET_STATUS`: 用于获取 SDFEC 设备的状态。
   - `XSDFEC_SET_IRQ`: 用于设置中断配置。
   - `XSDFEC_SET_TURBO`: 用于设置 Turbo 码参数。
   - `XSDFEC_ADD_LDPC_CODE_PARAMS`: 用于添加 LDPC 码的参数。
   - `XSDFEC_GET_CONFIG`: 用于获取 SDFEC 的配置。
   - `XSDFEC_GET_TURBO`: 用于获取 Turbo 码的配置。
   - `XSDFEC_SET_ORDER`: 用于设置数据处理顺序。
   - `XSDFEC_SET_BYPASS`: 用于设置旁路模式。
   - `XSDFEC_IS_ACTIVE`: 用于检查设备是否处于活动状态。
   - `XSDFEC_CLEAR_STATS`: 用于清除统计信息。
   - `XSDFEC_GET_STATS`: 用于获取统计信息。
   - `XSDFEC_SET_DEFAULT_CONFIG`: 用于设置默认配置。

**与 Android 功能的关系举例:**

这个头文件定义的接口通常用于与底层硬件加速器进行交互，这在 Android 设备中有很多应用场景，例如：

* **多媒体处理 (Multimedia Processing):**  FEC 编码常用于提高无线传输的可靠性，例如在视频流传输或广播电视应用中。Android 设备可能使用 Xilinx SDFEC 硬件加速器来进行 FEC 编码和解码，以提高媒体流传输的质量。
    * **举例:**  Android TV 或支持数字电视功能的手机，在接收广播信号时，可能会使用 SDFEC IP 核进行解码，纠正传输过程中的错误，保证画面的清晰度和流畅性。
* **存储系统 (Storage Systems):**  在一些高性能或高可靠性要求的存储系统中，可能会使用 FEC 编码来提高数据存储的可靠性。虽然不太常见，但 Android 设备中某些特定的存储硬件或外部设备可能使用到。
* **通信系统 (Communication Systems):**  一些 Android 设备可能作为通信节点，例如在车载系统中，需要进行可靠的数据传输。SDFEC 可以用于提高这些通信链路的可靠性。

**详细解释 libc 函数的功能实现:**

这个头文件本身并不包含 libc 函数的实现。它定义的是内核接口。用户空间的程序（例如，使用 C 语言编写的 Android 组件）会使用 libc 提供的系统调用接口（如 `open()`, `ioctl()`, `close()`）来与这个头文件定义的内核接口进行交互。

* **`open()`:**  用户空间程序会使用 `open()` 系统调用打开与 SDFEC 驱动程序关联的设备文件（通常位于 `/dev` 目录下）。
* **`ioctl()`:**  核心的交互是通过 `ioctl()` 系统调用完成的。`ioctl()` 允许用户空间程序向设备驱动程序发送控制命令和传递数据。这个头文件中定义的 `XSDFEC_*` 宏就是用于 `ioctl()` 调用的命令编号。
    * 例如，`XSDFEC_START_DEV` 宏会被用作 `ioctl()` 的第二个参数，告诉 SDFEC 驱动程序执行启动设备的操作。
    * 当使用 `XSDFEC_SET_TURBO` 时，用户空间程序会填充 `struct xsdfec_turbo` 结构体，并将指向该结构体的指针作为 `ioctl()` 的第三个参数传递给驱动程序。驱动程序会解析这个结构体，并根据其中的参数配置 SDFEC 硬件。
* **`close()`:**  在完成与 SDFEC 驱动程序的交互后，用户空间程序会使用 `close()` 系统调用关闭设备文件。

**涉及 dynamic linker 的功能，so 布局样本以及链接的处理过程:**

这个头文件本身不涉及 dynamic linker 的功能。它定义的是内核接口，属于操作系统内核的一部分。动态链接器（如 Android 的 `linker64` 或 `linker`）负责在程序运行时加载和链接共享库（.so 文件）。

与 SDFEC 相关的动态链接可能发生在用户空间，例如：

* **HAL (Hardware Abstraction Layer) 模块:** Android 的 HAL 通常以共享库的形式存在。可能会有一个与 SDFEC 硬件交互的 HAL 模块，该模块会使用这个头文件中定义的 ioctl 命令与内核驱动程序通信。
* **NDK 应用:**  如果 NDK 应用需要直接访问 SDFEC 硬件（虽然这种情况比较少见），它可能会链接到包含与内核交互的辅助库。

**SO 布局样本 (假设存在一个与 SDFEC 交互的 HAL 模块):**

```
/system/lib64/hw/vendor.foo.hardware.sdfec@1.0-impl.so
```

**链接的处理过程:**

1. **编译时链接:** 在编译 HAL 模块时，会链接到必要的 libc 库。如果 HAL 模块需要使用自定义的库来处理与 SDFEC 的交互，也会链接到这些库。
2. **运行时加载:** 当 Android 系统需要使用 SDFEC 功能时，例如，上层 Framework 调用了相应的 HAL 接口，Android 的动态链接器会加载 `vendor.foo.hardware.sdfec@1.0-impl.so` 这个共享库。
3. **符号解析:** 动态链接器会解析该共享库中的符号依赖，并将其与系统中已加载的其他共享库的符号进行链接。
4. **库的加载:**  动态链接器将共享库加载到进程的地址空间。
5. **初始化:**  共享库的初始化函数（如果存在）会被执行，通常会在这里打开与 SDFEC 设备文件（例如 `/dev/sdfec0`）的连接。

**逻辑推理，假设输入与输出:**

假设用户空间程序想要启动 SDFEC 设备：

* **假设输入:**
    - 设备文件描述符 `fd` 已通过 `open("/dev/sdfec0", ...)` 获取。
    - 使用 `XSDFEC_START_DEV` 作为 `ioctl()` 的命令。
* **逻辑推理:**  用户空间程序调用 `ioctl(fd, XSDFEC_START_DEV)`.
* **预期输出:**
    - 如果操作成功，`ioctl()` 返回 0。
    - SDFEC 硬件 IP 核的状态应该变为 `XSDFEC_STARTED`。可以通过后续的 `ioctl(fd, XSDFEC_GET_STATUS, &status)` 调用来验证，其中 `status.state` 应该等于 `XSDFEC_STARTED`。

假设用户空间程序想要设置 LDPC 码的参数：

* **假设输入:**
    - 设备文件描述符 `fd` 已打开。
    - 一个填充了 LDPC 参数的 `struct xsdfec_ldpc_params` 结构体 `ldpc_params`。
    - 使用 `XSDFEC_ADD_LDPC_CODE_PARAMS` 作为 `ioctl()` 的命令。
* **逻辑推理:** 用户空间程序调用 `ioctl(fd, XSDFEC_ADD_LDPC_CODE_PARAMS, &ldpc_params)`.
* **预期输出:**
    - 如果操作成功，`ioctl()` 返回 0。
    - SDFEC 硬件 IP 核会根据 `ldpc_params` 中的配置进行相应的设置。

**用户或编程常见的使用错误举例:**

1. **未打开设备文件:**  在调用 `ioctl()` 之前，忘记使用 `open()` 打开与 SDFEC 驱动程序关联的设备文件。这会导致 `ioctl()` 调用失败，并返回错误代码（通常是文件描述符无效）。
   ```c
   int fd;
   // 忘记打开设备文件
   // ioctl(fd, XSDFEC_START_DEV); // 错误：fd 未初始化或无效
   ```

2. **使用错误的 ioctl 命令:**  使用了与预期操作不符的 `ioctl` 命令编号。例如，想要设置 Turbo 码参数，却使用了 `XSDFEC_ADD_LDPC_CODE_PARAMS`。这会导致驱动程序无法识别命令或执行错误的操作。

3. **传递无效的数据结构:**  传递给 `ioctl()` 的数据结构（例如 `struct xsdfec_ldpc_params`) 未正确初始化，或者包含了超出硬件支持范围的值。这可能导致驱动程序崩溃或硬件行为异常。
   ```c
   struct xsdfec_ldpc_params ldpc_params;
   // 忘记初始化 ldpc_params 的某些字段
   int fd = open("/dev/sdfec0", O_RDWR);
   ioctl(fd, XSDFEC_ADD_LDPC_CODE_PARAMS, &ldpc_params); // 错误：ldpc_params 可能包含垃圾数据
   close(fd);
   ```

4. **权限问题:**  用户空间程序可能没有足够的权限访问 SDFEC 设备文件。这会导致 `open()` 调用失败，从而无法进行后续的 `ioctl()` 调用。

5. **设备驱动未加载:**  如果 SDFEC 的内核驱动程序没有正确加载，尝试打开设备文件将会失败。

**Android framework 或 ndk 是如何一步步的到达这里:**

以下是一个简化的流程，说明 Android Framework 或 NDK 应用如何最终与这个头文件中定义的内核接口交互：

1. **NDK 应用或 Framework 组件:**  用户空间的应用程序或 Android Framework 的某个组件需要使用 SDFEC 硬件加速的功能。
2. **高层 API 调用:**  应用程序或 Framework 组件会调用高层的 API，这些 API 可能属于 Android 的媒体框架、通信框架或其他相关服务。
3. **HAL 接口调用:**  高层 API 的实现会调用相应的硬件抽象层 (HAL) 接口。HAL 的目的是将硬件的具体实现细节抽象出来，提供统一的接口给上层使用。
4. **HAL 实现:**  负责 SDFEC 硬件的 HAL 模块（通常是一个 `.so` 共享库）会实现这些 HAL 接口。
5. **打开设备文件:**  HAL 模块的实现中，会使用 `open()` 系统调用打开与 SDFEC 驱动程序关联的设备文件，例如 `/dev/sdfec0`。
6. **ioctl 调用:**  HAL 模块会根据上层传递的参数，填充相应的 `struct xsdfec_*` 结构体，并使用 `ioctl()` 系统调用，配合这个头文件中定义的 `XSDFEC_*` 宏，与内核中的 SDFEC 驱动程序进行通信，控制和配置硬件。
7. **内核驱动程序:**  内核中的 SDFEC 驱动程序接收到 `ioctl()` 调用后，会解析命令和数据，并与底层的 Xilinx SDFEC 硬件 IP 核进行交互。
8. **硬件操作:**  Xilinx SDFEC 硬件 IP 核执行相应的 FEC 编码或解码操作。
9. **结果返回:**  硬件操作的结果会通过内核驱动程序返回给 HAL 模块，HAL 模块再将结果返回给上层的 Framework 组件或 NDK 应用。

**Frida Hook 示例调试这些步骤:**

可以使用 Frida hook HAL 模块中的函数，以观察其如何与内核驱动程序交互。

```python
import frida
import sys

# 替换为实际的 HAL 库名称
hal_library_name = "vendor.foo.hardware.sdfec@1.0-impl.so"
# 假设 HAL 中有一个用于启动 SDFEC 设备的函数
hal_function_name = "_ZN...HalModule...startDeviceEv" # 使用实际的符号名称

session = frida.attach('com.example.myapp') # 替换为目标应用的包名

script = session.create_script(f"""
    Interceptor.attach(Module.findExportByName("{hal_library_name}", "{hal_function_name}"), {{
        onEnter: function(args) {{
            console.log("[+] Hooked {hal_library_name}!{hal_function_name}");
            // 可以在这里查看传递给 HAL 函数的参数
        }},
        onLeave: function(retval) {{
            console.log("[+] {hal_library_name}!{hal_function_name} returned: " + retval);
            // 可以在这里查看 HAL 函数的返回值

            // Hook open 系统调用
            var openPtr = Module.findExportByName(null, "open");
            Interceptor.attach(openPtr, {{
                onEnter: function(args) {{
                    var pathname = Memory.readCString(args[0]);
                    if (pathname.includes("sdfec")) {{
                        console.log("[+] open(\"" + pathname + "\", " + args[1] + ")");
                        this.fd = pathname; // 保存文件名以便后续使用
                    }}
                }},
                onLeave: function(retval) {{
                    if (this.fd) {{
                        console.log("[+] open returned FD: " + retval);
                        this.fd = null;
                        // Hook ioctl 系统调用
                        var ioctlPtr = Module.findExportByName(null, "ioctl");
                        Interceptor.attach(ioctlPtr, {{
                            onEnter: function(args) {{
                                var request = args[1].toInt();
                                console.log("[+] ioctl(fd=" + args[0] + ", request=0x" + request.toString(16) + ")");
                                // 可以根据 request 的值（XSDFEC_* 宏）来判断执行了哪个操作
                                if (request === 0x40046600) { // 假设 XSDFEC_START_DEV 的值是 0x40046600
                                    console.log("[+]  -> XSDFEC_START_DEV");
                                }
                                // ... 可以添加更多 ioctl 命令的判断
                            }},
                            onLeave: function(retval) {{
                                console.log("[+] ioctl returned: " + retval);
                            }}
                        }});
                    }}
                }}
            }});
        }}
    }});
""")

script.load()
sys.stdin.read()
```

这个 Frida 脚本做了以下事情：

1. **Hook HAL 函数:**  Hook 了 HAL 模块中用于启动 SDFEC 设备的函数 (`hal_function_name`)，以观察其被调用。
2. **Hook `open` 系统调用:**  在 HAL 函数执行期间，hook 了 `open` 系统调用，以捕获 HAL 模块何时尝试打开与 SDFEC 相关的设备文件。
3. **Hook `ioctl` 系统调用:**  一旦检测到打开了 SDFEC 设备文件，就 hook `ioctl` 系统调用，以查看 HAL 模块向 SDFEC 驱动程序发送了哪些 `ioctl` 命令。通过检查 `ioctl` 的第二个参数（命令编号），可以判断执行了哪个具体的操作（例如，启动设备、设置参数等）。

通过这种方式，可以逐步跟踪 Android Framework 或 NDK 应用如何通过 HAL 与内核中的 SDFEC 驱动程序进行交互。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/misc/xilinx_sdfec.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __XILINX_SDFEC_H__
#define __XILINX_SDFEC_H__
#include <linux/types.h>
#define XSDFEC_LDPC_SC_TABLE_ADDR_BASE (0x10000)
#define XSDFEC_LDPC_SC_TABLE_ADDR_HIGH (0x10400)
#define XSDFEC_LDPC_LA_TABLE_ADDR_BASE (0x18000)
#define XSDFEC_LDPC_LA_TABLE_ADDR_HIGH (0x19000)
#define XSDFEC_LDPC_QC_TABLE_ADDR_BASE (0x20000)
#define XSDFEC_LDPC_QC_TABLE_ADDR_HIGH (0x28000)
#define XSDFEC_SC_TABLE_DEPTH (XSDFEC_LDPC_SC_TABLE_ADDR_HIGH - XSDFEC_LDPC_SC_TABLE_ADDR_BASE)
#define XSDFEC_LA_TABLE_DEPTH (XSDFEC_LDPC_LA_TABLE_ADDR_HIGH - XSDFEC_LDPC_LA_TABLE_ADDR_BASE)
#define XSDFEC_QC_TABLE_DEPTH (XSDFEC_LDPC_QC_TABLE_ADDR_HIGH - XSDFEC_LDPC_QC_TABLE_ADDR_BASE)
enum xsdfec_code {
  XSDFEC_TURBO_CODE = 0,
  XSDFEC_LDPC_CODE,
};
enum xsdfec_order {
  XSDFEC_MAINTAIN_ORDER = 0,
  XSDFEC_OUT_OF_ORDER,
};
enum xsdfec_turbo_alg {
  XSDFEC_MAX_SCALE = 0,
  XSDFEC_MAX_STAR,
  XSDFEC_TURBO_ALG_MAX,
};
enum xsdfec_state {
  XSDFEC_INIT = 0,
  XSDFEC_STARTED,
  XSDFEC_STOPPED,
  XSDFEC_NEEDS_RESET,
  XSDFEC_PL_RECONFIGURE,
};
enum xsdfec_axis_width {
  XSDFEC_1x128b = 1,
  XSDFEC_2x128b = 2,
  XSDFEC_4x128b = 4,
};
enum xsdfec_axis_word_include {
  XSDFEC_FIXED_VALUE = 0,
  XSDFEC_IN_BLOCK,
  XSDFEC_PER_AXI_TRANSACTION,
  XSDFEC_AXIS_WORDS_INCLUDE_MAX,
};
struct xsdfec_turbo {
  __u32 alg;
  __u8 scale;
};
struct xsdfec_ldpc_params {
  __u32 n;
  __u32 k;
  __u32 psize;
  __u32 nlayers;
  __u32 nqc;
  __u32 nmqc;
  __u32 nm;
  __u32 norm_type;
  __u32 no_packing;
  __u32 special_qc;
  __u32 no_final_parity;
  __u32 max_schedule;
  __u32 sc_off;
  __u32 la_off;
  __u32 qc_off;
  __u32 * sc_table;
  __u32 * la_table;
  __u32 * qc_table;
  __u16 code_id;
};
struct xsdfec_status {
  __u32 state;
  __s8 activity;
};
struct xsdfec_irq {
  __s8 enable_isr;
  __s8 enable_ecc_isr;
};
struct xsdfec_config {
  __u32 code;
  __u32 order;
  __u32 din_width;
  __u32 din_word_include;
  __u32 dout_width;
  __u32 dout_word_include;
  struct xsdfec_irq irq;
  __s8 bypass;
  __s8 code_wr_protect;
};
struct xsdfec_stats {
  __u32 isr_err_count;
  __u32 cecc_count;
  __u32 uecc_count;
};
struct xsdfec_ldpc_param_table_sizes {
  __u32 sc_size;
  __u32 la_size;
  __u32 qc_size;
};
#define XSDFEC_MAGIC 'f'
#define XSDFEC_START_DEV _IO(XSDFEC_MAGIC, 0)
#define XSDFEC_STOP_DEV _IO(XSDFEC_MAGIC, 1)
#define XSDFEC_GET_STATUS _IOR(XSDFEC_MAGIC, 2, struct xsdfec_status)
#define XSDFEC_SET_IRQ _IOW(XSDFEC_MAGIC, 3, struct xsdfec_irq)
#define XSDFEC_SET_TURBO _IOW(XSDFEC_MAGIC, 4, struct xsdfec_turbo)
#define XSDFEC_ADD_LDPC_CODE_PARAMS _IOW(XSDFEC_MAGIC, 5, struct xsdfec_ldpc_params)
#define XSDFEC_GET_CONFIG _IOR(XSDFEC_MAGIC, 6, struct xsdfec_config)
#define XSDFEC_GET_TURBO _IOR(XSDFEC_MAGIC, 7, struct xsdfec_turbo)
#define XSDFEC_SET_ORDER _IOW(XSDFEC_MAGIC, 8, unsigned long)
#define XSDFEC_SET_BYPASS _IOW(XSDFEC_MAGIC, 9, bool)
#define XSDFEC_IS_ACTIVE _IOR(XSDFEC_MAGIC, 10, bool)
#define XSDFEC_CLEAR_STATS _IO(XSDFEC_MAGIC, 11)
#define XSDFEC_GET_STATS _IOR(XSDFEC_MAGIC, 12, struct xsdfec_stats)
#define XSDFEC_SET_DEFAULT_CONFIG _IO(XSDFEC_MAGIC, 13)
#endif
```