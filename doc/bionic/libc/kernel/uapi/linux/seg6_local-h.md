Response:
Let's break down the thought process for answering the user's request. The request is comprehensive and touches on several aspects of the provided C header file.

**1. Understanding the Core Request:**

The fundamental task is to analyze the `seg6_local.h` header file and explain its purpose and relevance within the Android ecosystem, especially focusing on its connection to the Bionic libc, the kernel, and networking.

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI_LINUX_SEG6_LOCAL_H` and `#define _UAPI_LINUX_SEG6_LOCAL_H`:**  Standard include guard to prevent multiple inclusions. This is a common practice in C/C++.
* **`#include <linux/seg6.h>`:** This is a crucial clue. It indicates this header file is *part of* the Linux kernel's user-space API (UAPI). The `seg6.h` likely contains the core definitions for Segment Routing IPv6 (SRv6).
* **`enum` definitions:** The majority of the file consists of `enum` definitions. These enums define constants that represent different aspects and configurations related to SRv6 local processing. The names of the enums and their members (like `SEG6_LOCAL_ACTION`, `SEG6_LOCAL_ACTION_END`, etc.) give strong hints about their purpose. "Local" suggests actions performed on the device itself, rather than forwarding traffic.

**3. Connecting to SRv6:**

Based on the included header (`linux/seg6.h`) and the naming conventions, it's highly probable that this file defines constants related to *local end-point behaviors* within the Segment Routing IPv6 (SRv6) framework in the Linux kernel. SRv6 allows routing packets based on a list of segments (nodes) they must traverse. "Local" actions refer to what happens when a packet reaches its final segment on a specific device.

**4. Addressing the User's Specific Questions (Iterative Refinement):**

* **功能 (Functionality):**  The primary function is to define constants related to SRv6 local segment processing. This needs to be explained clearly, mentioning actions, tables, counters, etc.

* **与 Android 的关系 (Relationship with Android):** This is where Bionic comes in. As the Android C library, Bionic provides the interface for user-space applications to interact with the Linux kernel. Therefore, this header file, being part of the kernel's UAPI, is directly relevant to Android. Android applications or daemons that need to configure or interact with SRv6 on the device would use these definitions. A key point is that **typical Android apps won't directly use these**. It's more for networking infrastructure or potentially specialized network management tools. Providing examples of potential Android components (like `netd`) is helpful.

* **libc 函数的实现 (Implementation of libc functions):**  This is a trick question! This header file *defines constants*. It doesn't *contain* libc function implementations. The answer needs to clarify this distinction. The libc functions would use these constants when interacting with the kernel through system calls.

* **dynamic linker 的功能 (Dynamic linker functionality):**  Similarly, this header file is not directly related to the dynamic linker. The dynamic linker's job is to load and link shared libraries. While network-related libraries *might* use these definitions, the header itself isn't a dynamic linker component. The answer should clarify this. Providing a general example of SO layout and linking is still useful for context, even if this specific file isn't a direct part of it.

* **逻辑推理 (Logical deduction):** Given the nature of enum definitions, the logical deduction is straightforward: mapping symbolic names to integer values. Providing a simple example of how an application might use these constants in a system call is illustrative.

* **用户或编程常见的使用错误 (Common user/programming errors):**  The main errors would involve using incorrect constant values or misunderstanding their meaning when configuring SRv6. Emphasizing checking kernel documentation and potential version compatibility issues is crucial.

* **Android framework or ndk 如何到达这里 (How Android framework/NDK reaches here):**  This requires tracing the path from high-level Android components down to the kernel. The path involves the Android Framework (Java/Kotlin), native libraries (NDK), and ultimately system calls into the kernel. Highlighting components like `netd` and the use of `ioctl` or Netlink is important.

* **Frida hook 示例 (Frida hook example):**  A practical Frida example demonstrating how to intercept system calls related to SRv6 configuration (like `ioctl` with relevant commands) is a powerful way to illustrate how developers can interact with this functionality and debug it. The example should show how to filter for relevant calls and access the data being passed.

**5. Structuring the Answer:**

Organize the answer clearly, addressing each of the user's questions in a separate section. Use headings and bullet points to improve readability.

**6. Language and Tone:**

Use clear and concise Chinese. Explain technical concepts in a way that is understandable to someone with a reasonable technical background.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Maybe this file *implements* some SRv6 functionality within Bionic.
* **Correction:** The `#include <linux/seg6.h>` clearly indicates it's part of the *kernel* UAPI. Bionic just provides the interface to it. The file defines *constants*, not implementations.
* **Initial thought:** How does the dynamic linker relate to this?
* **Correction:**  It's not directly related. Focus on explaining the *purpose* of the header file and its connection to kernel interaction, not shoehorning in dynamic linking where it doesn't directly fit. However, provide a general overview of dynamic linking for context.
* **Initial thought:**  Give low-level kernel code examples.
* **Correction:** The request is more about the *user-space* view and how Android interacts with it. Focus on system calls and user-space APIs.

By following this iterative process of analyzing the input, connecting it to relevant concepts, and addressing each part of the user's request with clear explanations and examples, a comprehensive and accurate answer can be constructed.
这是一个定义 Linux 内核用户空间 API (UAPI) 中关于 IPv6 扩展头部 Segment Routing (SRv6) 的本地行为的头文件。它并没有实现任何具体的 C 库函数或动态链接功能，而是定义了一些枚举常量，用于配置和控制 SRv6 在本地设备上的行为。

**功能列举:**

这个头文件定义了以下几个主要方面的常量：

1. **`SEG6_LOCAL_UNSPEC` 到 `SEG6_LOCAL_MAX`:**  定义了可以配置的 SRv6 本地行为的类型，例如：
    * `SEG6_LOCAL_ACTION`:  定义当一个 SRv6 数据包到达其最后一个段时，本地设备应采取的动作。
    * `SEG6_LOCAL_SRH`:  可能与配置或处理 SRH（Segment Routing Header）有关。
    * `SEG6_LOCAL_TABLE`:  可能与本地 SRv6 策略或路由表配置相关。
    * `SEG6_LOCAL_NH4`, `SEG6_LOCAL_NH6`: 定义下一跳是 IPv4 还是 IPv6。
    * `SEG6_LOCAL_IIF`, `SEG6_LOCAL_OIF`: 定义入接口和出接口。
    * `SEG6_LOCAL_BPF`:  与使用 BPF (Berkeley Packet Filter) 进行 SRv6 本地处理相关。
    * `SEG6_LOCAL_VRFTABLE`:  可能与 VRF (Virtual Routing and Forwarding) 表格相关。
    * `SEG6_LOCAL_COUNTERS`:  与 SRv6 本地处理的计数器相关。
    * `SEG6_LOCAL_FLAVORS`: 定义 SRv6 本地行为的变体或风格。

2. **`SEG6_LOCAL_ACTION_UNSPEC` 到 `SEG6_LOCAL_ACTION_MAX`:** 定义了具体的本地动作类型，当数据包到达其最后一个段时可以执行的操作，例如：
    * `SEG6_LOCAL_ACTION_END`:  基本的结束动作。
    * `SEG6_LOCAL_ACTION_END_X`:  可能表示某种扩展的结束动作。
    * `SEG6_LOCAL_ACTION_END_T`:  可能涉及某种隧道处理。
    * `SEG6_LOCAL_ACTION_END_DX2`, `SEG6_LOCAL_ACTION_END_DX6`, `SEG6_LOCAL_ACTION_END_DX4`, `SEG6_LOCAL_ACTION_END_DT6`, `SEG6_LOCAL_ACTION_END_DT4`, `SEG6_LOCAL_ACTION_END_B6`, `SEG6_LOCAL_ACTION_END_B6_ENCAP`, `SEG6_LOCAL_ACTION_END_BM`, `SEG6_LOCAL_ACTION_END_S`, `SEG6_LOCAL_ACTION_END_AS`, `SEG6_LOCAL_ACTION_END_AM`: 这些都代表了不同的 SRv6 终端行为，可能涉及解封装、路由查找、策略执行等不同的操作。具体的含义需要参考 Linux 内核关于 SRv6 的文档。
    * `SEG6_LOCAL_ACTION_END_BPF`:  表示使用 BPF 程序来处理。
    * `SEG6_LOCAL_ACTION_END_DT46`:  可能涉及 IPv4/IPv6 之间的转换。

3. **`SEG6_LOCAL_BPF_PROG_UNSPEC` 到 `SEG6_LOCAL_BPF_PROG_MAX`:** 定义了与 BPF 程序相关的配置选项，例如加载或指定 BPF 程序。

4. **`SEG6_LOCAL_CNT_UNSPEC` 到 `SEG6_LOCAL_CNT_MAX`:** 定义了与 SRv6 本地处理相关的计数器类型，例如统计处理的包数、字节数和错误数。

5. **`SEG6_LOCAL_FLV_UNSPEC` 到 `SEG6_LOCAL_FLV_MAX` 和 `SEG6_LOCAL_FLV_OP_UNSPEC` 到 `SEG6_LOCAL_FLV_OP_MAX`:** 定义了 SRv6 本地行为风格及其操作，例如 PSP (Penultimate Segment Pop), USP (Ultimate Segment Pop), USD (Ultimate Segment Decapsulation) 等。

**与 Android 功能的关系举例:**

SRv6 是一种网络技术，它允许在 IPv6 数据包头中携带路由信息，使得网络可以基于这些信息进行灵活的路由。虽然普通的 Android 应用程序不太可能直接使用这些常量，但在 Android 系统底层的网络组件中可能会用到，例如：

* **网络守护进程 (netd):**  `netd` 负责处理 Android 系统的网络配置和管理，它可能会使用这些常量来配置 Linux 内核的 SRv6 功能。例如，通过 `ioctl` 系统调用或者 Netlink 接口，`netd` 可以设置 SRv6 的本地行为，比如当数据包到达本地时应该执行哪个 `SEG6_LOCAL_ACTION`。
* **虚拟化/容器化:** 在 Android 系统中如果使用了网络虚拟化或容器化技术，这些常量可能用于配置虚拟机或容器的网络栈中的 SRv6 功能。

**举例说明:** 假设 Android 设备作为 SRv6 网络中的一个节点，并且需要配置当发往该设备的数据包的 SRH 最后一个段指向本地时，执行 `SEG6_LOCAL_ACTION_END_DX6` 操作（具体的含义需要查阅内核文档，但通常可能涉及解封装 IPv6）。`netd` 这样的网络管理进程可能会使用 `ioctl` 系统调用，并传递包含 `SEG6_LOCAL_ACTION` 和 `SEG6_LOCAL_ACTION_END_DX6` 值的参数来配置内核。

**libc 函数的功能实现:**

这个头文件本身并没有包含任何 libc 函数的实现。它只是定义了一些宏和枚举常量。libc 函数（例如 `socket`, `bind`, `ioctl` 等）可能会在内部使用这些常量，或者允许应用程序通过这些常量来与内核的网络子系统进行交互。

例如，`ioctl` 函数可以用于向设备驱动程序发送控制命令。在配置 SRv6 本地行为时，可能会使用 `ioctl` 函数，并且需要指定与 SRv6 相关的操作码和数据结构，而这些数据结构中可能会用到这里定义的常量。

**涉及 dynamic linker 的功能:**

这个头文件与 dynamic linker (动态链接器) 没有直接关系。dynamic linker 的主要职责是在程序启动时加载所需的共享库，并解析符号引用。这个头文件定义的是内核的网络配置常量，属于内核 UAPI 的一部分。

**SO 布局样本和链接的处理过程 (仅为示例):**

虽然这个头文件本身不涉及动态链接，但如果某个 Android 的网络库（例如 `libnetd_client.so`）需要使用 SRv6 相关的功能，它可能会间接地依赖于内核提供的接口。

假设 `libnetd_client.so` 中有如下代码（简化示例）：

```c
#include <sys/ioctl.h>
#include <linux/seg6_local.h>

// ...

int configure_srv6_local_action(int socket_fd) {
  struct {
    int cmd;
    int action;
  } request;

  request.cmd = /* 某个与 SRv6 本地行为配置相关的 ioctl 命令 */;
  request.action = SEG6_LOCAL_ACTION_END_DX6; // 使用头文件中定义的常量

  if (ioctl(socket_fd, request.cmd, &request) < 0) {
    perror("ioctl failed");
    return -1;
  }
  return 0;
}
```

**链接处理过程：**

1. 当一个使用 `libnetd_client.so` 的进程启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载 `libnetd_client.so` 到内存中。
2. 如果 `libnetd_client.so` 中使用了标准 C 库函数（例如 `ioctl`, `perror`），dynamic linker 会解析这些符号，并将它们链接到 Bionic libc (`/system/lib64/libc.so` 或 `/system/lib/libc.so`) 中对应的实现。
3. **重点：**  `SEG6_LOCAL_ACTION_END_DX6` 这样的常量在编译时会被替换为其对应的数值。这个头文件只是在编译时提供这些常量的定义，dynamic linker 不会直接处理这个头文件。

**SO 布局样本 (简化):**

```
/system/lib64/libc.so  // Bionic C 库
/system/lib64/libnetd_client.so // 可能包含使用 SRv6 功能的代码

libnetd_client.so 的部分内容 (内存布局示意):
----------------------------------------
| .text (代码段)                       |
|   - configure_srv6_local_action 函数 |
| .data (数据段)                       |
| .rodata (只读数据段)                  |
| .dynamic (动态链接信息)             |
|   - NEEDED libc.so                  |
|   - SYMTAB (符号表，包含 configure_srv6_local_action 等符号) |
|   - STRTAB (字符串表)                |
----------------------------------------
```

**逻辑推理，假设输入与输出:**

这个头文件主要定义常量，不涉及复杂的逻辑推理。它的作用是提供符号化的名称来代替硬编码的数字，提高代码的可读性和可维护性。

**假设输入：**  一个程序想要配置 SRv6 本地行为，使其在接收到目标地址为本地的 SRv6 数据包时执行 "END_DT6" 操作。

**使用头文件中的常量：**  程序会使用 `SEG6_LOCAL_ACTION` 和 `SEG6_LOCAL_ACTION_END_DT6` 常量来构造配置信息。

**输出：**  通过系统调用（如 `ioctl`），内核网络子系统会根据配置信息设置相应的 SRv6 处理逻辑。当满足条件的数据包到达时，内核会执行预期的 "END_DT6" 操作（具体的内核行为不在这个头文件的定义范围内）。

**用户或编程常见的使用错误:**

1. **使用了错误的常量值:** 开发者可能会错误地使用了 `SEG6_LOCAL_ACTION` 枚举中的某个值，导致配置了错误的 SRv6 本地行为。例如，本意是使用 `SEG6_LOCAL_ACTION_END`，却错误地使用了 `SEG6_LOCAL_ACTION_END_X`。
2. **内核版本不兼容:**  这些常量是内核 UAPI 的一部分，不同版本的 Linux 内核可能支持不同的 SRv6 功能和常量。如果应用程序使用的常量在当前运行的 Android 设备内核中不存在，可能会导致配置失败或未定义的行为。
3. **权限不足:** 配置内核网络功能通常需要 root 权限或特定的网络管理权限。普通应用程序可能无法成功调用相关的系统调用来配置 SRv6。

**Android framework 或 ndk 是如何一步步的到达这里:**

1. **Android Framework (Java/Kotlin):** 高层 Android Framework 中的应用程序通常不会直接操作这些底层的网络配置。
2. **Native 代码 (NDK):** 如果需要进行底层的网络操作，开发者可能会使用 NDK 编写 C/C++ 代码。
3. **系统服务 (System Services):**  像 `netd` 这样的系统服务通常负责处理底层的网络配置。这些服务使用 native 代码编写，并会调用 Bionic libc 提供的系统调用接口。
4. **Bionic libc:**  `netd` 等系统服务会使用 Bionic libc 提供的函数，例如 `socket` 创建套接字，`ioctl` 发送控制命令到内核。
5. **系统调用 (System Calls):**  `ioctl` 函数最终会触发一个系统调用，进入 Linux 内核。
6. **内核网络子系统:**  内核接收到系统调用后，网络子系统会解析 `ioctl` 命令和参数，并根据这些参数配置 SRv6 的本地行为。这里，`bionic/libc/kernel/uapi/linux/seg6_local.h` 中定义的常量会被内核使用或比对。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `ioctl` 系统调用，并过滤与 SRv6 相关的命令，来观察 Android 系统如何配置 SRv6 本地行为。

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
        return

    try:
        process = frida.get_usb_device().attach(sys.argv[1])
    except frida.ProcessNotFoundError:
        print("Process not found")
        return

    script_code = """
    'use strict';

    // Function to ab2hex a Uint8Array
    function ab2hex(ab) {
      return Array.prototype.map.call(new Uint8Array(ab), x => ('00' + x.toString(16)).slice(-2)).join('');
    }

    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();
            const argp = args[2];

            // 检查是否是与网络相关的 socket
            const sock_type = this.context.socket ? Memory.readU32(this.context.socket.add(0x4)) : -1; // 假设 socket 结构体布局

            // 粗略判断是否是与 SRv6 相关的 ioctl 命令 (需要根据具体的命令值判断)
            // 这里只是一个示例，你需要查找实际的 SRv6 ioctl 命令值
            const SRV6_BASE = 0xA0; // 假设 SRv6 相关的 ioctl 命令以 0xA0 开头
            if ((request >> 8) == SRV6_BASE) {
                send({
                    type: 'info',
                    payload: `ioctl called with fd: ${fd}, request: 0x${request.toString(16)}, argp: ${argp}`
                });

                // 可以尝试读取 argp 指向的数据，解析 SRv6 配置信息
                // 注意：需要知道数据结构的布局
                try {
                    // 示例：假设配置信息是一个包含 action 字段的结构体
                    const action = Memory.readU32(argp.add(4)); // 假设 action 字段偏移为 4
                    send({
                        type: 'info',
                        payload: `  SRv6 Action: ${action}`
                    });
                } catch (e) {
                    send({
                        type: 'error',
                        payload: `  Error reading argp: ${e}`
                    });
                }
            }
        },
        onLeave: function(retval) {
            //console.log("ioctl returned:", retval);
        }
    });
    """

    script = process.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Running, press Ctrl+C to stop")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("[*] Stopping")
        script.unload()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将上述 Python 代码保存为 `frida_hook_srv6.py`。
2. 替换代码中的 `SRV6_BASE` 和读取 `argp` 的逻辑，以匹配实际的 SRv6 `ioctl` 命令和数据结构。你需要查阅 Linux 内核的 `uapi/linux/if_arp.h` 或相关的头文件来找到与 SRv6 相关的 `ioctl` 命令值。
3. 运行 Frida，指定要 hook 的进程名称或 PID，例如：
   ```bash
   python frida_hook_srv6.py com.android.netd
   ```
   或
   ```bash
   python frida_hook_srv6.py $(pidof com.android.netd)
   ```
4. 当系统进行 SRv6 相关配置时，Frida 会拦截 `ioctl` 调用，并打印出相关的参数，包括 `request` 值（可能包含 `SEG6_LOCAL_ACTION` 等常量的值）以及指向配置数据的指针。

**请注意:**  上述 Frida 脚本只是一个基本示例，你需要根据具体的 SRv6 `ioctl` 命令和数据结构来调整脚本，才能正确地解析和显示 SRv6 的配置信息。 调试内核相关的操作通常比较复杂，需要对 Linux 内核的网络子系统有一定的了解。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/seg6_local.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_SEG6_LOCAL_H
#define _UAPI_LINUX_SEG6_LOCAL_H
#include <linux/seg6.h>
enum {
  SEG6_LOCAL_UNSPEC,
  SEG6_LOCAL_ACTION,
  SEG6_LOCAL_SRH,
  SEG6_LOCAL_TABLE,
  SEG6_LOCAL_NH4,
  SEG6_LOCAL_NH6,
  SEG6_LOCAL_IIF,
  SEG6_LOCAL_OIF,
  SEG6_LOCAL_BPF,
  SEG6_LOCAL_VRFTABLE,
  SEG6_LOCAL_COUNTERS,
  SEG6_LOCAL_FLAVORS,
  __SEG6_LOCAL_MAX,
};
#define SEG6_LOCAL_MAX (__SEG6_LOCAL_MAX - 1)
enum {
  SEG6_LOCAL_ACTION_UNSPEC = 0,
  SEG6_LOCAL_ACTION_END = 1,
  SEG6_LOCAL_ACTION_END_X = 2,
  SEG6_LOCAL_ACTION_END_T = 3,
  SEG6_LOCAL_ACTION_END_DX2 = 4,
  SEG6_LOCAL_ACTION_END_DX6 = 5,
  SEG6_LOCAL_ACTION_END_DX4 = 6,
  SEG6_LOCAL_ACTION_END_DT6 = 7,
  SEG6_LOCAL_ACTION_END_DT4 = 8,
  SEG6_LOCAL_ACTION_END_B6 = 9,
  SEG6_LOCAL_ACTION_END_B6_ENCAP = 10,
  SEG6_LOCAL_ACTION_END_BM = 11,
  SEG6_LOCAL_ACTION_END_S = 12,
  SEG6_LOCAL_ACTION_END_AS = 13,
  SEG6_LOCAL_ACTION_END_AM = 14,
  SEG6_LOCAL_ACTION_END_BPF = 15,
  SEG6_LOCAL_ACTION_END_DT46 = 16,
  __SEG6_LOCAL_ACTION_MAX,
};
#define SEG6_LOCAL_ACTION_MAX (__SEG6_LOCAL_ACTION_MAX - 1)
enum {
  SEG6_LOCAL_BPF_PROG_UNSPEC,
  SEG6_LOCAL_BPF_PROG,
  SEG6_LOCAL_BPF_PROG_NAME,
  __SEG6_LOCAL_BPF_PROG_MAX,
};
#define SEG6_LOCAL_BPF_PROG_MAX (__SEG6_LOCAL_BPF_PROG_MAX - 1)
enum {
  SEG6_LOCAL_CNT_UNSPEC,
  SEG6_LOCAL_CNT_PAD,
  SEG6_LOCAL_CNT_PACKETS,
  SEG6_LOCAL_CNT_BYTES,
  SEG6_LOCAL_CNT_ERRORS,
  __SEG6_LOCAL_CNT_MAX,
};
#define SEG6_LOCAL_CNT_MAX (__SEG6_LOCAL_CNT_MAX - 1)
enum {
  SEG6_LOCAL_FLV_UNSPEC,
  SEG6_LOCAL_FLV_OPERATION,
  SEG6_LOCAL_FLV_LCBLOCK_BITS,
  SEG6_LOCAL_FLV_LCNODE_FN_BITS,
  __SEG6_LOCAL_FLV_MAX,
};
#define SEG6_LOCAL_FLV_MAX (__SEG6_LOCAL_FLV_MAX - 1)
enum {
  SEG6_LOCAL_FLV_OP_UNSPEC,
  SEG6_LOCAL_FLV_OP_PSP,
  SEG6_LOCAL_FLV_OP_USP,
  SEG6_LOCAL_FLV_OP_USD,
  SEG6_LOCAL_FLV_OP_NEXT_CSID,
  __SEG6_LOCAL_FLV_OP_MAX
};
#define SEG6_LOCAL_FLV_OP_MAX (__SEG6_LOCAL_FLV_OP_MAX - 1)
#endif
```