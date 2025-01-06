Response:
Let's break down the thought process for answering the user's request about the `mrp_bridge.h` header file.

**1. Understanding the Core Request:**

The user provided a header file and asked for a comprehensive analysis covering its functionality, relationship to Android, explanation of libc functions (even though there aren't any directly in this file), dynamic linker aspects (again, not directly present but relevant contextually), potential errors, and how Android frameworks reach this level, along with a Frida hook example.

**2. Initial Analysis of the Header File:**

The first and most crucial step is to carefully read the header file. Key observations:

* **Auto-generated:** The comment at the top immediately tells us this isn't manually written code, but rather generated, likely from some higher-level definition. This has implications for understanding its purpose – it represents a low-level interface.
* **`#ifndef`, `#define`, `#include`:** These are standard C preprocessor directives for header file inclusion guards and including other headers. `linux/types.h` and `linux/if_ether.h` indicate this is related to the Linux kernel networking subsystem.
* **Constants (`#define`):**  These define various numerical values like maximum frame length, default priority, lengths of UUIDs and OUI, and a version number. These constants likely define parameters for the MRP protocol.
* **Enums (`enum`):**  This is the bulk of the file. The enums define different states and roles within the MRP (Media Redundancy Protocol) bridge context. The names are quite descriptive: `br_mrp_ring_role_type`, `br_mrp_in_role_type`, `br_mrp_ring_state_type`, etc. This strongly suggests the file defines the data structures and states for configuring and monitoring an MRP bridge.
* **TLV Structure:** The `br_mrp_tlv_header_type` and `br_mrp_sub_tlv_header_type` enums point to the use of Type-Length-Value (TLV) encoding for exchanging information within the MRP protocol. This is a common way to structure variable-length messages.

**3. Connecting to Android:**

The prompt mentions "bionic," Android's C library. The file path `bionic/libc/kernel/uapi/linux/` strongly suggests this header defines a *userspace* interface to a *kernel* feature. This is a critical distinction. While the *implementation* of MRP bridging lives in the Linux kernel, this header provides the *definitions* that Android (user-space processes) uses to interact with it.

**4. Addressing Specific Questions (and Adjusting for Reality):**

* **Functionality:** Based on the analysis of enums and constants, the primary function is clearly related to the configuration and monitoring of Media Redundancy Protocol (MRP) bridging within the Linux kernel, as exposed to Android userspace.
* **Relationship to Android:** The key is the userspace-kernel interaction. Android's networking stack (at a lower level) would use these definitions to configure the kernel's MRP bridge functionality.
* **`libc` Functions:**  **Crucially, the header file *itself* contains no `libc` functions.**  This is an important point to address accurately. The interaction with the kernel is likely done through system calls (like `ioctl`) that are part of `libc`.
* **Dynamic Linker:** Again, the header doesn't directly involve the dynamic linker. However, *code* that *uses* this header (like a library or service) *would* be linked by the dynamic linker.
* **Logic Reasoning (Assumptions):**  Since it's a header file, direct logic reasoning isn't really applicable in terms of input/output. The "logic" is in how the kernel uses these definitions. We can make assumptions about how different states might trigger actions.
* **User Errors:** Misconfiguration of these low-level parameters (e.g., incorrect role settings) would be the main source of errors.
* **Android Framework/NDK Path:** This requires understanding the layers of Android. A high-level framework component would eventually translate a request into a lower-level system call, likely involving `ioctl` and data structures defined by this header.
* **Frida Hook:**  The challenge here is *what* to hook. Since the header has no functions, you'd hook the *system call* that uses these definitions (like `ioctl`) or functions in a library that utilizes this header.

**5. Structuring the Answer:**

A logical structure is important for clarity. The provided answer follows a good structure:

* **Introduction:** Briefly describe the file and its context.
* **Functionality:**  Explain the core purpose of defining MRP bridge parameters.
* **Relationship to Android:**  Clarify the userspace-kernel boundary.
* **`libc` Functions:**  Address the prompt directly, explaining that there are none in *this* file but that `ioctl` is the likely interface.
* **Dynamic Linker:** Explain its indirect role and provide a hypothetical SO layout.
* **Logic Reasoning:**  Give an example of how the states might interact.
* **User Errors:** Provide common misconfiguration examples.
* **Android Framework/NDK Path:** Detail the journey from framework to kernel.
* **Frida Hook:**  Give a practical example of hooking `ioctl`.

**Self-Correction/Refinement during the Thought Process:**

* **Initial Thought:** "Oh, it's `bionic`, so it must have `libc` functions."  **Correction:**  Realize that `bionic` encompasses more than just `libc`. This file is in the `kernel/uapi` directory, meaning it's a userspace interface to kernel structures, not part of the `libc` implementation itself.
* **Initial Thought:** "How does the dynamic linker play a role here?" **Correction:** Recognize that while the *header* isn't directly used by the linker, code that *includes* this header will be linked. So, the connection is indirect.
* **Frida Hooking:**  Initially think about hooking something *within* the header. **Correction:** Realize that you need to hook the *syscall* or a *function* that *uses* the definitions from this header.

By following these steps and incorporating self-correction, we arrive at a comprehensive and accurate answer to the user's request. The key is to understand the *context* of the header file within the Android and Linux ecosystems.

这个文件 `bionic/libc/kernel/uapi/linux/mrp_bridge.handroid` 定义了用于配置和控制 Linux 内核中 **媒体冗余协议 (Media Redundancy Protocol, MRP)** 桥接功能的 **用户空间应用程序接口 (UAPI)**。由于它位于 `bionic/libc/kernel/uapi` 路径下，这表明它是 Android 系统中用于与 Linux 内核交互的一部分。

**文件功能:**

该文件定义了以下内容，用于用户空间程序与内核中的 MRP 桥接模块进行通信：

1. **常量定义 (`#define`)**:
   - `MRP_MAX_FRAME_LENGTH`:  定义了 MRP 帧的最大长度。
   - `MRP_DEFAULT_PRIO`:  定义了 MRP 帧的默认优先级。
   - `MRP_DOMAIN_UUID_LENGTH`:  定义了 MRP 域 UUID 的长度。
   - `MRP_VERSION`:  定义了 MRP 协议的版本号。
   - `MRP_FRAME_PRIO`: 定义了 MRP 帧优先级的位数。
   - `MRP_OUI_LENGTH`: 定义了组织唯一标识符 (OUI) 的长度。
   - `MRP_MANUFACTURE_DATA_LENGTH`: 定义了制造商数据的长度。

2. **枚举类型 (`enum`)**:
   - `br_mrp_ring_role_type`: 定义了 MRP 环的角色类型，例如禁用 (`BR_MRP_RING_ROLE_DISABLED`)、主环控制者 (`BR_MRP_RING_ROLE_MRC`)、主环管理器 (`BR_MRP_RING_ROLE_MRM`)、主环代理 (`BR_MRP_RING_ROLE_MRA`)。这些角色定义了环中不同节点的职责。
   - `br_mrp_in_role_type`: 定义了内部环的角色类型，类似于外部环，有禁用 (`BR_MRP_IN_ROLE_DISABLED`)、内部环控制者 (`BR_MRP_IN_ROLE_MIC`)、内部环管理器 (`BR_MRP_IN_ROLE_MIM`)。
   - `br_mrp_ring_state_type`: 定义了 MRP 环的状态，例如打开 (`BR_MRP_RING_STATE_OPEN`) 和关闭 (`BR_MRP_RING_STATE_CLOSED`)。
   - `br_mrp_in_state_type`: 定义了内部环的状态，例如打开 (`BR_MRP_IN_STATE_OPEN`) 和关闭 (`BR_MRP_IN_STATE_CLOSED`)。
   - `br_mrp_port_state_type`: 定义了 MRP 端口的状态，例如禁用 (`BR_MRP_PORT_STATE_DISABLED`)、阻塞 (`BR_MRP_PORT_STATE_BLOCKED`)、转发 (`BR_MRP_PORT_STATE_FORWARDING`)、未连接 (`BR_MRP_PORT_STATE_NOT_CONNECTED`)。
   - `br_mrp_port_role_type`: 定义了 MRP 端口的角色，例如主端口 (`BR_MRP_PORT_ROLE_PRIMARY`)、次端口 (`BR_MRP_PORT_ROLE_SECONDARY`)、互连端口 (`BR_MRP_PORT_ROLE_INTER`)。
   - `br_mrp_tlv_header_type`: 定义了 MRP 消息中类型-长度-值 (TLV) 结构中头的类型，用于标识不同的 MRP 消息类型，例如结束 (`BR_MRP_TLV_HEADER_END`)、通用 (`BR_MRP_TLV_HEADER_COMMON`)、环测试 (`BR_MRP_TLV_HEADER_RING_TEST`) 等等。这些头定义了不同的 MRP 控制和状态信息。
   - `br_mrp_sub_tlv_header_type`: 定义了 MRP 消息中子 TLV 结构的头类型，用于更细粒度的信息标识，例如测试管理器 NACK (`BR_MRP_SUB_TLV_HEADER_TEST_MGR_NACK`)、测试传播 (`BR_MRP_SUB_TLV_HEADER_TEST_PROPAGATE`) 等。

**与 Android 功能的关系及举例说明:**

这个头文件定义了与 **网络冗余** 相关的底层机制。MRP 是一种二层协议，用于提高工业以太网等网络的可靠性。在网络设备（如交换机）之间形成环状拓扑，当环中的某个链路发生故障时，MRP 可以快速切换路径，保证网络连接的持续性。

在 Android 系统中，虽然普通的应用开发者可能不会直接接触到 MRP，但它可能在以下场景中发挥作用：

* **工业自动化设备:**  如果 Android 被用作工业控制系统的一部分，连接到支持 MRP 的工业以太网，那么 Android 系统需要能够配置和管理其 MRP 端口。这个头文件就提供了这样的接口。
* **车载以太网:**  在一些高级车载网络中，也可能使用类似 MRP 的冗余协议来提高关键通信的可靠性。Android Automotive 系统可能会使用这些定义来配置车辆网络接口。

**举例说明:**

假设一个 Android 设备充当工业自动化网络中的一个节点，并且连接到一个 MRP 环。Android 系统需要配置其网络接口以参与 MRP 协议。这可能涉及到设置端口角色（例如，作为主端口或次端口），配置环的角色（如果设备是环管理器），以及监控环的状态。相关的配置信息（例如端口状态、环状态）会使用这个头文件中定义的枚举类型来表示。

**libc 函数的功能实现:**

**这个头文件本身并没有定义任何 libc 函数。** 它只是一个包含常量和类型定义的头文件。用户空间的程序会使用这些定义来构建与内核通信的数据结构，然后通过 **系统调用 (system calls)** 与内核中的 MRP 桥接模块进行交互。

常见的系统调用包括：

* **`ioctl`**:  这可能是最常用的系统调用，用于配置和控制设备。用户空间的程序可能会使用 `ioctl` 系统调用，并传递包含这个头文件中定义的常量和枚举值的结构体，来设置 MRP 桥接的参数，例如设置端口角色、环角色、启用/禁用 MRP 等。

**详细解释 `ioctl` 的功能实现 (以假设的场景为例):**

1. **用户空间程序:**  一个 Android 应用程序或者系统服务想要配置某个网络接口参与 MRP 协议。它会包含 `mrp_bridge.h` 头文件，并使用其中定义的常量和枚举类型来填充一个表示 MRP 配置信息的结构体。

2. **系统调用 `ioctl`:** 程序调用 `ioctl` 系统调用，指定要操作的网络接口的文件描述符，以及一个特定的 **`ioctl` 命令码 (ioctl command code)**，该命令码指示内核要执行 MRP 相关的操作，比如配置端口角色。同时，程序会将包含 MRP 配置信息的结构体指针作为 `ioctl` 的参数传递给内核。

3. **内核处理:**
   - Linux 内核接收到 `ioctl` 系统调用后，会根据提供的文件描述符找到对应的网络设备驱动。
   - 内核会根据 `ioctl` 命令码，调用相应的内核函数来处理 MRP 配置请求。
   - 内核函数会解析用户空间传递过来的结构体，提取 MRP 配置信息，例如端口角色、环角色等。
   - 内核会根据这些配置信息，更新网络设备的内部状态，并启动或停止相关的 MRP 协议处理流程。

**涉及 dynamic linker 的功能:**

这个头文件本身不涉及 dynamic linker 的功能。Dynamic linker 的主要职责是加载共享库 (shared objects, .so 文件) 并解析符号依赖关系。

**SO 布局样本 (假设一个使用 MRP 配置功能的共享库):**

```
libmrpconfig.so:
    .text           # 包含代码段
        mrp_port_set_role()  # 设置 MRP 端口角色的函数
        mrp_ring_get_status() # 获取 MRP 环状态的函数
        ...
    .data           # 包含已初始化的全局变量
    .bss            # 包含未初始化的全局变量
    .dynsym         # 动态符号表
        mrp_port_set_role
        mrp_ring_get_status
        ioctl          # 依赖的 libc 函数
    .dynstr         # 动态字符串表
        libc.so
    .plt            # 程序链接表 (Procedure Linkage Table)
        ioctl
    .got.plt        # 全局偏移表 (Global Offset Table) 的 PLT 部分
        地址占位符，用于运行时解析 ioctl 的地址
```

**链接的处理过程:**

1. **编译时:** 当编译 `libmrpconfig.so` 时，编译器会识别出对 `ioctl` 函数的调用。由于 `ioctl` 是 libc 的一部分，编译器会在生成的动态符号表中记录对 `ioctl` 的依赖。

2. **加载时:** 当 Android 系统加载 `libmrpconfig.so` 时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会执行以下操作：
   - **加载依赖库:** Dynamic linker 会检查 `libmrpconfig.so` 的依赖关系，发现它依赖于 `libc.so`，因此会加载 `libc.so` 到内存中。
   - **符号解析:** Dynamic linker 会解析 `libmrpconfig.so` 中对外部符号（例如 `ioctl`）的引用。它会在 `libc.so` 的符号表中查找 `ioctl` 的地址。
   - **重定位:** Dynamic linker 会更新 `libmrpconfig.so` 的 `.got.plt` 表中的条目，将 `ioctl` 的占位符地址替换为在 `libc.so` 中找到的实际地址。这样，当 `libmrpconfig.so` 中的代码调用 `ioctl` 时，实际上会跳转到 `libc.so` 中 `ioctl` 函数的实现。

**逻辑推理 (假设输入与输出):**

假设用户空间程序想要将网络接口 `eth0` 的 MRP 端口角色设置为 `BR_MRP_PORT_ROLE_PRIMARY`。

**假设输入:**

* 网络接口名称: "eth0"
* 目标端口角色: `BR_MRP_PORT_ROLE_PRIMARY` (其值为 0)

**处理过程 (模拟内核行为):**

1. 用户空间程序会构造一个包含网络接口名称和目标端口角色的数据结构。
2. 程序调用 `ioctl` 系统调用，命令码指示设置 MRP 端口角色，并将该数据结构传递给内核。
3. 内核的网络驱动程序接收到 `ioctl` 调用。
4. 内核解析数据结构，提取网络接口名称 "eth0" 和目标端口角色 `BR_MRP_PORT_ROLE_PRIMARY`。
5. 内核会查找名为 "eth0" 的网络接口。
6. 内核会将该接口的 MRP 端口角色设置为 Primary。

**假设输出 (可能通过后续的 `ioctl` 调用获取):**

* 当查询 `eth0` 的 MRP 端口角色时，返回 `BR_MRP_PORT_ROLE_PRIMARY`。
* 如果 MRP 环的状态发生变化，例如由于端口角色改变而触发了环拓扑变化，内核会发出相应的事件通知（但这通常不是 `ioctl` 的直接输出）。

**用户或编程常见的使用错误:**

1. **使用了错误的 `ioctl` 命令码:**  如果用户空间程序使用了错误的 `ioctl` 命令码，内核可能无法识别请求，导致操作失败或产生未预期的行为。

2. **传递了无效的参数:**  例如，传递了不存在的网络接口名称，或者使用了超出枚举范围的端口角色值。这会导致内核校验失败，`ioctl` 调用返回错误。

3. **权限不足:** 配置网络接口通常需要 root 权限。如果应用程序没有足够的权限调用 `ioctl`，操作将会失败。

4. **在不适当的时机进行配置:**  例如，在网络接口未启动或 MRP 模块未加载时尝试配置 MRP 参数，可能会导致错误。

**Frida hook 示例调试步骤:**

假设我们想监控用户空间程序如何设置 MRP 端口角色。我们可以使用 Frida hook `ioctl` 系统调用来观察传递的参数。

**Frida Hook 示例 (Python):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received message: {message['payload']}")
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <process name or PID>")
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
            const argp = args[2];

            // 假设设置 MRP 端口角色的 ioctl 命令码是某个特定的值，例如 0x89XX
            const MRP_SET_PORT_ROLE = 0x89XX; // 需要替换成实际的命令码

            if (request === MRP_SET_PORT_ROLE) {
                console.log("[*] ioctl called with MRP_SET_PORT_ROLE");
                console.log("    File Descriptor:", fd);
                console.log("    Request Code:", request);

                // 读取传递给 ioctl 的结构体内容 (需要根据实际结构体定义进行解析)
                // 假设结构体包含接口名称和端口角色
                // const ifnamePtr = argp.readPointer();
                // const ifname = ifnamePtr.readCString();
                // const portRole = argp.add(offset_of_port_role).readU32(); // 需要知道端口角色在结构体中的偏移

                // console.log("    Interface Name:", ifname);
                // console.log("    Port Role:", portRole);
            }
        },
        onLeave: function(retval) {
            // console.log("Return value:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print(f"[*] Hooking ioctl in process '{target}'. Press Ctrl+C to stop.")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**调试步骤:**

1. **找到目标进程:** 确定哪个 Android 进程或服务可能调用与 MRP 相关的 `ioctl`。

2. **确定 `ioctl` 命令码:** 需要找到用于设置 MRP 端口角色的实际 `ioctl` 命令码。这可能需要查看相关的内核源代码或网络驱动程序代码。

3. **分析数据结构:**  了解传递给 `ioctl` 的数据结构的布局，包括接口名称和端口角色等字段的偏移量和类型。

4. **编写 Frida 脚本:**  编写 Frida 脚本，hook `ioctl` 系统调用，并在 `onEnter` 中检查 `ioctl` 的命令码是否匹配目标命令码。如果匹配，则尝试读取和解析传递的参数。

5. **运行 Frida 脚本:**  使用 Frida 连接到目标进程，运行脚本。

6. **触发操作:**  在 Android 设备上执行触发 MRP 端口角色设置的操作。

7. **观察输出:**  Frida 脚本会在控制台上打印出 `ioctl` 调用的相关信息，包括文件描述符、命令码以及传递的参数值，从而帮助我们理解用户空间程序是如何与内核进行交互的。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **高层 Framework API:**  用户或应用程序可能通过 Android Framework 提供的网络配置 API 进行操作，例如 `ConnectivityManager` 或 `NetworkPolicyManager`。这些 API 通常是 Java 接口。

2. **System Services:** Framework API 的请求会被传递给相应的系统服务，例如 `NetworkManagementService`。这些服务通常运行在独立的进程中。

3. **JNI 调用:** 系统服务可能需要调用底层的 C/C++ 代码来执行网络配置操作。这通常通过 Java Native Interface (JNI) 完成。系统服务会调用 native 方法，这些方法会调用到 NDK 提供的库。

4. **NDK 库:** NDK 库可能会封装一些底层的网络配置逻辑。在涉及到 MRP 这样的底层协议时，NDK 库可能会直接或者间接地调用 `ioctl` 系统调用。

5. **Bionic libc:** NDK 库最终会通过 Bionic libc 提供的 `syscall()` 函数或封装好的 `ioctl()` 函数来发起系统调用。`ioctl()` 函数会根据提供的文件描述符、命令码和参数，将请求传递给 Linux 内核。

6. **Linux Kernel:** Linux 内核接收到 `ioctl` 系统调用后，会根据文件描述符找到对应的网络设备驱动程序。驱动程序会解析 `ioctl` 命令码和参数，并执行相应的 MRP 配置操作。在处理过程中，内核会使用 `bionic/libc/kernel/uapi/linux/mrp_bridge.h` 中定义的常量和枚举类型来解释和操作配置信息。

总结来说，Android Framework 的高层操作会逐步向下传递，经过系统服务、JNI 调用、NDK 库，最终通过 Bionic libc 发起系统调用到达 Linux 内核，而 `mrp_bridge.h` 定义了用户空间与内核交互时使用的数据结构和常量。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/mrp_bridge.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_MRP_BRIDGE_H_
#define _UAPI_LINUX_MRP_BRIDGE_H_
#include <linux/types.h>
#include <linux/if_ether.h>
#define MRP_MAX_FRAME_LENGTH 200
#define MRP_DEFAULT_PRIO 0x8000
#define MRP_DOMAIN_UUID_LENGTH 16
#define MRP_VERSION 1
#define MRP_FRAME_PRIO 7
#define MRP_OUI_LENGTH 3
#define MRP_MANUFACTURE_DATA_LENGTH 2
enum br_mrp_ring_role_type {
  BR_MRP_RING_ROLE_DISABLED,
  BR_MRP_RING_ROLE_MRC,
  BR_MRP_RING_ROLE_MRM,
  BR_MRP_RING_ROLE_MRA,
};
enum br_mrp_in_role_type {
  BR_MRP_IN_ROLE_DISABLED,
  BR_MRP_IN_ROLE_MIC,
  BR_MRP_IN_ROLE_MIM,
};
enum br_mrp_ring_state_type {
  BR_MRP_RING_STATE_OPEN,
  BR_MRP_RING_STATE_CLOSED,
};
enum br_mrp_in_state_type {
  BR_MRP_IN_STATE_OPEN,
  BR_MRP_IN_STATE_CLOSED,
};
enum br_mrp_port_state_type {
  BR_MRP_PORT_STATE_DISABLED,
  BR_MRP_PORT_STATE_BLOCKED,
  BR_MRP_PORT_STATE_FORWARDING,
  BR_MRP_PORT_STATE_NOT_CONNECTED,
};
enum br_mrp_port_role_type {
  BR_MRP_PORT_ROLE_PRIMARY,
  BR_MRP_PORT_ROLE_SECONDARY,
  BR_MRP_PORT_ROLE_INTER,
};
enum br_mrp_tlv_header_type {
  BR_MRP_TLV_HEADER_END = 0x0,
  BR_MRP_TLV_HEADER_COMMON = 0x1,
  BR_MRP_TLV_HEADER_RING_TEST = 0x2,
  BR_MRP_TLV_HEADER_RING_TOPO = 0x3,
  BR_MRP_TLV_HEADER_RING_LINK_DOWN = 0x4,
  BR_MRP_TLV_HEADER_RING_LINK_UP = 0x5,
  BR_MRP_TLV_HEADER_IN_TEST = 0x6,
  BR_MRP_TLV_HEADER_IN_TOPO = 0x7,
  BR_MRP_TLV_HEADER_IN_LINK_DOWN = 0x8,
  BR_MRP_TLV_HEADER_IN_LINK_UP = 0x9,
  BR_MRP_TLV_HEADER_IN_LINK_STATUS = 0xa,
  BR_MRP_TLV_HEADER_OPTION = 0x7f,
};
enum br_mrp_sub_tlv_header_type {
  BR_MRP_SUB_TLV_HEADER_TEST_MGR_NACK = 0x1,
  BR_MRP_SUB_TLV_HEADER_TEST_PROPAGATE = 0x2,
  BR_MRP_SUB_TLV_HEADER_TEST_AUTO_MGR = 0x3,
};
#endif

"""

```