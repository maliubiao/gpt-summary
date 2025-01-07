Response:
Let's break down the thought process to answer the prompt effectively.

**1. Understanding the Core Request:**

The central request is to analyze a Linux kernel UAPI header file (`thermal.h`) within the context of Android's Bionic library. The goal is to understand its functionality, its relation to Android, the underlying implementation (where applicable), potential errors, and how Android frameworks interact with it.

**2. Initial Analysis of the Header File:**

* **`auto-generated`:** This is a key piece of information. It means the file is not directly written by humans but generated from some other source (likely a more abstract description of the thermal management interface). This implies the file primarily *defines* things rather than *implements* them.
* **`#ifndef _UAPI_LINUX_THERMAL_H` and `#define _UAPI_LINUX_THERMAL_H`:** Standard include guards to prevent multiple inclusions. This is common in C/C++ headers.
* **`THERMAL_NAME_LENGTH 20`:** Defines a constant for the maximum length of a thermal zone name.
* **`enum thermal_device_mode`:**  Defines possible states for thermal devices (enabled/disabled).
* **`enum thermal_trip_type`:** Defines types of thermal trip points (active, passive, hot, critical).
* **`#define THERMAL_GENL_FAMILY_NAME "thermal"` and related `#define`s:** This points to the use of Netlink's Generic Netlink (Genl) framework for communication. The definitions here are for the Genl family, version, and multicast groups related to thermal management.
* **`enum thermal_genl_attr`:** Defines attributes that can be exchanged via Genl messages (temperature, trip points, names, governor information, etc.).
* **`enum thermal_genl_sampling`:** Defines sampling-related attributes (currently only temperature).
* **`enum thermal_genl_event`:** Defines events that can be broadcast via Genl (thermal zone creation/deletion, trip point changes, etc.).
* **`enum thermal_genl_cmd`:** Defines commands that can be sent via Genl to query information (get temperature, get trip points, etc.).

**3. Relating to Android:**

* **Bionic Context:** The prompt explicitly mentions "bionic/libc/kernel/uapi/linux/". This places the file within Android's C library interface to the Linux kernel. It's a *user-space* view of kernel structures and definitions.
* **Thermal Management in Android:**  Android needs to manage device temperature to prevent overheating, which can lead to performance degradation, battery issues, and even hardware damage. This header file is a crucial part of that system.
* **Framework Interaction:** The Android framework (Java/Kotlin code) doesn't directly use this header file. Instead, it interacts with system services (written in C++) that *do* use these definitions to communicate with the kernel.
* **NDK:** NDK developers can use these definitions if they are writing low-level code that interacts directly with the thermal management subsystem.

**4. Addressing Specific Prompt Points:**

* **功能 (Functions):** The file itself doesn't contain functions in the C/C++ sense (implementations). It defines constants, enums, and macros. Its "function" is to provide a common vocabulary for interacting with the kernel's thermal management.
* **与 Android 功能的关系 (Relationship to Android functionality):**  Focus on the *what* and *why* of thermal management in Android. Examples: performance throttling, battery management, device safety.
* **libc 函数的实现 (Implementation of libc functions):** This is where it's crucial to understand that this is a *header file*. It *declares* interfaces but doesn't *implement* them. The *actual* implementation resides in the kernel. So, the answer should focus on the conceptual level and how user-space interacts with the kernel using system calls and the Genl framework. Avoid going into specific C code details for "libc functions" here, as those are not directly present in this file.
* **dynamic linker 的功能 (Dynamic linker functionality):**  This header file is a static definition. It doesn't involve dynamic linking directly. The dynamic linker is involved when libraries that *use* these definitions are loaded, but the header itself doesn't contain dynamic linking logic. Explain the role of the dynamic linker in general and how shared libraries might use these definitions. Provide a simplified SO layout example and a high-level overview of the linking process.
* **逻辑推理 (Logical reasoning):** The Genl attributes and events allow for logical deductions about the system's state. Provide examples of how observing certain events (like `THERMAL_GENL_EVENT_TZ_TRIP_UP`) can lead to conclusions about the device's temperature.
* **用户或编程常见的使用错误 (Common user/programming errors):**  Focus on misinterpretations of the defined values, incorrect usage of system calls or Genl APIs, and ignoring error conditions.
* **Android framework or ndk 如何到达这里 (How Android framework/NDK reaches here):**  Trace the path from the high-level framework down to the kernel interaction. Illustrate with an example scenario (e.g., temperature change triggering a notification).
* **frida hook 示例 (Frida hook example):** Focus on hooking the *system calls* or *Genl communication* that would be used based on these definitions. Since direct function calls are not present in this header, hooking system calls or Genl message handling is the relevant approach.

**5. Structuring the Answer:**

Organize the answer logically, addressing each point of the prompt. Use clear headings and subheadings. Provide concrete examples and explanations. Use Chinese as requested.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Try to explain specific C functions. **Correction:** Realize this is a header file and focus on the definitions and the underlying mechanisms they represent (like Genl).
* **Initial thought:**  Provide very detailed C code for dynamic linking. **Correction:** Keep the dynamic linking explanation high-level and focused on the concept and how shared libraries might use these definitions.
* **Initial thought:**  Focus only on direct function calls for Frida hooking. **Correction:** Expand to include hooking system calls and Genl message handling, as those are the relevant interaction points.

By following these steps, the generated answer effectively addresses all aspects of the prompt and provides a comprehensive explanation of the `thermal.h` header file within the Android ecosystem.
## 对 `bionic/libc/kernel/uapi/linux/thermal.handroid` 源代码文件的分析

这个文件 `thermal.h` 是 Android Bionic 库中，用于定义与 Linux 内核热管理子系统用户空间 API 相关的常量、枚举和宏定义。它是一个 **用户空间应用程序接口 (UAPI)** 头文件，意味着它定义了用户空间程序（例如 Android 系统服务或 NDK 应用）与 Linux 内核热管理功能进行交互的方式。

**功能列举：**

这个头文件本身 **不包含具体的函数实现**，它的主要功能是 **定义数据结构和常量**，为用户空间程序提供与内核热管理子系统交互的接口规范。具体来说，它定义了：

1. **热设备状态枚举 (`enum thermal_device_mode`)**: 定义了热设备的两种状态：
    * `THERMAL_DEVICE_DISABLED`: 热设备被禁用。
    * `THERMAL_DEVICE_ENABLED`: 热设备被启用。

2. **热跳变类型枚举 (`enum thermal_trip_type`)**: 定义了热跳变点的类型，用于指示温度变化的不同阶段和严重程度：
    * `THERMAL_TRIP_ACTIVE`:  激活跳变点，通常用于启动主动散热措施（如风扇加速）。
    * `THERMAL_TRIP_PASSIVE`: 被动跳变点，通常用于限制功耗或降低性能以降低温度。
    * `THERMAL_TRIP_HOT`:  高温跳变点，指示设备温度较高。
    * `THERMAL_TRIP_CRITICAL`: 临界跳变点，指示设备温度非常高，可能导致硬件损坏，需要采取紧急措施。

3. **Generic Netlink (Genl) 相关定义**:  定义了用于通过 Generic Netlink 与内核热管理子系统通信的常量和枚举：
    * `THERMAL_GENL_FAMILY_NAME`:  定义了 Genl 家族的名称，即 "thermal"。
    * `THERMAL_GENL_VERSION`: 定义了 Genl 家族的版本号。
    * `THERMAL_GENL_SAMPLING_GROUP_NAME`: 定义了用于温度采样的多播组名称。
    * `THERMAL_GENL_EVENT_GROUP_NAME`: 定义了用于热管理事件的多播组名称。
    * `enum thermal_genl_attr`: 定义了可以通过 Genl 消息传递的各种属性，例如温度、跳变点信息、设备名称、调速器信息等。这些属性用于请求或设置热管理相关的信息。
    * `enum thermal_genl_sampling`: 定义了温度采样相关的属性。
    * `enum thermal_genl_event`: 定义了内核可以发送给用户空间的各种热管理事件，例如热区创建/删除、跳变点状态变化、调速器切换等。
    * `enum thermal_genl_cmd`: 定义了用户空间可以发送给内核的热管理命令，例如获取热区 ID、获取跳变点信息、获取温度等。

4. **其他常量**:
    * `THERMAL_NAME_LENGTH`: 定义了热区或热控制设备名称的最大长度。

**与 Android 功能的关系及举例说明：**

这个头文件定义的接口是 Android 热管理框架的基础。Android 系统需要监控设备温度并采取相应的措施来防止过热，保障设备稳定运行和用户体验。

**举例说明：**

* **Android Framework 中的 Thermal Service:** Android Framework 中有一个 `ThermalService` 系统服务，负责监控设备温度和管理热策略。`ThermalService` 可能会使用这个头文件中定义的 `THERMAL_GENL_CMD_*` 命令通过 Generic Netlink 与内核通信，获取各个热区的温度信息 (`THERMAL_GENL_CMD_TZ_GET_TEMP`)。
* **性能调控:** 当设备温度达到某个跳变点（例如 `THERMAL_TRIP_PASSIVE`），内核可能会发送 `THERMAL_GENL_EVENT_TZ_TRIP_UP` 事件给用户空间。`ThermalService` 接收到这个事件后，可能会触发性能调控策略，例如降低 CPU 或 GPU 的频率，以降低发热。
* **电池管理:**  电池温度也是热管理的重要组成部分。这个头文件定义的接口可以用于监控电池温度，并在电池过热时采取保护措施。
* **NDK 应用:** NDK 开发者可以使用这个头文件中定义的常量和枚举，直接通过 Generic Netlink 与内核热管理子系统交互，获取更底层的热管理信息。例如，一个游戏应用可以根据 CPU 温度调整渲染质量以避免设备过热。

**libc 函数的功能实现：**

这个头文件本身不包含任何 libc 函数的实现。它只是定义了常量和数据结构。用户空间程序需要使用标准的 Linux 系统调用和 Generic Netlink API 来与内核进行交互。

例如，要通过 Generic Netlink 发送命令或接收事件，需要使用诸如 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等标准的 socket 相关系统调用，以及 Netlink 相关的库函数（通常在 `libnl` 或 `libmnl` 中）。

**对于涉及 dynamic linker 的功能：**

这个头文件本身与 dynamic linker 没有直接的功能关联。Dynamic linker 的主要职责是在程序启动时加载所需的共享库，并解析和重定位符号。

然而，如果某个共享库（例如 Android 系统服务的一部分）使用了这个头文件中定义的常量和结构，那么 dynamic linker 会负责将这个共享库加载到进程的地址空间。

**SO 布局样本：**

假设一个名为 `libthermal_monitor.so` 的共享库使用了 `thermal.h` 中的定义：

```
libthermal_monitor.so:
    .text         # 代码段
        ... 使用 thermal.h 中定义的常量和枚举 ...
        ... 调用 Netlink 相关函数与内核通信 ...
    .data         # 数据段
        ...
    .rodata       # 只读数据段
        ...
    .bss          # 未初始化数据段
        ...
    .dynamic      # 动态链接信息
        NEEDED      libc.so
        NEEDED      libnl.so  # 如果使用了 libnl 库
        SONAME      libthermal_monitor.so
        ...
    .symtab       # 符号表
        ...
    .strtab       # 字符串表
        ...
```

**链接的处理过程：**

1. 当一个进程（例如 `ThermalService`）启动时，操作系统会加载其主执行文件。
2. Dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会被激活。
3. Dynamic linker 会读取主执行文件的 `.dynamic` 段，查找 `NEEDED` 条目，确定需要加载的共享库，例如 `libc.so` 和 `libthermal_monitor.so`。
4. Dynamic linker 会在预定义的路径（例如 `/system/lib64`, `/vendor/lib64` 等）中查找这些共享库。
5. 一旦找到共享库，Dynamic linker 会将其加载到进程的地址空间中。
6. Dynamic linker 会解析共享库的符号表 (`.symtab`)，并根据主执行文件和已加载的共享库中的符号引用进行符号重定位，即将符号的虚拟地址填充到相应的代码和数据段中。
7. 如果 `libthermal_monitor.so` 中使用了 `thermal.h` 中定义的常量，这些常量的值是在编译时确定的，并直接嵌入到 `libthermal_monitor.so` 的代码或数据段中。Dynamic linker 不需要对这些常量进行特殊处理。
8. 如果 `libthermal_monitor.so` 调用了 Netlink 相关的库函数（例如 `libnl.so` 中的函数），Dynamic linker 会解析这些函数调用，并将它们链接到 `libnl.so` 中相应的函数地址。

**逻辑推理的假设输入与输出：**

**假设输入：**

* 用户空间程序（例如 `ThermalMonitorApp`）通过 Generic Netlink 向内核发送 `THERMAL_GENL_CMD_TZ_GET_TEMP` 命令，请求 ID 为 0 的热区的温度。

**逻辑推理：**

1. 内核热管理子系统接收到该命令。
2. 内核查找 ID 为 0 的热区，并读取其当前的温度值。
3. 内核构建一个 Generic Netlink 响应消息，其中包含 `THERMAL_GENL_ATTR_TZ_TEMP` 属性，该属性的值是热区的温度。

**输出：**

* 用户空间程序接收到内核的 Generic Netlink 响应消息，可以从中解析出 `THERMAL_GENL_ATTR_TZ_TEMP` 属性的值，即热区的温度。

**涉及用户或者编程常见的使用错误：**

1. **错误的属性或命令 ID:** 在构建 Generic Netlink 消息时，使用了错误的 `thermal_genl_attr` 或 `thermal_genl_cmd` 枚举值，导致内核无法识别请求或返回错误的信息。
    * **示例:** 用户错误地使用了 `THERMAL_GENL_ATTR_CDEV_CUR_STATE` 来请求热区温度，而不是 `THERMAL_GENL_ATTR_TZ_TEMP`。

2. **未正确处理 Netlink 消息格式:**  Generic Netlink 消息有特定的格式，包括头部、属性等。用户空间程序如果没有正确地构建或解析这些消息，会导致通信失败。
    * **示例:**  忘记在 Netlink 消息中添加必要的头部信息，或者解析属性时使用了错误的偏移量。

3. **权限不足:** 某些热管理操作可能需要 root 权限或特定的 capabilities。非特权进程尝试执行这些操作会失败。
    * **示例:** 一个普通应用尝试修改热区的跳变点温度，但没有相应的权限。

4. **忽略错误返回值:** 在使用 Netlink 相关函数时，应该检查函数的返回值以判断操作是否成功。忽略错误返回值可能导致程序出现不可预测的行为。
    * **示例:** `sendto()` 函数返回 -1 表示发送失败，但程序没有检查返回值并继续执行。

5. **对枚举值的错误理解:**  错误地理解 `thermal_trip_type` 或 `thermal_device_mode` 等枚举值的含义，导致程序逻辑错误。
    * **示例:** 将 `THERMAL_TRIP_PASSIVE` 误认为是最高温度状态。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤 (以获取温度为例):**

1. **Java Framework (e.g., `android.os.Temperature`)**:  应用或系统服务（例如 `ThermalService`）可能使用 Java Framework 提供的 `android.os.Temperature` 类来获取温度信息。
2. **Native Binder Call (ThermalService)**:  `Temperature` 类的方法最终会通过 Binder IPC 调用到 Native 层的 `ThermalService`。
3. **Native Thermal HAL (thermal_hal.h)**: `ThermalService` 的 Native 层实现会通过 Thermal HAL (Hardware Abstraction Layer) 与底层的硬件或内核驱动进行交互。
4. **Generic Netlink Communication**:  某些 Thermal HAL 的实现可能会选择使用 Generic Netlink 与内核的热管理子系统通信。这时，就会使用到 `thermal.h` 中定义的常量和结构。
5. **System Calls (socket, sendto, recvfrom)**:  `ThermalService` 使用标准的 socket 系统调用和 Netlink 相关的库函数（例如 `libnl`）来发送和接收 Generic Netlink 消息。
6. **Kernel Thermal Subsystem**:  内核的热管理子系统接收到 Netlink 消息后，会处理请求并返回响应。

**NDK 应用到达这里的步骤:**

1. **NDK 应用代码**: NDK 应用可以直接包含 `bionic/libc/kernel/uapi/linux/thermal.h` 头文件。
2. **Generic Netlink API**: NDK 应用可以使用标准的 Linux 系统调用和 Netlink 相关的库函数（例如 `libnl` 或自己实现）来构建和发送 Generic Netlink 消息。
3. **System Calls (socket, sendto, recvfrom)**:  与 Framework 类似，NDK 应用最终会调用 socket 相关的系统调用与内核通信。
4. **Kernel Thermal Subsystem**:  内核接收和处理来自 NDK 应用的 Netlink 消息。

**Frida Hook 示例调试步骤 (以 Hook ThermalService 获取温度为例):**

```python
import frida
import sys

package_name = "com.android.systemui" # 例如，hook SystemUI 进程中的 ThermalService

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Make sure the app is running.")
    sys.exit(1)

script_code = """
// 假设 ThermalService 中使用了某个函数来获取温度，例如可能封装了 Netlink 通信
// 需要根据实际情况找到对应的函数名和参数类型

// 示例：Hook 一个可能用于获取温度的 Native 函数 (需要根据具体实现修改)
Interceptor.attach(Module.findExportByName("libandroid_runtime.so", "_ZN7android15ThermalService15getThermalInfosEv"), {
    onEnter: function(args) {
        console.log("[+] getThermalInfos called");
    },
    onLeave: function(retval) {
        console.log("[+] getThermalInfos returned:", retval);
        // 可以进一步分析返回值，查看温度信息
    }
});

// 示例：Hook 底层的 sendto 系统调用，查看发送的 Netlink 消息
// 需要根据实际情况判断 ThermalService 是否直接使用 sendto
var sendtoPtr = Module.findExportByName(null, "sendto");
if (sendtoPtr) {
    Interceptor.attach(sendtoPtr, {
        onEnter: function(args) {
            var sockfd = args[0];
            var bufPtr = args[1];
            var len = args[2].toInt32();
            var flags = args[3];
            var destAddrPtr = args[4];
            var addrlen = args[5];

            // 可以检查目标地址是否为 Netlink 地址
            // 可以读取发送缓冲区的内容，查看是否包含热管理相关的命令和属性
            console.log("[*] sendto called");
            console.log("    sockfd:", sockfd);
            console.log("    len:", len);
            if (len > 0) {
                console.log("    data:", hexdump(bufPtr.readByteArray(len), { ansi: true }));
            }
        }
    });
}

// 示例：Hook 底层的 recvfrom 系统调用，查看接收的 Netlink 消息
var recvfromPtr = Module.findExportByName(null, "recvfrom");
if (recvfromPtr) {
    Interceptor.attach(recvfromPtr, {
        onEnter: function(args) {
            // ... 类似 sendto 的处理，查看接收到的数据
            console.log("[*] recvfrom called");
        },
        onLeave: function(retval) {
            if (retval.toInt32() > 0) {
                console.log("    received data:", hexdump(this.context.rdi.readByteArray(retval.toInt32()), { ansi: true }));
            }
        }
    });
}
""";

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 示例:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **指定目标进程:** 设置要 hook 的进程名称 (`package_name`)，例如 `com.android.systemui`，这可能包含 `ThermalService`。
3. **连接到设备和进程:** 使用 `frida.get_usb_device().attach(package_name)` 连接到 USB 设备上的目标进程。
4. **编写 Frida 脚本:**
   * **Hook Native 函数:**  尝试 hook `ThermalService` 中可能用于获取温度的 Native 函数。你需要根据 Android 源码或逆向工程找到具体的函数名（例如示例中的 `_ZN7android15ThermalService15getThermalInfosEv` 是一个假设的函数名，需要替换成实际的）。`Interceptor.attach` 用于拦截函数的调用，并在函数进入 (`onEnter`) 和退出 (`onLeave`) 时执行自定义的代码。
   * **Hook `sendto` 系统调用:**  Hook `sendto` 系统调用可以查看进程发送的网络数据包。通过检查发送的目标地址和数据内容，可以判断是否正在发送与热管理相关的 Generic Netlink 消息。
   * **Hook `recvfrom` 系统调用:**  类似地，Hook `recvfrom` 系统调用可以查看进程接收的网络数据包，从而观察内核返回的热管理信息。
5. **加载和运行脚本:** 使用 `session.create_script()` 创建脚本，设置消息回调，加载脚本并保持脚本运行。

**使用 Frida Hook 调试的步骤：**

1. 确保你的 Android 设备已连接到电脑，并且 adb 可用。
2. 安装 Frida 和 Frida-server。
3. 运行目标应用或服务（例如，重启 SystemUI）。
4. 运行上面的 Frida Python 脚本。
5. 观察 Frida 的输出，你可以看到 `sendto` 和 `recvfrom` 系统调用的调用信息，包括发送和接收的数据内容（以十六进制显示）。通过分析这些数据，你可以了解 `ThermalService` 是如何与内核热管理子系统通信的。
6. 如果你成功 hook 了 `ThermalService` 的特定函数，你还可以看到函数的调用和返回值，从而更直接地了解温度信息的获取过程。

请注意，实际的函数名和实现细节可能因 Android 版本和设备制造商而异，你需要进行一些逆向工程来确定要 hook 的目标。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/thermal.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_THERMAL_H
#define _UAPI_LINUX_THERMAL_H
#define THERMAL_NAME_LENGTH 20
enum thermal_device_mode {
  THERMAL_DEVICE_DISABLED = 0,
  THERMAL_DEVICE_ENABLED,
};
enum thermal_trip_type {
  THERMAL_TRIP_ACTIVE = 0,
  THERMAL_TRIP_PASSIVE,
  THERMAL_TRIP_HOT,
  THERMAL_TRIP_CRITICAL,
};
#define THERMAL_GENL_FAMILY_NAME "thermal"
#define THERMAL_GENL_VERSION 0x01
#define THERMAL_GENL_SAMPLING_GROUP_NAME "sampling"
#define THERMAL_GENL_EVENT_GROUP_NAME "event"
enum thermal_genl_attr {
  THERMAL_GENL_ATTR_UNSPEC,
  THERMAL_GENL_ATTR_TZ,
  THERMAL_GENL_ATTR_TZ_ID,
  THERMAL_GENL_ATTR_TZ_TEMP,
  THERMAL_GENL_ATTR_TZ_TRIP,
  THERMAL_GENL_ATTR_TZ_TRIP_ID,
  THERMAL_GENL_ATTR_TZ_TRIP_TYPE,
  THERMAL_GENL_ATTR_TZ_TRIP_TEMP,
  THERMAL_GENL_ATTR_TZ_TRIP_HYST,
  THERMAL_GENL_ATTR_TZ_MODE,
  THERMAL_GENL_ATTR_TZ_NAME,
  THERMAL_GENL_ATTR_TZ_CDEV_WEIGHT,
  THERMAL_GENL_ATTR_TZ_GOV,
  THERMAL_GENL_ATTR_TZ_GOV_NAME,
  THERMAL_GENL_ATTR_CDEV,
  THERMAL_GENL_ATTR_CDEV_ID,
  THERMAL_GENL_ATTR_CDEV_CUR_STATE,
  THERMAL_GENL_ATTR_CDEV_MAX_STATE,
  THERMAL_GENL_ATTR_CDEV_NAME,
  THERMAL_GENL_ATTR_GOV_NAME,
  THERMAL_GENL_ATTR_CPU_CAPABILITY,
  THERMAL_GENL_ATTR_CPU_CAPABILITY_ID,
  THERMAL_GENL_ATTR_CPU_CAPABILITY_PERFORMANCE,
  THERMAL_GENL_ATTR_CPU_CAPABILITY_EFFICIENCY,
  __THERMAL_GENL_ATTR_MAX,
};
#define THERMAL_GENL_ATTR_MAX (__THERMAL_GENL_ATTR_MAX - 1)
enum thermal_genl_sampling {
  THERMAL_GENL_SAMPLING_TEMP,
  __THERMAL_GENL_SAMPLING_MAX,
};
#define THERMAL_GENL_SAMPLING_MAX (__THERMAL_GENL_SAMPLING_MAX - 1)
enum thermal_genl_event {
  THERMAL_GENL_EVENT_UNSPEC,
  THERMAL_GENL_EVENT_TZ_CREATE,
  THERMAL_GENL_EVENT_TZ_DELETE,
  THERMAL_GENL_EVENT_TZ_DISABLE,
  THERMAL_GENL_EVENT_TZ_ENABLE,
  THERMAL_GENL_EVENT_TZ_TRIP_UP,
  THERMAL_GENL_EVENT_TZ_TRIP_DOWN,
  THERMAL_GENL_EVENT_TZ_TRIP_CHANGE,
  THERMAL_GENL_EVENT_TZ_TRIP_ADD,
  THERMAL_GENL_EVENT_TZ_TRIP_DELETE,
  THERMAL_GENL_EVENT_CDEV_ADD,
  THERMAL_GENL_EVENT_CDEV_DELETE,
  THERMAL_GENL_EVENT_CDEV_STATE_UPDATE,
  THERMAL_GENL_EVENT_TZ_GOV_CHANGE,
  THERMAL_GENL_EVENT_CPU_CAPABILITY_CHANGE,
  __THERMAL_GENL_EVENT_MAX,
};
#define THERMAL_GENL_EVENT_MAX (__THERMAL_GENL_EVENT_MAX - 1)
enum thermal_genl_cmd {
  THERMAL_GENL_CMD_UNSPEC,
  THERMAL_GENL_CMD_TZ_GET_ID,
  THERMAL_GENL_CMD_TZ_GET_TRIP,
  THERMAL_GENL_CMD_TZ_GET_TEMP,
  THERMAL_GENL_CMD_TZ_GET_GOV,
  THERMAL_GENL_CMD_TZ_GET_MODE,
  THERMAL_GENL_CMD_CDEV_GET,
  __THERMAL_GENL_CMD_MAX,
};
#define THERMAL_GENL_CMD_MAX (__THERMAL_GENL_CMD_MAX - 1)
#endif

"""

```