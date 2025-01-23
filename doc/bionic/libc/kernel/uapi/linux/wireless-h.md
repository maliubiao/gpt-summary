Response:
Let's break down the thought process to generate the comprehensive answer.

1. **Understanding the Core Request:** The request is to analyze the `wireless.handroid` header file within the Android bionic library and explain its purpose, its relation to Android, the function of its elements, and related technical details like dynamic linking and usage.

2. **Initial Assessment of the File:** The first and most important observation is that this is a *header file* (`.h`). Header files in C/C++ primarily define interfaces and data structures. They don't contain the *implementation* of functions. This immediately tells us we won't be explaining the "how" of libc function *implementations* within this specific file.

3. **Identifying the Key Components:**  Scanning the header file reveals several categories of content:
    * **Includes:** `linux/types.h`, `linux/socket.h`, `linux/if.h`, `stddef.h`. These suggest the file deals with low-level network and socket programming concepts within a Linux environment.
    * **Defines (Macros):**  A large number of `#define` statements. These fall into categories like:
        * `WIRELESS_EXT`: A likely extension identifier.
        * `SIOC...`:  These strongly resemble `ioctl` (input/output control) command codes related to wireless interfaces.
        * `IW_...`: These appear to be constants and bitmasks related to wireless information elements and capabilities.
        * `IWEV...`: These look like wireless event codes.
    * **Structs:** Definitions of various `struct iw_*`. These clearly represent data structures used to exchange information about wireless interfaces.
    * **Unions:** The `union iwreq_data` suggests different types of data can be associated with a wireless request.
    * **Other Defines:** Definitions related to event capabilities and packed lengths.

4. **Connecting to Android:** The request explicitly asks about the connection to Android. The path `bionic/libc/kernel/uapi/linux/wireless.handroid` is a strong indicator. `bionic` is Android's C library. `kernel/uapi` means this is a *user-space API* that mirrors kernel definitions. Therefore, this file *defines how user-space Android interacts with the Linux kernel's wireless subsystem*.

5. **Determining the Functionality:** Based on the components identified above, the primary function of this header file is to:
    * **Provide the necessary constants and data structures for Android user-space processes to interact with the Linux kernel's wireless drivers.** This interaction happens primarily through `ioctl` system calls.
    * **Define the command codes (`SIOC...`) used to configure and query wireless interfaces.**
    * **Define the data structures (`iw_*`) used to pass information back and forth between user-space and the kernel.**
    * **Define event codes (`IWEV...`) that the kernel can send to user-space to notify about wireless events.**

6. **Addressing Specific Request Points:**

    * **List the functions:**  Realize that header files *don't define functions*. They define *interfaces*. The "functions" here are the `ioctl` commands, even though they aren't C functions defined in this file.
    * **Relationship to Android:**  Emphasize the user-space/kernel interaction. Explain how Android frameworks and applications utilize these definitions.
    * **Detailed explanation of libc functions:** Since it's a header file, clarify that it *defines* structures and constants, not implements libc functions. Mention the *actual* libc functions that *use* these definitions (like `socket`, `ioctl`).
    * **Dynamic Linker:** This file itself doesn't directly involve the dynamic linker. However, the *libc* it belongs to *does*. Explain that the code using these definitions will be linked against libc. Provide a basic example of an SO layout and the linking process.
    * **Logical Reasoning:** The `IW_IS_SET` and `IW_IS_GET` macros are good examples of logical operations. Explain their purpose with hypothetical input and output.
    * **Common Usage Errors:** Think about how developers might misuse the constants or structures defined here. Incorrect `ioctl` commands or malformed data structures are common errors.
    * **Android Framework/NDK Path:**  Trace the path from high-level Android components down to the `ioctl` calls that eventually use these definitions. Focus on the `WifiManager`, `ConnectivityService`, and how NDK developers might use `ioctl` directly.
    * **Frida Hook:** Provide concrete Frida examples to intercept the `ioctl` calls and inspect the relevant data structures. This is crucial for demonstrating how these definitions are actually used.

7. **Structuring the Answer:** Organize the information logically with clear headings and subheadings to make it easy to read and understand. Use bullet points and code blocks to highlight important details.

8. **Refinement and Clarity:**  Review the answer to ensure accuracy and clarity. Avoid jargon where possible, or explain it if necessary. Make sure the examples are relevant and easy to follow. For instance, explicitly stating that this file *doesn't contain function implementations* is important to avoid misunderstanding.

By following this structured approach, addressing each part of the request systematically, and focusing on the nature of a header file, it's possible to create a comprehensive and accurate explanation like the example provided in the initial prompt's answer.
这个文件 `bionic/libc/kernel/uapi/linux/wireless.handroid` 是 Android 的 Bionic C 库中的一个头文件，它定义了用户空间程序与 Linux 内核中关于无线网络子系统进行交互时所使用的一些常量、数据结构和宏。由于其路径包含 `uapi` (用户空间应用程序编程接口)，这表明它定义了用户空间可以使用的接口，而不是内核内部的实现。

**功能列举:**

这个头文件的主要功能是为用户空间的应用程序提供访问和控制 Linux 无线功能的接口定义。具体包括：

1. **定义了用于 `ioctl` 系统调用的命令常量 (Macros):**  以 `SIOCSIW...` 和 `SIOCGIW...` 开头的宏定义，如 `SIOCSIWESSID` (设置 ESSID) 和 `SIOCGIWNAME` (获取接口名称)。这些常量作为 `ioctl` 调用的命令参数，用于配置或查询无线接口的各种属性。

2. **定义了与无线事件相关的常量 (Macros):** 以 `IWEVTXDROP`、`IWEVQUAL` 等开头的宏定义，代表了内核向用户空间传递的无线事件类型，例如丢包、信号质量变化等。

3. **定义了表示无线参数和状态的常量 (Macros):**  以 `IW_MODE_AUTO`、`IW_ENCODE_ENABLED` 等开头的宏定义，用于表示无线模式、加密状态等各种属性的取值。

4. **定义了用于传递无线信息的结构体 (Structs):**  如 `iw_param`、`iw_point`、`iw_freq`、`iw_quality`、`iwreq` 等。这些结构体用于在用户空间和内核空间之间传递配置信息、状态信息和事件信息。

5. **定义了用于不同类型 `ioctl` 请求的数据联合体 (Union):**  `union iwreq_data` 定义了可以与 `iwreq` 结构体一起使用的各种数据类型，以便根据不同的 `ioctl` 命令传递不同的数据。

6. **定义了用于表示无线能力范围的结构体 (Struct):** `struct iw_range` 定义了无线网卡的各种能力范围，例如支持的频率、速率等。

7. **定义了用于私有 `ioctl` 命令的结构体 (Struct):** `struct iw_priv_args` 用于扩展无线配置的功能，允许驱动程序定义自己的 `ioctl` 命令。

8. **定义了用于描述无线事件的结构体 (Struct):** `struct iw_event` 用于封装内核发送给用户空间的无线事件信息。

**与 Android 功能的关系及举例说明:**

这个头文件对于 Android 的 Wi-Fi 功能至关重要。Android 框架层和 Native 层（通过 NDK）都需要使用这些定义来与底层的 Wi-Fi 驱动进行交互。

* **连接 Wi-Fi 网络:** 当 Android 用户点击连接到一个 Wi-Fi 网络时，Android 系统会使用这个头文件中定义的常量和结构体，例如 `SIOCSIWESSID` (设置网络名称)、`SIOCSIWENCODEEXT` (设置加密方式和密钥) 等，通过 `ioctl` 系统调用来配置 Wi-Fi 接口。

* **扫描可用 Wi-Fi 网络:**  Android 系统使用 `SIOCSIWSCAN` 命令来触发 Wi-Fi 扫描，并使用 `SIOCGIWSCAN` 命令来获取扫描结果。扫描结果的数据结构会用到这个头文件中定义的结构体，例如 `iw_event` 和其中包含的无线网络信息。

* **获取 Wi-Fi 状态信息:** Android 系统会使用诸如 `SIOCGIWNAME` (获取接口名称)、`SIOCGIWFREQ` (获取频率)、`SIOCGIWAP` (获取连接的 AP 的 MAC 地址) 等命令来获取当前的 Wi-Fi 连接状态和参数。

**libc 函数的功能是如何实现的:**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了常量和数据结构。实际使用这些定义的 libc 函数通常是 `socket()` 和 `ioctl()`。

* **`socket()`:**  用于创建一个套接字，通常会指定地址族为 `AF_INET` 或 `AF_INET6`，类型为 `SOCK_DGRAM` 或 `SOCK_RAW`。为了执行无线相关的 `ioctl`，通常需要一个与网络接口关联的套接字。

* **`ioctl()`:**  这是一个通用的设备输入/输出控制系统调用。对于无线操作，`ioctl()` 会接收一个与无线接口关联的文件描述符（通常是一个 socket）、一个命令常量（例如 `SIOCSIWESSID`），以及一个指向包含参数的结构体的指针（例如指向 `iwreq` 结构体的指针）。内核中的无线驱动程序会根据 `ioctl()` 的命令和参数执行相应的操作。

**涉及 dynamic linker 的功能，so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker。但是，任何使用了这个头文件中定义的常量和数据结构的应用程序或库，在编译时都需要链接到 Bionic libc 库。

**SO 布局样本:**

假设有一个名为 `libwifi_hal.so` 的动态链接库，它使用了这个头文件中的定义：

```
libwifi_hal.so:
  .text         # 代码段
  .rodata       # 只读数据段 (可能包含一些与无线相关的常量)
  .data         # 可读写数据段
  .bss          # 未初始化数据段
  .dynsym       # 动态符号表
  .dynstr       # 动态字符串表
  .rel.dyn      # 动态重定位表
  .plt          # 程序链接表 (用于延迟绑定)
  .got.plt      # 全局偏移量表 (用于延迟绑定)
```

**链接的处理过程:**

1. **编译时:** 当 `libwifi_hal.so` 的源代码包含 `#include <linux/wireless.h>` (或其在 bionic 中的路径) 时，编译器会读取这个头文件，获取其中定义的常量和结构体信息。

2. **链接时:** 链接器会解析 `libwifi_hal.so` 中对 libc 函数（例如 `socket`、`ioctl`）的调用，并在其动态符号表中记录下来，表示这些符号需要在运行时从 libc 中解析。

3. **运行时:** 当 Android 系统加载 `libwifi_hal.so` 时，dynamic linker（如 `linker64` 或 `linker`）会执行以下操作：
   * **加载依赖库:** 识别 `libwifi_hal.so` 依赖的库，包括 Bionic libc (`libc.so`)。
   * **符号解析:** 遍历 `libwifi_hal.so` 的 `.rel.dyn` 段，找到需要重定位的符号。对于来自 libc 的符号，dynamic linker 会在 `libc.so` 的动态符号表中查找对应的地址。
   * **重定位:** 将找到的 libc 函数的地址填入 `libwifi_hal.so` 的 `.got.plt` 表中。
   * **延迟绑定:**  通常采用延迟绑定，即在第一次调用 libc 函数时才进行符号解析和重定位。当 `libwifi_hal.so` 首次调用 `socket` 或 `ioctl` 时，会通过 `.plt` 表跳转到 dynamic linker 的代码，进行符号解析和重定位，然后将真正的函数地址写入 `.got.plt`，后续的调用将直接通过 `.got.plt` 跳转到 libc 函数。

**逻辑推理，假设输入与输出:**

考虑 `IW_IS_SET(cmd)` 宏的逻辑：

```c
#define IW_IS_SET(cmd) (! ((cmd) & 0x1))
```

**假设输入:**

* `cmd = 0x8B00` (SIOCSIWCOMMIT，设置操作)
* `cmd = 0x8B01` (SIOCGIWNAME，获取操作)

**逻辑推理:**

`IW_IS_SET(cmd)` 的目的是判断 `cmd` 是否代表一个 "设置" 操作。通常，`ioctl` 命令的奇偶性可以区分设置和获取操作。这里假设设置操作的命令码的最低位为 0，获取操作的最低位为 1。

* **当 `cmd = 0x8B00` 时:**
    * `0x8B00 & 0x1` 的结果是 `0`。
    * `!0` 的结果是 `1` (真)。
    * **输出:** `IW_IS_SET(0x8B00)` 返回 `1`，表示这是一个设置操作。

* **当 `cmd = 0x8B01` 时:**
    * `0x8B01 & 0x1` 的结果是 `1`。
    * `!1` 的结果是 `0` (假)。
    * **输出:** `IW_IS_SET(0x8B01)` 返回 `0`，表示这不是一个设置操作（很可能是获取操作）。

**用户或编程常见的使用错误:**

1. **使用错误的 `ioctl` 命令码:** 传递给 `ioctl()` 的命令码不正确，可能导致操作失败或未定义的行为。例如，尝试使用设置命令去获取信息，或者反之。

2. **传递不正确的参数结构体:** `ioctl()` 的第三个参数是指向参数结构体的指针。如果传递的结构体类型或内容与 `ioctl` 命令不匹配，会导致错误。例如，对于需要 `iw_point` 结构的命令，传递了 `iw_param` 结构。

3. **忘记初始化结构体:** 在使用 `iwreq` 或其他结构体之前，没有正确地初始化其成员，特别是 `ifr_name` (接口名称) 和 `u` (数据联合体) 中的相关字段。

4. **缓冲区溢出:** 在使用 `iw_point` 结构体接收可变长度的数据时，没有正确处理缓冲区大小，可能导致缓冲区溢出。

5. **权限不足:** 某些 `ioctl` 操作可能需要 root 权限。在非 root 权限下调用这些操作会失败。

**Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤：**

1. **用户交互或系统事件:** 用户在设置中开关 Wi-Fi，或者应用程序请求扫描 Wi-Fi 网络。
2. **Framework 层 (Java):**  Android Framework 中的 `WifiManager` 或 `ConnectivityService` 等系统服务会接收到这些请求。
3. **Native 服务层 (C++):** Framework 层通过 JNI 调用到 Native 层的 Wi-Fi 服务，例如 `wificond` 或直接的 HAL 实现。
4. **HAL (Hardware Abstraction Layer):** Native 服务层会调用 Wi-Fi HAL 接口，这些接口定义了与 Wi-Fi 驱动交互的标准方法。
5. **驱动程序交互 (C/C++):** HAL 的实现最终会调用底层的 Wi-Fi 驱动程序。这通常涉及到打开一个与 Wi-Fi 接口关联的套接字，并使用 `ioctl()` 系统调用，传递包含在这个 `wireless.handroid` 头文件中定义的常量和结构体的参数。

**NDK 到达这里的步骤：**

1. **NDK 应用开发:** 开发者使用 NDK 编写 C/C++ 代码，需要进行底层的 Wi-Fi 操作。
2. **直接使用 Socket 和 ioctl:** 开发者可以直接在 NDK 代码中使用 `socket()` 创建套接字，并使用 `ioctl()` 系统调用，并包含 `linux/wireless.h` 头文件（或 bionic 中的对应路径）。
3. **编译和链接:** NDK 代码会被编译成动态链接库，并链接到 Bionic libc。

**Frida Hook 示例调试步骤:**

假设我们想 hook `ioctl` 系统调用，查看其与无线相关的操作。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['data']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(['com.android.settings']) # 替换为目标进程
    session = device.attach(pid)
    device.resume(pid)
except frida.TimedOutError:
    print("[-] Device not found or busy.")
    sys.exit(1)
except frida.RPCError as e:
    print(f"[-] RPC Error: {e}")
    sys.exit(1)

script_code = """
    var libc = Process.getModuleByName("libc.so");
    var ioctlPtr = libc.getExportByName("ioctl");

    Interceptor.attach(ioctlPtr, {
        onEnter: function(args) {
            var fd = args[0].toInt32();
            var request = args[1].toInt32();
            var requestName = "Unknown";

            // 将 SIOC 常量映射到名称 (只列举部分)
            var siocMap = {
                0x8B00: "SIOCSIWCOMMIT",
                0x8B01: "SIOCGIWNAME",
                0x8B1A: "SIOCSIWESSID",
                0x8B1B: "SIOCGIWESSID",
                0x8B18: "SIOCSIWSCAN",
                0x8B19: "SIOCGIWSCAN"
            };

            if (siocMap[request]) {
                requestName = siocMap[request];
            } else if ((request >= 0x8B00) && (request <= 0x8BFF)) {
                requestName = "SIOCIW (Unknown)";
            }

            send({ tag: "ioctl", data: "ioctl(fd=" + fd + ", request=" + request + " (" + requestName + "))" });

            // 你可以进一步解析 arg[2] 指向的数据结构，但这需要了解具体的 ioctl 命令和数据结构布局
        },
        onLeave: function(retval) {
            send({ tag: "ioctl", data: "ioctl returned: " + retval });
        }
    });
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **导入 Frida 库:**  导入 `frida` 和 `sys` 库。
2. **定义消息处理函数:** `on_message` 函数用于打印 Frida 脚本发送的消息。
3. **连接到设备和进程:** 使用 `frida.get_usb_device()` 连接到 USB 设备，然后使用 `device.spawn()` 启动目标进程 (例如 Android 设置)，或使用 `device.attach()` 连接到已运行的进程。
4. **获取 `ioctl` 函数地址:** 使用 `Process.getModuleByName("libc.so")` 获取 `libc.so` 模块，然后使用 `getExportByName("ioctl")` 获取 `ioctl` 函数的地址。
5. **拦截 `ioctl` 调用:** 使用 `Interceptor.attach()` 拦截 `ioctl` 函数的调用。
6. **`onEnter` 函数:** 在 `ioctl` 函数调用之前执行：
   * 获取函数参数：文件描述符 `fd` 和请求码 `request`。
   * 将请求码映射到名称：创建一个 `siocMap` 字典，将常见的 `SIOC` 常量映射到其名称。
   * 发送消息：使用 `send()` 函数将 `ioctl` 的调用信息发送回 Python 脚本。
   * **进一步解析参数:** 可以根据 `request` 的值，进一步解析 `args[2]` 指向的数据结构，例如 `iwreq`，以获取更详细的无线操作信息。这需要根据具体的 `ioctl` 命令来解析相应的结构体。
7. **`onLeave` 函数:** 在 `ioctl` 函数调用之后执行，打印返回值。
8. **加载脚本:** 使用 `session.create_script()` 创建 Frida 脚本，并使用 `script.load()` 加载脚本到目标进程。
9. **保持脚本运行:** 使用 `sys.stdin.read()` 使 Python 脚本保持运行状态，以便持续监听目标进程的 `ioctl` 调用。

通过运行这个 Frida 脚本，你可以监控 Android 系统或应用在进行无线操作时调用的 `ioctl` 系统调用，并查看相关的命令码，从而理解 Android Framework 或 NDK 是如何一步步地使用 `wireless.handroid` 中定义的常量来与内核进行交互的。要解析 `args[2]` 指向的数据，你需要根据 `request` 的值，查阅 `wireless.handroid` 中定义的结构体，并使用 Frida 的 Memory API 来读取内存中的数据。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/wireless.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_WIRELESS_H
#define _UAPI_LINUX_WIRELESS_H
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <stddef.h>
#define WIRELESS_EXT 22
#define SIOCSIWCOMMIT 0x8B00
#define SIOCGIWNAME 0x8B01
#define SIOCSIWNWID 0x8B02
#define SIOCGIWNWID 0x8B03
#define SIOCSIWFREQ 0x8B04
#define SIOCGIWFREQ 0x8B05
#define SIOCSIWMODE 0x8B06
#define SIOCGIWMODE 0x8B07
#define SIOCSIWSENS 0x8B08
#define SIOCGIWSENS 0x8B09
#define SIOCSIWRANGE 0x8B0A
#define SIOCGIWRANGE 0x8B0B
#define SIOCSIWPRIV 0x8B0C
#define SIOCGIWPRIV 0x8B0D
#define SIOCSIWSTATS 0x8B0E
#define SIOCGIWSTATS 0x8B0F
#define SIOCSIWSPY 0x8B10
#define SIOCGIWSPY 0x8B11
#define SIOCSIWTHRSPY 0x8B12
#define SIOCGIWTHRSPY 0x8B13
#define SIOCSIWAP 0x8B14
#define SIOCGIWAP 0x8B15
#define SIOCGIWAPLIST 0x8B17
#define SIOCSIWSCAN 0x8B18
#define SIOCGIWSCAN 0x8B19
#define SIOCSIWESSID 0x8B1A
#define SIOCGIWESSID 0x8B1B
#define SIOCSIWNICKN 0x8B1C
#define SIOCGIWNICKN 0x8B1D
#define SIOCSIWRATE 0x8B20
#define SIOCGIWRATE 0x8B21
#define SIOCSIWRTS 0x8B22
#define SIOCGIWRTS 0x8B23
#define SIOCSIWFRAG 0x8B24
#define SIOCGIWFRAG 0x8B25
#define SIOCSIWTXPOW 0x8B26
#define SIOCGIWTXPOW 0x8B27
#define SIOCSIWRETRY 0x8B28
#define SIOCGIWRETRY 0x8B29
#define SIOCSIWENCODE 0x8B2A
#define SIOCGIWENCODE 0x8B2B
#define SIOCSIWPOWER 0x8B2C
#define SIOCGIWPOWER 0x8B2D
#define SIOCSIWGENIE 0x8B30
#define SIOCGIWGENIE 0x8B31
#define SIOCSIWMLME 0x8B16
#define SIOCSIWAUTH 0x8B32
#define SIOCGIWAUTH 0x8B33
#define SIOCSIWENCODEEXT 0x8B34
#define SIOCGIWENCODEEXT 0x8B35
#define SIOCSIWPMKSA 0x8B36
#define SIOCIWFIRSTPRIV 0x8BE0
#define SIOCIWLASTPRIV 0x8BFF
#define SIOCIWFIRST 0x8B00
#define SIOCIWLAST SIOCIWLASTPRIV
#define IW_IOCTL_IDX(cmd) ((cmd) - SIOCIWFIRST)
#define IW_HANDLER(id,func) [IW_IOCTL_IDX(id)] = func
#define IW_IS_SET(cmd) (! ((cmd) & 0x1))
#define IW_IS_GET(cmd) ((cmd) & 0x1)
#define IWEVTXDROP 0x8C00
#define IWEVQUAL 0x8C01
#define IWEVCUSTOM 0x8C02
#define IWEVREGISTERED 0x8C03
#define IWEVEXPIRED 0x8C04
#define IWEVGENIE 0x8C05
#define IWEVMICHAELMICFAILURE 0x8C06
#define IWEVASSOCREQIE 0x8C07
#define IWEVASSOCRESPIE 0x8C08
#define IWEVPMKIDCAND 0x8C09
#define IWEVFIRST 0x8C00
#define IW_EVENT_IDX(cmd) ((cmd) - IWEVFIRST)
#define IW_PRIV_TYPE_MASK 0x7000
#define IW_PRIV_TYPE_NONE 0x0000
#define IW_PRIV_TYPE_BYTE 0x1000
#define IW_PRIV_TYPE_CHAR 0x2000
#define IW_PRIV_TYPE_INT 0x4000
#define IW_PRIV_TYPE_FLOAT 0x5000
#define IW_PRIV_TYPE_ADDR 0x6000
#define IW_PRIV_SIZE_FIXED 0x0800
#define IW_PRIV_SIZE_MASK 0x07FF
#define IW_MAX_FREQUENCIES 32
#define IW_MAX_BITRATES 32
#define IW_MAX_TXPOWER 8
#define IW_MAX_SPY 8
#define IW_MAX_AP 64
#define IW_ESSID_MAX_SIZE 32
#define IW_MODE_AUTO 0
#define IW_MODE_ADHOC 1
#define IW_MODE_INFRA 2
#define IW_MODE_MASTER 3
#define IW_MODE_REPEAT 4
#define IW_MODE_SECOND 5
#define IW_MODE_MONITOR 6
#define IW_MODE_MESH 7
#define IW_QUAL_QUAL_UPDATED 0x01
#define IW_QUAL_LEVEL_UPDATED 0x02
#define IW_QUAL_NOISE_UPDATED 0x04
#define IW_QUAL_ALL_UPDATED 0x07
#define IW_QUAL_DBM 0x08
#define IW_QUAL_QUAL_INVALID 0x10
#define IW_QUAL_LEVEL_INVALID 0x20
#define IW_QUAL_NOISE_INVALID 0x40
#define IW_QUAL_RCPI 0x80
#define IW_QUAL_ALL_INVALID 0x70
#define IW_FREQ_AUTO 0x00
#define IW_FREQ_FIXED 0x01
#define IW_MAX_ENCODING_SIZES 8
#define IW_ENCODING_TOKEN_MAX 64
#define IW_ENCODE_INDEX 0x00FF
#define IW_ENCODE_FLAGS 0xFF00
#define IW_ENCODE_MODE 0xF000
#define IW_ENCODE_DISABLED 0x8000
#define IW_ENCODE_ENABLED 0x0000
#define IW_ENCODE_RESTRICTED 0x4000
#define IW_ENCODE_OPEN 0x2000
#define IW_ENCODE_NOKEY 0x0800
#define IW_ENCODE_TEMP 0x0400
#define IW_POWER_ON 0x0000
#define IW_POWER_TYPE 0xF000
#define IW_POWER_PERIOD 0x1000
#define IW_POWER_TIMEOUT 0x2000
#define IW_POWER_MODE 0x0F00
#define IW_POWER_UNICAST_R 0x0100
#define IW_POWER_MULTICAST_R 0x0200
#define IW_POWER_ALL_R 0x0300
#define IW_POWER_FORCE_S 0x0400
#define IW_POWER_REPEATER 0x0800
#define IW_POWER_MODIFIER 0x000F
#define IW_POWER_MIN 0x0001
#define IW_POWER_MAX 0x0002
#define IW_POWER_RELATIVE 0x0004
#define IW_TXPOW_TYPE 0x00FF
#define IW_TXPOW_DBM 0x0000
#define IW_TXPOW_MWATT 0x0001
#define IW_TXPOW_RELATIVE 0x0002
#define IW_TXPOW_RANGE 0x1000
#define IW_RETRY_ON 0x0000
#define IW_RETRY_TYPE 0xF000
#define IW_RETRY_LIMIT 0x1000
#define IW_RETRY_LIFETIME 0x2000
#define IW_RETRY_MODIFIER 0x00FF
#define IW_RETRY_MIN 0x0001
#define IW_RETRY_MAX 0x0002
#define IW_RETRY_RELATIVE 0x0004
#define IW_RETRY_SHORT 0x0010
#define IW_RETRY_LONG 0x0020
#define IW_SCAN_DEFAULT 0x0000
#define IW_SCAN_ALL_ESSID 0x0001
#define IW_SCAN_THIS_ESSID 0x0002
#define IW_SCAN_ALL_FREQ 0x0004
#define IW_SCAN_THIS_FREQ 0x0008
#define IW_SCAN_ALL_MODE 0x0010
#define IW_SCAN_THIS_MODE 0x0020
#define IW_SCAN_ALL_RATE 0x0040
#define IW_SCAN_THIS_RATE 0x0080
#define IW_SCAN_TYPE_ACTIVE 0
#define IW_SCAN_TYPE_PASSIVE 1
#define IW_SCAN_MAX_DATA 4096
#define IW_SCAN_CAPA_NONE 0x00
#define IW_SCAN_CAPA_ESSID 0x01
#define IW_SCAN_CAPA_BSSID 0x02
#define IW_SCAN_CAPA_CHANNEL 0x04
#define IW_SCAN_CAPA_MODE 0x08
#define IW_SCAN_CAPA_RATE 0x10
#define IW_SCAN_CAPA_TYPE 0x20
#define IW_SCAN_CAPA_TIME 0x40
#define IW_CUSTOM_MAX 256
#define IW_GENERIC_IE_MAX 1024
#define IW_MLME_DEAUTH 0
#define IW_MLME_DISASSOC 1
#define IW_MLME_AUTH 2
#define IW_MLME_ASSOC 3
#define IW_AUTH_INDEX 0x0FFF
#define IW_AUTH_FLAGS 0xF000
#define IW_AUTH_WPA_VERSION 0
#define IW_AUTH_CIPHER_PAIRWISE 1
#define IW_AUTH_CIPHER_GROUP 2
#define IW_AUTH_KEY_MGMT 3
#define IW_AUTH_TKIP_COUNTERMEASURES 4
#define IW_AUTH_DROP_UNENCRYPTED 5
#define IW_AUTH_80211_AUTH_ALG 6
#define IW_AUTH_WPA_ENABLED 7
#define IW_AUTH_RX_UNENCRYPTED_EAPOL 8
#define IW_AUTH_ROAMING_CONTROL 9
#define IW_AUTH_PRIVACY_INVOKED 10
#define IW_AUTH_CIPHER_GROUP_MGMT 11
#define IW_AUTH_MFP 12
#define IW_AUTH_WPA_VERSION_DISABLED 0x00000001
#define IW_AUTH_WPA_VERSION_WPA 0x00000002
#define IW_AUTH_WPA_VERSION_WPA2 0x00000004
#define IW_AUTH_CIPHER_NONE 0x00000001
#define IW_AUTH_CIPHER_WEP40 0x00000002
#define IW_AUTH_CIPHER_TKIP 0x00000004
#define IW_AUTH_CIPHER_CCMP 0x00000008
#define IW_AUTH_CIPHER_WEP104 0x00000010
#define IW_AUTH_CIPHER_AES_CMAC 0x00000020
#define IW_AUTH_KEY_MGMT_802_1X 1
#define IW_AUTH_KEY_MGMT_PSK 2
#define IW_AUTH_ALG_OPEN_SYSTEM 0x00000001
#define IW_AUTH_ALG_SHARED_KEY 0x00000002
#define IW_AUTH_ALG_LEAP 0x00000004
#define IW_AUTH_ROAMING_ENABLE 0
#define IW_AUTH_ROAMING_DISABLE 1
#define IW_AUTH_MFP_DISABLED 0
#define IW_AUTH_MFP_OPTIONAL 1
#define IW_AUTH_MFP_REQUIRED 2
#define IW_ENCODE_SEQ_MAX_SIZE 8
#define IW_ENCODE_ALG_NONE 0
#define IW_ENCODE_ALG_WEP 1
#define IW_ENCODE_ALG_TKIP 2
#define IW_ENCODE_ALG_CCMP 3
#define IW_ENCODE_ALG_PMK 4
#define IW_ENCODE_ALG_AES_CMAC 5
#define IW_ENCODE_EXT_TX_SEQ_VALID 0x00000001
#define IW_ENCODE_EXT_RX_SEQ_VALID 0x00000002
#define IW_ENCODE_EXT_GROUP_KEY 0x00000004
#define IW_ENCODE_EXT_SET_TX_KEY 0x00000008
#define IW_MICFAILURE_KEY_ID 0x00000003
#define IW_MICFAILURE_GROUP 0x00000004
#define IW_MICFAILURE_PAIRWISE 0x00000008
#define IW_MICFAILURE_STAKEY 0x00000010
#define IW_MICFAILURE_COUNT 0x00000060
#define IW_ENC_CAPA_WPA 0x00000001
#define IW_ENC_CAPA_WPA2 0x00000002
#define IW_ENC_CAPA_CIPHER_TKIP 0x00000004
#define IW_ENC_CAPA_CIPHER_CCMP 0x00000008
#define IW_ENC_CAPA_4WAY_HANDSHAKE 0x00000010
#define IW_EVENT_CAPA_BASE(cmd) ((cmd >= SIOCIWFIRSTPRIV) ? (cmd - SIOCIWFIRSTPRIV + 0x60) : (cmd - SIOCIWFIRST))
#define IW_EVENT_CAPA_INDEX(cmd) (IW_EVENT_CAPA_BASE(cmd) >> 5)
#define IW_EVENT_CAPA_MASK(cmd) (1 << (IW_EVENT_CAPA_BASE(cmd) & 0x1F))
#define IW_EVENT_CAPA_K_0 (IW_EVENT_CAPA_MASK(0x8B04) | IW_EVENT_CAPA_MASK(0x8B06) | IW_EVENT_CAPA_MASK(0x8B1A))
#define IW_EVENT_CAPA_K_1 (IW_EVENT_CAPA_MASK(0x8B2A))
#define IW_EVENT_CAPA_SET(event_capa,cmd) (event_capa[IW_EVENT_CAPA_INDEX(cmd)] |= IW_EVENT_CAPA_MASK(cmd))
#define IW_EVENT_CAPA_SET_KERNEL(event_capa) { event_capa[0] |= IW_EVENT_CAPA_K_0; event_capa[1] |= IW_EVENT_CAPA_K_1; }
struct iw_param {
  __s32 value;
  __u8 fixed;
  __u8 disabled;
  __u16 flags;
};
struct iw_point {
  void  * pointer;
  __u16 length;
  __u16 flags;
};
struct iw_freq {
  __s32 m;
  __s16 e;
  __u8 i;
  __u8 flags;
};
struct iw_quality {
  __u8 qual;
  __u8 level;
  __u8 noise;
  __u8 updated;
};
struct iw_discarded {
  __u32 nwid;
  __u32 code;
  __u32 fragment;
  __u32 retries;
  __u32 misc;
};
struct iw_missed {
  __u32 beacon;
};
struct iw_thrspy {
  struct sockaddr addr;
  struct iw_quality qual;
  struct iw_quality low;
  struct iw_quality high;
};
struct iw_scan_req {
  __u8 scan_type;
  __u8 essid_len;
  __u8 num_channels;
  __u8 flags;
  struct sockaddr bssid;
  __u8 essid[IW_ESSID_MAX_SIZE];
  __u32 min_channel_time;
  __u32 max_channel_time;
  struct iw_freq channel_list[IW_MAX_FREQUENCIES];
};
struct iw_encode_ext {
  __u32 ext_flags;
  __u8 tx_seq[IW_ENCODE_SEQ_MAX_SIZE];
  __u8 rx_seq[IW_ENCODE_SEQ_MAX_SIZE];
  struct sockaddr addr;
  __u16 alg;
  __u16 key_len;
  __u8 key[];
};
struct iw_mlme {
  __u16 cmd;
  __u16 reason_code;
  struct sockaddr addr;
};
#define IW_PMKSA_ADD 1
#define IW_PMKSA_REMOVE 2
#define IW_PMKSA_FLUSH 3
#define IW_PMKID_LEN 16
struct iw_pmksa {
  __u32 cmd;
  struct sockaddr bssid;
  __u8 pmkid[IW_PMKID_LEN];
};
struct iw_michaelmicfailure {
  __u32 flags;
  struct sockaddr src_addr;
  __u8 tsc[IW_ENCODE_SEQ_MAX_SIZE];
};
#define IW_PMKID_CAND_PREAUTH 0x00000001
struct iw_pmkid_cand {
  __u32 flags;
  __u32 index;
  struct sockaddr bssid;
};
struct iw_statistics {
  __u16 status;
  struct iw_quality qual;
  struct iw_discarded discard;
  struct iw_missed miss;
};
union iwreq_data {
  char name[IFNAMSIZ];
  struct iw_point essid;
  struct iw_param nwid;
  struct iw_freq freq;
  struct iw_param sens;
  struct iw_param bitrate;
  struct iw_param txpower;
  struct iw_param rts;
  struct iw_param frag;
  __u32 mode;
  struct iw_param retry;
  struct iw_point encoding;
  struct iw_param power;
  struct iw_quality qual;
  struct sockaddr ap_addr;
  struct sockaddr addr;
  struct iw_param param;
  struct iw_point data;
};
struct iwreq {
  union {
    char ifrn_name[IFNAMSIZ];
  } ifr_ifrn;
  union iwreq_data u;
};
struct iw_range {
  __u32 throughput;
  __u32 min_nwid;
  __u32 max_nwid;
  __u16 old_num_channels;
  __u8 old_num_frequency;
  __u8 scan_capa;
  __u32 event_capa[6];
  __s32 sensitivity;
  struct iw_quality max_qual;
  struct iw_quality avg_qual;
  __u8 num_bitrates;
  __s32 bitrate[IW_MAX_BITRATES];
  __s32 min_rts;
  __s32 max_rts;
  __s32 min_frag;
  __s32 max_frag;
  __s32 min_pmp;
  __s32 max_pmp;
  __s32 min_pmt;
  __s32 max_pmt;
  __u16 pmp_flags;
  __u16 pmt_flags;
  __u16 pm_capa;
  __u16 encoding_size[IW_MAX_ENCODING_SIZES];
  __u8 num_encoding_sizes;
  __u8 max_encoding_tokens;
  __u8 encoding_login_index;
  __u16 txpower_capa;
  __u8 num_txpower;
  __s32 txpower[IW_MAX_TXPOWER];
  __u8 we_version_compiled;
  __u8 we_version_source;
  __u16 retry_capa;
  __u16 retry_flags;
  __u16 r_time_flags;
  __s32 min_retry;
  __s32 max_retry;
  __s32 min_r_time;
  __s32 max_r_time;
  __u16 num_channels;
  __u8 num_frequency;
  struct iw_freq freq[IW_MAX_FREQUENCIES];
  __u32 enc_capa;
};
struct iw_priv_args {
  __u32 cmd;
  __u16 set_args;
  __u16 get_args;
  char name[IFNAMSIZ];
};
struct iw_event {
  __u16 len;
  __u16 cmd;
  union iwreq_data u;
};
#define IW_EV_LCP_LEN (sizeof(struct iw_event) - sizeof(union iwreq_data))
#define IW_EV_CHAR_LEN (IW_EV_LCP_LEN + IFNAMSIZ)
#define IW_EV_UINT_LEN (IW_EV_LCP_LEN + sizeof(__u32))
#define IW_EV_FREQ_LEN (IW_EV_LCP_LEN + sizeof(struct iw_freq))
#define IW_EV_PARAM_LEN (IW_EV_LCP_LEN + sizeof(struct iw_param))
#define IW_EV_ADDR_LEN (IW_EV_LCP_LEN + sizeof(struct sockaddr))
#define IW_EV_QUAL_LEN (IW_EV_LCP_LEN + sizeof(struct iw_quality))
#define IW_EV_POINT_OFF offsetof(struct iw_point, length)
#define IW_EV_POINT_LEN (IW_EV_LCP_LEN + sizeof(struct iw_point) - IW_EV_POINT_OFF)
#define IW_EV_LCP_PK_LEN (4)
#define IW_EV_CHAR_PK_LEN (IW_EV_LCP_PK_LEN + IFNAMSIZ)
#define IW_EV_UINT_PK_LEN (IW_EV_LCP_PK_LEN + sizeof(__u32))
#define IW_EV_FREQ_PK_LEN (IW_EV_LCP_PK_LEN + sizeof(struct iw_freq))
#define IW_EV_PARAM_PK_LEN (IW_EV_LCP_PK_LEN + sizeof(struct iw_param))
#define IW_EV_ADDR_PK_LEN (IW_EV_LCP_PK_LEN + sizeof(struct sockaddr))
#define IW_EV_QUAL_PK_LEN (IW_EV_LCP_PK_LEN + sizeof(struct iw_quality))
#define IW_EV_POINT_PK_LEN (IW_EV_LCP_PK_LEN + 4)
#endif
```