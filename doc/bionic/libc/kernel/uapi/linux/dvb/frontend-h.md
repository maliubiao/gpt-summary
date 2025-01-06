Response:
Let's break down the thought process for answering the request about the `frontend.handroid` header file.

**1. Understanding the Core Request:**

The fundamental goal is to analyze a C header file related to DVB frontend control in Android, specifically within the `bionic` library. The request has several sub-parts, requiring explanations of functionality, Android relevance, libc/dynamic linker aspects, usage errors, and how Android frameworks access this code.

**2. Initial Scan and Identification of Key Concepts:**

My first step is to quickly scan the file and identify the major components:

* **Include:**  `#include <linux/types.h>` -  Indicates this header relies on standard Linux type definitions.
* **Enums:**  A large number of `enum` definitions (like `fe_caps`, `fe_type`, `fe_status`, etc.). These define sets of named constants, representing different states, capabilities, and configuration options for DVB frontends.
* **Structures:** Several `struct` definitions (like `dvb_frontend_info`, `dvb_diseqc_master_cmd`, `dtv_property`, etc.). These group related data together, representing hardware information, commands, properties, and status.
* **Macros:** `#define` statements, including bitmasks for capabilities (`FE_CAN_*`), constants for DTV parameters (`DTV_*`), and ioctl definitions (`FE_*`). These provide shortcuts and define the interface for interacting with the DVB driver.
* **Typedefs:**  `typedef` statements create aliases for the `enum` types, often adding a `_t` suffix. This is common practice in C.

From this initial scan, I can deduce the core functionality revolves around controlling and querying digital video broadcasting (DVB) hardware.

**3. Addressing the Specific Questions Systematically:**

Now, I tackle each part of the request:

* **功能 (Functionality):** This is the easiest. I summarize the purpose of the header file based on the identified components. Keywords like "defining the interface," "controlling DVB hardware," "enumerations for capabilities," "structures for parameters and status," and "ioctl definitions" are key.

* **与 Android 功能的关系及举例 (Relationship with Android and Examples):**  This requires connecting the generic DVB concepts to the Android context. I know Android devices can have TV tuners. The key is to explain *how* this low-level interface might be used. I'd think of the software layers involved:
    * **HAL (Hardware Abstraction Layer):**  This is the most direct connection. The HAL interacts with the kernel drivers using these structures and ioctls.
    * **Android Framework:**  Higher-level Android APIs (like `TvInputService`) abstract the hardware details. They ultimately rely on the HAL.
    * **NDK:**  Developers can potentially access lower-level functionality using the NDK, though direct use of these kernel headers might be less common.
    * **Example:**  Tuning a frequency is a concrete example that demonstrates the flow from a user action to the low-level parameters defined in the header.

* **详细解释每一个 libc 函数的功能是如何实现的 (Detailed explanation of each libc function):**  This is a trick question!  *This header file itself does not define or implement any libc functions.* It *uses* standard C types (`__u32`, `char`, `enum`, `struct`), but it's a header file defining data structures and constants for kernel interaction. My answer needs to clarify this misconception.

* **对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程 (Dynamic linker functionality, SO layout, and linking process):**  Similar to the libc question, this header file isn't directly involved in dynamic linking. It's a header used for system calls. The dynamic linker works with shared libraries (.so files) at the user-space level. My answer should explain this distinction.

* **逻辑推理，假设输入与输出 (Logical reasoning, assumed input and output):** This requires demonstrating how the defined structures and enums would be used in a practical scenario. I choose the example of setting the frequency and modulation, showing how the `dvb_frontend_parameters` structure would be populated and passed to the kernel (implicitly through an ioctl).

* **用户或者编程常见的使用错误 (Common user/programming errors):** I focus on errors related to incorrect usage of the defined structures and ioctls. Examples include passing invalid enum values, incorrect structure sizes, and forgetting permissions.

* **说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤 (How Android Framework/NDK reaches here, Frida hook example):** This involves tracing the path from the Android framework down to the kernel.
    * **Framework:** I start with a high-level component like `TvInputService` and mention its interaction with the HAL.
    * **HAL:**  Emphasize the HAL as the bridge.
    * **Kernel Driver:** The HAL communicates with the kernel driver using ioctls, which utilize the structures defined in this header.
    * **Frida Hook:** A Frida example targeting the `ioctl` system call, specifically looking for the `FE_SET_FRONTEND` command, shows how to intercept and observe this interaction. It’s crucial to illustrate how to extract relevant information from the hooked call.

**4. Language and Formatting:**

Throughout the process, I maintain the request's language (Chinese). I use clear headings and bullet points to organize the information and make it easily digestible. I ensure the technical terms are accurate and explained where necessary.

**Self-Correction/Refinement during the Process:**

* **Initial Misinterpretation:**  I might initially think this header file *implements* some functionality. However, recognizing the `#ifndef` guards, `#include`, and the nature of the definitions clarifies that it's a *declaration* file for interacting with kernel drivers.
* **Overly Technical:**  I might initially provide very low-level kernel details. I'd then adjust to explain concepts at a level understandable to someone familiar with Android development but perhaps not kernel internals.
* **Missing Context:** I might forget to explicitly mention the role of the HAL. I'd go back and ensure that关键 intermediary is highlighted.

By following this structured approach, combining technical knowledge with an understanding of the Android architecture, and carefully addressing each part of the request, I can generate a comprehensive and accurate answer.
## 对 bionic/libc/kernel/uapi/linux/dvb/frontend.handroid 的源代码文件分析

这个头文件 `frontend.handroid` 定义了用于控制数字视频广播 (DVB) 前端的内核用户空间应用程序接口 (uAPI)。 DVB 前端是接收和解调数字电视信号的硬件组件。由于它位于 `bionic/libc/kernel/uapi/linux` 目录下，可以判断它是 Android 系统中 bionic C 库为了兼容 Linux 内核 API 而提供的。`handroid` 可能是指为 Android 定制的版本或者只是一个用于区分的命名。

**它的功能:**

这个头文件主要定义了以下功能：

1. **定义了 DVB 前端硬件的能力 (Capabilities):** `enum fe_caps` 枚举列出了各种 DVB 前端可以支持的特性，例如自动反转、不同的前向纠错 (FEC) 码率、不同的调制方式 (QPSK, QAM 等)、带宽设置、保护间隔等等。这些能力标志位可以用来查询硬件的支持情况。

2. **定义了 DVB 前端的类型 (Type):** `enum fe_type` 枚举定义了不同的 DVB 前端类型，例如 QPSK (卫星)、QAM (有线)、OFDM (地面) 和 ATSC (北美地面)。

3. **定义了 DVB 前端的信息结构 (Information Structure):** `struct dvb_frontend_info` 结构体包含了 DVB 前端硬件的详细信息，例如名称、类型、支持的频率范围、符号率范围、以及 `fe_caps` 定义的能力。

4. **定义了用于控制 DiSEqC 设备的消息结构 (DiSEqC Control):** `struct dvb_diseqc_master_cmd` 和 `struct dvb_diseqc_slave_reply` 用于与 DiSEqC (Digital Satellite Equipment Control) 设备通信，例如控制卫星天线的旋转或切换 LNB (低噪声模块)。

5. **定义了 LNB 电压和 22kHz 音频信号的控制 (LNB Control):** `enum fe_sec_voltage` 和 `enum fe_sec_tone_mode` 用于控制连接到 DVB 前端的低噪声模块 (LNB) 的电压 (13V/18V 用于选择极化) 和 22kHz 音频信号 (用于选择频段)。

6. **定义了发送迷你 DiSEqC 命令 (Mini DiSEqC Command):** `enum fe_sec_mini_cmd` 定义了可以发送的简单的 DiSEqC 命令。

7. **定义了 DVB 前端的状态 (Status):** `enum fe_status` 枚举定义了 DVB 前端在接收信号过程中的各种状态，例如是否有信号、是否捕获到载波、Viterbi 解码器是否同步、是否锁定信号等等。

8. **定义了频谱反转模式 (Spectral Inversion):** `enum fe_spectral_inversion` 定义了频谱反转是打开、关闭还是自动。

9. **定义了前向纠错码率 (FEC Rate):** `enum fe_code_rate` 枚举定义了各种可能的前向纠错码率。

10. **定义了调制方式 (Modulation):** `enum fe_modulation` 枚举定义了各种可能的调制方式，例如 QPSK、QAM-16、QAM-256 等。

11. **定义了传输模式 (Transmission Mode):** `enum fe_transmit_mode` 枚举定义了 OFDM 系统的传输模式，例如 2K、8K 等。

12. **定义了保护间隔 (Guard Interval):** `enum fe_guard_interval` 枚举定义了 OFDM 系统的保护间隔。

13. **定义了分层调制 (Hierarchy):** `enum fe_hierarchy` 枚举定义了分层调制的信息。

14. **定义了交织模式 (Interleaving):** `enum fe_interleaving` 枚举定义了交织模式。

15. **定义了用于设置和获取 DVB 前端属性的宏 (DTV Properties):** 以 `DTV_` 开头的宏定义了各种可以设置和获取的 DVB 前端属性的 ID，例如频率、调制方式、带宽、FEC 等等。这些宏通常与 `FE_SET_PROPERTY` 和 `FE_GET_PROPERTY` ioctl 一起使用。

16. **定义了用于控制 DVB 前端的 ioctl 请求码 (IOCTL Request Codes):** 以 `FE_` 开头的宏定义了可以发送给 DVB 前端驱动的 ioctl 请求码，例如 `FE_GET_INFO` (获取前端信息)、`FE_SET_FRONTEND` (设置前端参数)、`FE_READ_STATUS` (读取前端状态) 等。

17. **定义了带宽 (Bandwidth):** `enum fe_bandwidth` 定义了不同的带宽值。

18. **定义了导频信号 (Pilot):** `enum fe_pilot` 定义了导频信号的状态。

19. **定义了滚降系数 (Rolloff):** `enum fe_rolloff` 定义了滚降系数。

20. **定义了传输系统 (Delivery System):** `enum fe_delivery_system` 定义了不同的传输系统标准，例如 DVB-C、DVB-T、DVB-S、ISDB-T、ATSC 等。

21. **定义了用于获取统计信息的结构 (Statistics):** `struct dtv_stats` 和 `struct dtv_fe_stats` 用于获取 DVB 前端的统计信息，例如信号强度、信噪比、误码率等。

22. **定义了用于设置和获取 DVB 前端属性的通用结构 (DTV Property):** `struct dtv_property` 是一个通用的结构体，用于设置和获取 DVB 前端的各种属性。它包含属性的命令码、数据、以及操作结果。

23. **定义了用于批量设置 DVB 前端属性的结构 (DTV Properties):** `struct dtv_properties` 允许一次设置多个 DVB 前端属性。

24. **定义了 DVB 前端事件结构 (Frontend Event):** `struct dvb_frontend_event` 包含了前端的状态和参数，用于异步通知事件。

**它与 Android 的功能的关系及举例说明:**

Android 设备，特别是那些具有数字电视接收功能的设备（例如某些平板电脑、电视盒子或车载设备），会使用到这些定义。Android Framework 或者 NDK 中的应用程序可以通过访问底层的 DVB 驱动程序来控制电视调谐器。

**举例说明:**

假设一个 Android 应用需要调谐到一个特定的电视频道。它需要执行以下步骤，这些步骤会涉及到这个头文件中定义的结构和宏：

1. **打开 DVB 前端设备文件:**  使用 `open()` 系统调用打开与 DVB 前端硬件关联的设备文件，通常位于 `/dev/dvb/adapterX/frontendY`。

2. **获取前端信息:** 使用 `ioctl(fd, FE_GET_INFO, &frontend_info)` 获取前端的硬件信息，`frontend_info` 是一个 `struct dvb_frontend_info` 类型的变量。通过这个调用，可以知道前端支持的类型和能力。

3. **设置前端参数:**  根据要调谐的频道信息，填充 `struct dvb_frontend_parameters` 结构体，包括频率、符号率、调制方式、FEC 等参数。例如，如果要调谐一个 QPSK 卫星频道，需要填充 `u.qpsk` 成员。

4. **调用 `FE_SET_FRONTEND` ioctl:** 使用 `ioctl(fd, FE_SET_FRONTEND, &frontend_parameters)` 将设置好的参数发送给驱动程序，驱动程序会控制硬件进行调谐。

5. **轮询或等待状态:** 使用 `ioctl(fd, FE_READ_STATUS, &status)` 定期读取前端状态，直到 `status` 中的 `FE_HAS_LOCK` 位被设置，表示调谐成功。

6. **获取信号质量:** 使用 `ioctl(fd, FE_READ_SIGNAL_STRENGTH, &signal_strength)` 或 `ioctl(fd, FE_READ_SNR, &snr)` 获取信号强度和信噪比等信息。也可以使用 `FE_GET_PROPERTY` 和相关的 `DTV_STAT_*` 宏来获取更详细的统计信息。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**并没有定义或实现任何 libc 函数**。它定义的是数据结构、枚举和宏，这些是用于与内核驱动程序交互的接口。实际的 libc 函数，例如 `open()` 和 `ioctl()`，是在 `bionic` 库中实现的。

* **`open()`:** `open()` 函数用于打开一个文件或设备。它的实现涉及到系统调用 `__NR_openat` (或者更早版本的 `__NR_open`)。内核会根据路径名找到对应的文件系统或设备驱动程序，并分配一个文件描述符返回给用户空间。

* **`ioctl()`:** `ioctl()` 函数用于执行设备特定的控制操作。它的实现涉及到系统调用 `__NR_ioctl`。用户空间程序将文件描述符、请求码（例如 `FE_SET_FRONTEND`）和指向参数的指针传递给内核。内核会根据文件描述符找到对应的设备驱动程序，并调用驱动程序中与该请求码关联的处理函数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身与 dynamic linker **没有直接关系**。Dynamic linker 主要负责在程序启动或运行时加载共享库 (.so 文件) 并解析符号。这个头文件定义的是内核 uAPI，用户空间的应用程序会直接使用系统调用与内核交互，而不需要链接特定的共享库来使用这些定义。

通常，与 DVB 相关的用户空间库（例如 libdvbv5）可能会被动态链接，这些库会封装对内核 DVB API 的调用。

**假设一个使用 libdvbv5 的应用程序的 SO 布局样本：**

```
应用程序可执行文件 (e.g., tv_player)
|
├── libdvbv5.so  (封装了 DVB API 调用的共享库)
|   |
|   └── libc.so  (Android 的 C 库，包含 open() 和 ioctl())
|
└── linker64 或 linker  (动态链接器)
```

**链接的处理过程：**

1. **加载可执行文件:** 操作系统加载应用程序的可执行文件到内存。
2. **解析依赖:** 动态链接器 (linker64 或 linker) 解析可执行文件头的依赖信息，发现需要链接 `libdvbv5.so` 和 `libc.so`。
3. **加载共享库:** 动态链接器在预定义的路径中查找并加载这些共享库到内存。
4. **符号解析和重定位:** 动态链接器解析共享库的符号表，并将可执行文件和共享库中未定义的符号地址绑定到已加载的共享库中的符号地址。例如，应用程序中调用了 `libdvbv5.so` 中的一个函数，动态链接器会将该调用指向 `libdvbv5.so` 中该函数的实际地址。类似地，`libdvbv5.so` 中对 `open()` 和 `ioctl()` 的调用会链接到 `libc.so` 中的实现。

**逻辑推理，请给出假设输入与输出:**

**假设输入:**

* 用户空间应用程序尝试调谐到频率为 12500 MHz，符号率为 27500 kSps 的卫星频道，使用 QPSK 调制和 FEC 3/4。

**对应的结构体填充：**

```c
#include <linux/dvb/frontend.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int fd = open("/dev/dvb/adapter0/frontend0", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct dvb_frontend_parameters params;
    params.frequency = 12500000; // 频率单位是 Hz
    params.inversion = INVERSION_AUTO;
    params.u.qpsk.symbol_rate = 27500000; // 符号率单位是符号/秒
    params.u.qpsk.fec_inner = FEC_3_4;

    if (ioctl(fd, FE_SET_FRONTEND, &params) < 0) {
        perror("ioctl FE_SET_FRONTEND");
        close(fd);
        return 1;
    }

    printf("设置前端参数完成，等待锁定...\n");

    fe_status_t status;
    while (1) {
        if (ioctl(fd, FE_READ_STATUS, &status) < 0) {
            perror("ioctl FE_READ_STATUS");
            break;
        }
        if (status & FE_HAS_LOCK) {
            printf("锁定成功！\n");
            break;
        }
        usleep(100000); // 等待 100 毫秒
    }

    close(fd);
    return 0;
}
```

**预期输出:**

如果硬件工作正常且信号存在，程序会输出：

```
设置前端参数完成，等待锁定...
锁定成功！
```

如果出现错误，例如设备文件无法打开或 ioctl 调用失败，程序会输出相应的错误信息。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **传递无效的枚举值:** 例如，将 `params.u.qpsk.fec_inner` 设置为一个未定义的 `fe_code_rate` 值。这可能导致驱动程序无法正确解析参数或出现未定义的行为。

2. **结构体大小不匹配:** 在使用 `ioctl` 时，如果传递的结构体大小与驱动程序期望的大小不一致，会导致数据错乱或内核崩溃。虽然头文件定义了结构体，但在不同的内核版本或体系结构下，结构体的填充方式可能略有不同。

3. **忘记检查 ioctl 的返回值:** `ioctl` 调用失败时会返回 -1，并设置 `errno`。程序员应该始终检查返回值并处理错误情况，例如设备不存在、权限不足或参数错误。

4. **在错误的设备文件上操作:**  例如，尝试在一个音频设备文件上调用 DVB 相关的 ioctl。这会导致 `ioctl` 调用失败。

5. **没有足够的权限:**  访问 `/dev/dvb` 下的设备文件通常需要 root 权限或者特定的用户组权限。普通应用程序如果没有相应的权限，`open()` 调用会失败。

6. **并发访问冲突:** 如果多个进程或线程同时尝试操作同一个 DVB 前端设备，可能会导致冲突和未定义的行为。需要使用适当的同步机制来保护对设备文件的访问。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤 (简化流程):**

1. **用户操作:** 用户在电视应用中选择频道或进行搜索操作。
2. **TV Input Framework:**  Android Framework 中的 `TvInputService` 或相关组件接收到用户的请求。
3. **HAL (Hardware Abstraction Layer):** `TvInputService` 通过 Hardware Abstraction Layer (HAL) 与底层的硬件交互。对于 DVB 设备，通常会使用 `android.hardware.tv.tuner` HAL 接口。
4. **Tuner HAL Implementation:** HAL 接口的实现 (通常是 `.so` 库) 会调用底层的 Linux DVB API。
5. **System Calls:** HAL 实现会使用系统调用，例如 `open()` 打开设备文件，使用 `ioctl()` 发送控制命令（例如 `FE_SET_FRONTEND`）。
6. **Kernel Driver:**  内核接收到 `ioctl` 调用后，会找到对应的 DVB 前端驱动程序。
7. **Hardware Interaction:** DVB 前端驱动程序会解析 ioctl 的参数，并与实际的 DVB 前端硬件进行通信，控制其频率、调制方式等参数。

**NDK 到达这里的步骤:**

使用 NDK 的应用程序可以直接调用底层的 Linux API，流程会更直接：

1. **NDK Application:**  NDK 应用程序使用 C/C++ 代码。
2. **Direct API Calls:** 应用程序直接使用 `open()` 打开 `/dev/dvb/...`，使用 `ioctl()` 发送控制命令，例如示例代码中的操作。

**Frida Hook 示例调试步骤:**

可以使用 Frida hook `ioctl` 系统调用，并过滤与 DVB 前端相关的请求码。

**Frida Hook 代码示例 (使用 Python):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.attach('com.android.tv.livetv') # 替换为目标进程名称

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            // 过滤与 DVB 前端相关的 ioctl 请求码
            const FE_SET_FRONTEND = 0xc0446f4c; // _IOW('o', 76, struct dvb_frontend_parameters)
            const FE_GET_INFO = 0x80386f3d;    // _IOR('o', 61, struct dvb_frontend_info)
            const FE_READ_STATUS = 0x80046f45; // _IOR('o', 69, fe_status_t)

            if (request === FE_SET_FRONTEND || request === FE_GET_INFO || request === FE_READ_STATUS) {
                console.log("ioctl called with fd:", fd, "request:", request);
                if (request === FE_SET_FRONTEND) {
                    // 读取 struct dvb_frontend_parameters 的内容
                    const paramsPtr = args[2];
                    const frequency = paramsPtr.readU32();
                    const inversion = paramsPtr.add(4).readU32(); // 假设 __u32 占用 4 字节
                    console.log("  Frequency:", frequency, "Inversion:", inversion);
                    // ... 可以读取更多参数
                }
            }
        },
        onLeave: function(retval) {
            // console.log("ioctl returned:", retval);
        }
    });
    """
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()

except frida.ServerNotStartedError:
    print("Frida server is not running on the device.")
except frida.USBTimeoutError:
    print("USB connection to the device timed out.")
except frida.ProcessNotFoundError:
    print("Process not found.")
except Exception as e:
    print(e)
```

**使用方法:**

1. 确保 Android 设备上运行了 Frida server。
2. 找到目标电视应用的进程 ID (PID) 或者直接使用应用名称。
3. 运行 Frida hook 脚本，将 PID 或应用名称作为参数传递。

**Frida Hook 输出示例:**

当目标应用尝试设置 DVB 前端参数时，Frida 会拦截 `ioctl` 调用并输出相关信息：

```
[*] ioctl called with fd: 32 request: -1073459380
[*]   Frequency: 12500000 Inversion: 2
[*] ioctl called with fd: 32 request: -2147450819
```

这个示例可以帮助开发者调试 Android Framework 或 NDK 如何与底层的 DVB 驱动进行交互，以及观察传递的具体参数。

总而言之，`bionic/libc/kernel/uapi/linux/dvb/frontend.handroid` 是一个定义了与 Linux DVB 前端驱动程序交互接口的关键头文件，Android 系统中的电视相关功能正是通过这些定义来实现对硬件的控制和数据获取。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/dvb/frontend.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _DVBFRONTEND_H_
#define _DVBFRONTEND_H_
#include <linux/types.h>
enum fe_caps {
  FE_IS_STUPID = 0,
  FE_CAN_INVERSION_AUTO = 0x1,
  FE_CAN_FEC_1_2 = 0x2,
  FE_CAN_FEC_2_3 = 0x4,
  FE_CAN_FEC_3_4 = 0x8,
  FE_CAN_FEC_4_5 = 0x10,
  FE_CAN_FEC_5_6 = 0x20,
  FE_CAN_FEC_6_7 = 0x40,
  FE_CAN_FEC_7_8 = 0x80,
  FE_CAN_FEC_8_9 = 0x100,
  FE_CAN_FEC_AUTO = 0x200,
  FE_CAN_QPSK = 0x400,
  FE_CAN_QAM_16 = 0x800,
  FE_CAN_QAM_32 = 0x1000,
  FE_CAN_QAM_64 = 0x2000,
  FE_CAN_QAM_128 = 0x4000,
  FE_CAN_QAM_256 = 0x8000,
  FE_CAN_QAM_AUTO = 0x10000,
  FE_CAN_TRANSMISSION_MODE_AUTO = 0x20000,
  FE_CAN_BANDWIDTH_AUTO = 0x40000,
  FE_CAN_GUARD_INTERVAL_AUTO = 0x80000,
  FE_CAN_HIERARCHY_AUTO = 0x100000,
  FE_CAN_8VSB = 0x200000,
  FE_CAN_16VSB = 0x400000,
  FE_HAS_EXTENDED_CAPS = 0x800000,
  FE_CAN_MULTISTREAM = 0x4000000,
  FE_CAN_TURBO_FEC = 0x8000000,
  FE_CAN_2G_MODULATION = 0x10000000,
  FE_NEEDS_BENDING = 0x20000000,
  FE_CAN_RECOVER = 0x40000000,
  FE_CAN_MUTE_TS = 0x80000000
};
enum fe_type {
  FE_QPSK,
  FE_QAM,
  FE_OFDM,
  FE_ATSC
};
struct dvb_frontend_info {
  char name[128];
  enum fe_type type;
  __u32 frequency_min;
  __u32 frequency_max;
  __u32 frequency_stepsize;
  __u32 frequency_tolerance;
  __u32 symbol_rate_min;
  __u32 symbol_rate_max;
  __u32 symbol_rate_tolerance;
  __u32 notifier_delay;
  enum fe_caps caps;
};
struct dvb_diseqc_master_cmd {
  __u8 msg[6];
  __u8 msg_len;
};
struct dvb_diseqc_slave_reply {
  __u8 msg[4];
  __u8 msg_len;
  int timeout;
};
enum fe_sec_voltage {
  SEC_VOLTAGE_13,
  SEC_VOLTAGE_18,
  SEC_VOLTAGE_OFF
};
enum fe_sec_tone_mode {
  SEC_TONE_ON,
  SEC_TONE_OFF
};
enum fe_sec_mini_cmd {
  SEC_MINI_A,
  SEC_MINI_B
};
enum fe_status {
  FE_NONE = 0x00,
  FE_HAS_SIGNAL = 0x01,
  FE_HAS_CARRIER = 0x02,
  FE_HAS_VITERBI = 0x04,
  FE_HAS_SYNC = 0x08,
  FE_HAS_LOCK = 0x10,
  FE_TIMEDOUT = 0x20,
  FE_REINIT = 0x40,
};
enum fe_spectral_inversion {
  INVERSION_OFF,
  INVERSION_ON,
  INVERSION_AUTO
};
enum fe_code_rate {
  FEC_NONE = 0,
  FEC_1_2,
  FEC_2_3,
  FEC_3_4,
  FEC_4_5,
  FEC_5_6,
  FEC_6_7,
  FEC_7_8,
  FEC_8_9,
  FEC_AUTO,
  FEC_3_5,
  FEC_9_10,
  FEC_2_5,
  FEC_1_3,
  FEC_1_4,
  FEC_5_9,
  FEC_7_9,
  FEC_8_15,
  FEC_11_15,
  FEC_13_18,
  FEC_9_20,
  FEC_11_20,
  FEC_23_36,
  FEC_25_36,
  FEC_13_45,
  FEC_26_45,
  FEC_28_45,
  FEC_32_45,
  FEC_77_90,
  FEC_11_45,
  FEC_4_15,
  FEC_14_45,
  FEC_7_15,
};
enum fe_modulation {
  QPSK,
  QAM_16,
  QAM_32,
  QAM_64,
  QAM_128,
  QAM_256,
  QAM_AUTO,
  VSB_8,
  VSB_16,
  PSK_8,
  APSK_16,
  APSK_32,
  DQPSK,
  QAM_4_NR,
  QAM_1024,
  QAM_4096,
  APSK_8_L,
  APSK_16_L,
  APSK_32_L,
  APSK_64,
  APSK_64_L,
};
enum fe_transmit_mode {
  TRANSMISSION_MODE_2K,
  TRANSMISSION_MODE_8K,
  TRANSMISSION_MODE_AUTO,
  TRANSMISSION_MODE_4K,
  TRANSMISSION_MODE_1K,
  TRANSMISSION_MODE_16K,
  TRANSMISSION_MODE_32K,
  TRANSMISSION_MODE_C1,
  TRANSMISSION_MODE_C3780,
};
enum fe_guard_interval {
  GUARD_INTERVAL_1_32,
  GUARD_INTERVAL_1_16,
  GUARD_INTERVAL_1_8,
  GUARD_INTERVAL_1_4,
  GUARD_INTERVAL_AUTO,
  GUARD_INTERVAL_1_128,
  GUARD_INTERVAL_19_128,
  GUARD_INTERVAL_19_256,
  GUARD_INTERVAL_PN420,
  GUARD_INTERVAL_PN595,
  GUARD_INTERVAL_PN945,
  GUARD_INTERVAL_1_64,
};
enum fe_hierarchy {
  HIERARCHY_NONE,
  HIERARCHY_1,
  HIERARCHY_2,
  HIERARCHY_4,
  HIERARCHY_AUTO
};
enum fe_interleaving {
  INTERLEAVING_NONE,
  INTERLEAVING_AUTO,
  INTERLEAVING_240,
  INTERLEAVING_720,
};
#define DTV_UNDEFINED 0
#define DTV_TUNE 1
#define DTV_CLEAR 2
#define DTV_FREQUENCY 3
#define DTV_MODULATION 4
#define DTV_BANDWIDTH_HZ 5
#define DTV_INVERSION 6
#define DTV_DISEQC_MASTER 7
#define DTV_SYMBOL_RATE 8
#define DTV_INNER_FEC 9
#define DTV_VOLTAGE 10
#define DTV_TONE 11
#define DTV_PILOT 12
#define DTV_ROLLOFF 13
#define DTV_DISEQC_SLAVE_REPLY 14
#define DTV_FE_CAPABILITY_COUNT 15
#define DTV_FE_CAPABILITY 16
#define DTV_DELIVERY_SYSTEM 17
#define DTV_ISDBT_PARTIAL_RECEPTION 18
#define DTV_ISDBT_SOUND_BROADCASTING 19
#define DTV_ISDBT_SB_SUBCHANNEL_ID 20
#define DTV_ISDBT_SB_SEGMENT_IDX 21
#define DTV_ISDBT_SB_SEGMENT_COUNT 22
#define DTV_ISDBT_LAYERA_FEC 23
#define DTV_ISDBT_LAYERA_MODULATION 24
#define DTV_ISDBT_LAYERA_SEGMENT_COUNT 25
#define DTV_ISDBT_LAYERA_TIME_INTERLEAVING 26
#define DTV_ISDBT_LAYERB_FEC 27
#define DTV_ISDBT_LAYERB_MODULATION 28
#define DTV_ISDBT_LAYERB_SEGMENT_COUNT 29
#define DTV_ISDBT_LAYERB_TIME_INTERLEAVING 30
#define DTV_ISDBT_LAYERC_FEC 31
#define DTV_ISDBT_LAYERC_MODULATION 32
#define DTV_ISDBT_LAYERC_SEGMENT_COUNT 33
#define DTV_ISDBT_LAYERC_TIME_INTERLEAVING 34
#define DTV_API_VERSION 35
#define DTV_CODE_RATE_HP 36
#define DTV_CODE_RATE_LP 37
#define DTV_GUARD_INTERVAL 38
#define DTV_TRANSMISSION_MODE 39
#define DTV_HIERARCHY 40
#define DTV_ISDBT_LAYER_ENABLED 41
#define DTV_STREAM_ID 42
#define DTV_ISDBS_TS_ID_LEGACY DTV_STREAM_ID
#define DTV_DVBT2_PLP_ID_LEGACY 43
#define DTV_ENUM_DELSYS 44
#define DTV_ATSCMH_FIC_VER 45
#define DTV_ATSCMH_PARADE_ID 46
#define DTV_ATSCMH_NOG 47
#define DTV_ATSCMH_TNOG 48
#define DTV_ATSCMH_SGN 49
#define DTV_ATSCMH_PRC 50
#define DTV_ATSCMH_RS_FRAME_MODE 51
#define DTV_ATSCMH_RS_FRAME_ENSEMBLE 52
#define DTV_ATSCMH_RS_CODE_MODE_PRI 53
#define DTV_ATSCMH_RS_CODE_MODE_SEC 54
#define DTV_ATSCMH_SCCC_BLOCK_MODE 55
#define DTV_ATSCMH_SCCC_CODE_MODE_A 56
#define DTV_ATSCMH_SCCC_CODE_MODE_B 57
#define DTV_ATSCMH_SCCC_CODE_MODE_C 58
#define DTV_ATSCMH_SCCC_CODE_MODE_D 59
#define DTV_INTERLEAVING 60
#define DTV_LNA 61
#define DTV_STAT_SIGNAL_STRENGTH 62
#define DTV_STAT_CNR 63
#define DTV_STAT_PRE_ERROR_BIT_COUNT 64
#define DTV_STAT_PRE_TOTAL_BIT_COUNT 65
#define DTV_STAT_POST_ERROR_BIT_COUNT 66
#define DTV_STAT_POST_TOTAL_BIT_COUNT 67
#define DTV_STAT_ERROR_BLOCK_COUNT 68
#define DTV_STAT_TOTAL_BLOCK_COUNT 69
#define DTV_SCRAMBLING_SEQUENCE_INDEX 70
#define DTV_MAX_COMMAND DTV_SCRAMBLING_SEQUENCE_INDEX
enum fe_pilot {
  PILOT_ON,
  PILOT_OFF,
  PILOT_AUTO,
};
enum fe_rolloff {
  ROLLOFF_35,
  ROLLOFF_20,
  ROLLOFF_25,
  ROLLOFF_AUTO,
  ROLLOFF_15,
  ROLLOFF_10,
  ROLLOFF_5,
};
enum fe_delivery_system {
  SYS_UNDEFINED,
  SYS_DVBC_ANNEX_A,
  SYS_DVBC_ANNEX_B,
  SYS_DVBT,
  SYS_DSS,
  SYS_DVBS,
  SYS_DVBS2,
  SYS_DVBH,
  SYS_ISDBT,
  SYS_ISDBS,
  SYS_ISDBC,
  SYS_ATSC,
  SYS_ATSCMH,
  SYS_DTMB,
  SYS_CMMB,
  SYS_DAB,
  SYS_DVBT2,
  SYS_TURBO,
  SYS_DVBC_ANNEX_C,
  SYS_DVBC2,
};
#define SYS_DVBC_ANNEX_AC SYS_DVBC_ANNEX_A
#define SYS_DMBTH SYS_DTMB
enum atscmh_sccc_block_mode {
  ATSCMH_SCCC_BLK_SEP = 0,
  ATSCMH_SCCC_BLK_COMB = 1,
  ATSCMH_SCCC_BLK_RES = 2,
};
enum atscmh_sccc_code_mode {
  ATSCMH_SCCC_CODE_HLF = 0,
  ATSCMH_SCCC_CODE_QTR = 1,
  ATSCMH_SCCC_CODE_RES = 2,
};
enum atscmh_rs_frame_ensemble {
  ATSCMH_RSFRAME_ENS_PRI = 0,
  ATSCMH_RSFRAME_ENS_SEC = 1,
};
enum atscmh_rs_frame_mode {
  ATSCMH_RSFRAME_PRI_ONLY = 0,
  ATSCMH_RSFRAME_PRI_SEC = 1,
  ATSCMH_RSFRAME_RES = 2,
};
enum atscmh_rs_code_mode {
  ATSCMH_RSCODE_211_187 = 0,
  ATSCMH_RSCODE_223_187 = 1,
  ATSCMH_RSCODE_235_187 = 2,
  ATSCMH_RSCODE_RES = 3,
};
#define NO_STREAM_ID_FILTER (~0U)
#define LNA_AUTO (~0U)
enum fecap_scale_params {
  FE_SCALE_NOT_AVAILABLE = 0,
  FE_SCALE_DECIBEL,
  FE_SCALE_RELATIVE,
  FE_SCALE_COUNTER
};
struct dtv_stats {
  __u8 scale;
  union {
    __u64 uvalue;
    __s64 svalue;
  } __attribute__((packed));
} __attribute__((packed));
#define MAX_DTV_STATS 4
struct dtv_fe_stats {
  __u8 len;
  struct dtv_stats stat[MAX_DTV_STATS];
} __attribute__((packed));
struct dtv_property {
  __u32 cmd;
  __u32 reserved[3];
  union {
    __u32 data;
    struct dtv_fe_stats st;
    struct {
      __u8 data[32];
      __u32 len;
      __u32 reserved1[3];
      void * reserved2;
    } buffer;
  } u;
  int result;
} __attribute__((packed));
#define DTV_IOCTL_MAX_MSGS 64
struct dtv_properties {
  __u32 num;
  struct dtv_property * props;
};
#define FE_TUNE_MODE_ONESHOT 0x01
#define FE_GET_INFO _IOR('o', 61, struct dvb_frontend_info)
#define FE_DISEQC_RESET_OVERLOAD _IO('o', 62)
#define FE_DISEQC_SEND_MASTER_CMD _IOW('o', 63, struct dvb_diseqc_master_cmd)
#define FE_DISEQC_RECV_SLAVE_REPLY _IOR('o', 64, struct dvb_diseqc_slave_reply)
#define FE_DISEQC_SEND_BURST _IO('o', 65)
#define FE_SET_TONE _IO('o', 66)
#define FE_SET_VOLTAGE _IO('o', 67)
#define FE_ENABLE_HIGH_LNB_VOLTAGE _IO('o', 68)
#define FE_READ_STATUS _IOR('o', 69, fe_status_t)
#define FE_READ_BER _IOR('o', 70, __u32)
#define FE_READ_SIGNAL_STRENGTH _IOR('o', 71, __u16)
#define FE_READ_SNR _IOR('o', 72, __u16)
#define FE_READ_UNCORRECTED_BLOCKS _IOR('o', 73, __u32)
#define FE_SET_FRONTEND_TUNE_MODE _IO('o', 81)
#define FE_GET_EVENT _IOR('o', 78, struct dvb_frontend_event)
#define FE_DISHNETWORK_SEND_LEGACY_CMD _IO('o', 80)
#define FE_SET_PROPERTY _IOW('o', 82, struct dtv_properties)
#define FE_GET_PROPERTY _IOR('o', 83, struct dtv_properties)
enum fe_bandwidth {
  BANDWIDTH_8_MHZ,
  BANDWIDTH_7_MHZ,
  BANDWIDTH_6_MHZ,
  BANDWIDTH_AUTO,
  BANDWIDTH_5_MHZ,
  BANDWIDTH_10_MHZ,
  BANDWIDTH_1_712_MHZ,
};
typedef enum fe_sec_voltage fe_sec_voltage_t;
typedef enum fe_caps fe_caps_t;
typedef enum fe_type fe_type_t;
typedef enum fe_sec_tone_mode fe_sec_tone_mode_t;
typedef enum fe_sec_mini_cmd fe_sec_mini_cmd_t;
typedef enum fe_status fe_status_t;
typedef enum fe_spectral_inversion fe_spectral_inversion_t;
typedef enum fe_code_rate fe_code_rate_t;
typedef enum fe_modulation fe_modulation_t;
typedef enum fe_transmit_mode fe_transmit_mode_t;
typedef enum fe_bandwidth fe_bandwidth_t;
typedef enum fe_guard_interval fe_guard_interval_t;
typedef enum fe_hierarchy fe_hierarchy_t;
typedef enum fe_pilot fe_pilot_t;
typedef enum fe_rolloff fe_rolloff_t;
typedef enum fe_delivery_system fe_delivery_system_t;
struct dvb_qpsk_parameters {
  __u32 symbol_rate;
  fe_code_rate_t fec_inner;
};
struct dvb_qam_parameters {
  __u32 symbol_rate;
  fe_code_rate_t fec_inner;
  fe_modulation_t modulation;
};
struct dvb_vsb_parameters {
  fe_modulation_t modulation;
};
struct dvb_ofdm_parameters {
  fe_bandwidth_t bandwidth;
  fe_code_rate_t code_rate_HP;
  fe_code_rate_t code_rate_LP;
  fe_modulation_t constellation;
  fe_transmit_mode_t transmission_mode;
  fe_guard_interval_t guard_interval;
  fe_hierarchy_t hierarchy_information;
};
struct dvb_frontend_parameters {
  __u32 frequency;
  fe_spectral_inversion_t inversion;
  union {
    struct dvb_qpsk_parameters qpsk;
    struct dvb_qam_parameters qam;
    struct dvb_ofdm_parameters ofdm;
    struct dvb_vsb_parameters vsb;
  } u;
};
struct dvb_frontend_event {
  fe_status_t status;
  struct dvb_frontend_parameters parameters;
};
#define FE_SET_FRONTEND _IOW('o', 76, struct dvb_frontend_parameters)
#define FE_GET_FRONTEND _IOR('o', 77, struct dvb_frontend_parameters)
#endif

"""

```