Response:
Let's break down the thought process for answering the request about `cec.handroid`.

1. **Understand the Core Request:** The user wants to know the functionality of the provided C header file (`cec.handroid`), its relationship to Android, details about libc functions, dynamic linker aspects, potential usage errors, and how Android frameworks/NDK interact with it. They also want Frida hook examples.

2. **Initial Analysis of the Header File:**
   - **Name:** `cec.handroid` strongly suggests it's related to Consumer Electronics Control (CEC) within Android. The `.handroid` suffix is a common convention for kernel UAPI headers copied into Android.
   - **`#ifndef _CEC_UAPI_H`:** This is a standard header guard, indicating this file defines an interface.
   - **Includes:** `<linux/types.h>` and `<linux/string.h>` point to standard Linux kernel types and string manipulation functions.
   - **`struct cec_msg`:** This is the central data structure, representing a CEC message. The members (`tx_ts`, `rx_ts`, `len`, `msg`, etc.) clearly relate to transmitting and receiving CEC data.
   - **Definitions (Macros and Enums):**  A large number of `#define` statements follow. These define constants and bit flags related to CEC messages, status codes, logical and physical addresses, device types, capabilities, and various CEC commands and operands. These are essentially the vocabulary of the CEC protocol.
   - **IOCTL definitions (`CEC_ADAP_G_CAPS`, `CEC_TRANSMIT`, etc.):**  These macros use `_IOWR`, `_IOR`, `_IOW`, indicating this header defines the interface for interacting with a CEC driver in the Linux kernel via ioctl calls.
   - **Message and Opcode Definitions (`CEC_MSG_ACTIVE_SOURCE`, `CEC_OP_PLAY_MODE_PLAY_FWD`, etc.):**  These further define the specific commands and parameters used in CEC communication.

3. **Identify Key Functionality:** Based on the header file's contents:
   - **CEC Messaging:** The core function is defining the structure and constants for sending and receiving CEC messages.
   - **Device Addressing:** It defines logical and physical addresses for CEC devices.
   - **Device Capabilities:** It describes how to represent the capabilities of CEC devices.
   - **Event Handling:**  It includes structures for reporting CEC-related events.
   - **IOCTL Interface:**  Crucially, it defines the ioctl codes used by user-space programs to interact with the CEC kernel driver.

4. **Relate to Android Functionality:**
   - **HDMI CEC:**  The most direct link is HDMI CEC functionality in Android. This allows Android devices to control and interact with other HDMI devices (TVs, Blu-ray players, etc.).
   - **Remote Control:** CEC enables using a single remote to control multiple devices.
   - **Auto Device Discovery:** CEC can facilitate automatic detection of connected devices.
   - **Power Management:** CEC can be used to turn devices on or off together.
   - **Input Switching:** CEC allows devices to automatically switch the TV's input.

5. **Address Specific Questions:**
   - **libc Functions:** The header itself *doesn't define* libc functions. It uses standard types (`__u64`, `__u32`, `__u8`) and includes standard headers. The *interaction* happens through system calls (via the ioctls), which are part of the C library's interface to the kernel. Therefore, the explanation focuses on `ioctl()`.
   - **Dynamic Linker:** This header file is a *kernel UAPI* header. It's used during compilation, but it's not directly linked by the dynamic linker at runtime. The dynamic linker is involved in loading libraries that *use* this interface (e.g., a HAL implementation). The explanation should clarify this distinction and provide an example of how a HAL might use the ioctls.
   - **Logic Reasoning:** The assumptions are based on how CEC generally works. Input: a CEC message to turn on a TV. Output: The TV turns on. This is a high-level illustration.
   - **Usage Errors:** Focus on common errors when interacting with device drivers via ioctl: incorrect file descriptors, invalid ioctl codes, and incorrect data structures.

6. **Android Framework/NDK Interaction:**
   - **Kernel Driver:** The starting point is the Linux kernel CEC driver.
   - **Hardware Abstraction Layer (HAL):**  A HAL implementation (likely in C++) will use the ioctls defined in this header to communicate with the kernel driver.
   - **Android Framework (Java/Kotlin):**  Higher-level Android framework APIs (likely in the `android.hardware.hdmi` package) provide a more abstract interface for applications. These APIs will communicate with the HAL through Binder.
   - **NDK:** NDK developers can potentially access the HAL or even interact directly with the `/dev/cecX` device nodes (though this is less common and generally discouraged for portability reasons).

7. **Frida Hook Examples:**  Provide concrete examples of how to use Frida to intercept calls at different layers:
   - **`ioctl`:**  Hooking the system call itself.
   - **HAL method:** Hooking a function within the CEC HAL implementation.
   - **Framework API:** Hooking a Java/Kotlin method in the `android.hardware.hdmi` package.

8. **Structure and Language:** Organize the information logically using clear headings and bullet points. Use precise and accurate language, explaining technical terms where necessary. Since the request was in Chinese, the response should also be in Chinese.

9. **Review and Refine:** After drafting the answer, review it to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas where the explanation could be improved. For example, ensure the distinction between kernel UAPI headers and runtime linking is clear. Make sure the Frida examples are practical and illustrate the concepts.

This detailed breakdown shows the step-by-step process of understanding the request, analyzing the input, identifying key information, connecting it to Android concepts, and structuring a comprehensive answer with relevant examples and explanations. It emphasizes understanding the different layers involved in the Android software stack, from the kernel up to the application framework.
这是一个定义了 Linux 内核中 Consumer Electronics Control (CEC) 用户空间 API 的头文件。CEC 允许 HDMI 设备互相通信，例如让电视遥控器控制机顶盒。由于这个文件位于 `bionic/libc/kernel/uapi/linux/cec.handroid`，它定义了 Android 系统中用户空间程序与 CEC 驱动交互的接口。

**功能列举:**

1. **定义 CEC 消息结构体 (`struct cec_msg`)**:  定义了 CEC 消息的格式，包括发送和接收时间戳、消息长度、超时时间、序列号、标志位、消息内容以及各种状态信息（例如，回复状态、接收/发送状态、仲裁丢失次数、NACK 计数等）。

2. **定义 CEC 消息标志位**:  例如 `CEC_MSG_FL_REPLY_TO_FOLLOWERS`、`CEC_MSG_FL_RAW` 等，用于指示消息的特定属性。

3. **定义 CEC 发送状态标志位**:  例如 `CEC_TX_STATUS_OK`、`CEC_TX_STATUS_ARB_LOST` 等，用于指示消息发送的结果。

4. **定义 CEC 接收状态标志位**:  例如 `CEC_RX_STATUS_OK`、`CEC_RX_STATUS_TIMEOUT` 等，用于指示消息接收的结果。

5. **定义 CEC 逻辑地址**:  例如 `CEC_LOG_ADDR_TV`、`CEC_LOG_ADDR_RECORD_1` 等，以及相关的掩码，用于标识 HDMI 网络中的设备类型。

6. **定义 CEC 供应商 ID 常量**:  例如 `CEC_VENDOR_ID_NONE`。

7. **定义 CEC 工作模式常量**:  例如 `CEC_MODE_INITIATOR`、`CEC_MODE_FOLLOWER` 等，以及相关的掩码，用于设置 CEC 适配器的工作模式。

8. **定义 CEC 功能常量**:  例如 `CEC_CAP_PHYS_ADDR`、`CEC_CAP_LOG_ADDRS` 等，用于描述 CEC 适配器的能力。

9. **定义 CEC 设备能力结构体 (`struct cec_caps`)**:  描述 CEC 适配器的驱动名称、设备名称、可用的逻辑地址、功能和版本。

10. **定义 CEC 逻辑地址信息结构体 (`struct cec_log_addrs`)**:  描述设备的逻辑地址、CEC 版本、供应商 ID、OSD 名称等信息。

11. **定义与 DRM 连接器相关的结构体 (`struct cec_drm_connector_info`) 和连接器信息结构体 (`struct cec_connector_info`)**:  用于将 CEC 适配器与 DRM (Direct Rendering Manager) 连接器关联起来。

12. **定义 CEC 事件类型和相关结构体 (`struct cec_event_state_change`, `struct cec_event_lost_msgs`, `struct cec_event`)**:  用于通知用户空间程序 CEC 状态变化、消息丢失等事件。

13. **定义 ioctl 命令宏**:  例如 `CEC_ADAP_G_CAPS`、`CEC_TRANSMIT`、`CEC_RECEIVE` 等，用户空间程序通过这些 ioctl 命令与内核中的 CEC 驱动进行交互。

14. **定义各种 CEC 消息操作码 (opcodes)**:  例如 `CEC_MSG_ACTIVE_SOURCE`、`CEC_MSG_STANDBY`、`CEC_MSG_USER_CONTROL_PRESSED` 等，以及与这些消息相关的操作数，用于实现各种 CEC 功能。

**与 Android 功能的关系及举例说明:**

这个头文件直接关系到 Android 设备上 **HDMI CEC (Consumer Electronics Control)** 的功能。HDMI CEC 允许连接到 Android 设备的 HDMI 设备（例如电视、Soundbar、蓝光播放器）进行双向通信。

**举例说明:**

* **遥控器控制 (One Touch Play/System Standby):**  用户可以使用电视的遥控器来控制 Android 机顶盒的播放或使其进入待机状态。Android 系统通过 CEC 驱动接收来自电视的 `CEC_MSG_USER_CONTROL_PRESSED` (例如，播放、暂停) 或 `CEC_MSG_STANDBY` 消息，并执行相应的操作。
* **自动设备发现和激活 (Active Source):** 当 Android 设备连接到电视时，它可以发送 `CEC_MSG_ACTIVE_SOURCE` 消息，告知电视它已激活，从而让电视自动切换到 Android 设备所在的 HDMI 输入源。
* **音频回传通道 (ARC - Audio Return Channel):**  Android 设备可以作为音频接收器，通过 HDMI ARC 从电视接收音频。这可能涉及到 `CEC_MSG_INITIATE_ARC` 和相关的消息。
* **电源控制 (Power Control):**  Android 设备可以发送 `CEC_MSG_STANDBY` 消息来关闭连接的电视，或者接收来自电视的 `CEC_MSG_ACTIVE_SOURCE` 消息来唤醒自身。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**没有定义 libc 函数**。它定义的是内核 UAPI，即用户空间程序与内核驱动交互的接口。用户空间程序需要使用 **libc 提供的系统调用**，例如 `ioctl()`，来与 CEC 驱动进行通信。

**`ioctl()` 函数的功能和实现:**

`ioctl()` (input/output control) 是一个系统调用，允许用户空间程序向设备驱动程序发送控制命令并传递数据。

**实现原理:**

1. **用户空间调用:** 用户空间的应用程序调用 `ioctl()` 函数，并传入以下参数：
   - **文件描述符 (fd):**  指向已打开的 CEC 设备文件（例如 `/dev/cec0`）。
   - **请求码 (request):**  一个整数值，指定要执行的操作。在这个头文件中，这些请求码由 `CEC_ADAP_G_CAPS`、`CEC_TRANSMIT` 等宏定义。这些宏通常使用 `_IO`, `_IOR`, `_IOW`, `_IOWR` 等宏来生成，编码了数据传输的方向和数据结构的大小。
   - **可选参数 (*argp):**  一个指向内存区域的指针，用于传递数据给驱动程序或从驱动程序接收数据。这个指针指向的结构体类型取决于 `request` 参数。例如，当 `request` 为 `CEC_TRANSMIT` 时，`argp` 指向 `struct cec_msg` 结构体，包含了要发送的 CEC 消息。

2. **内核处理:**
   - **系统调用入口:**  内核接收到 `ioctl()` 系统调用请求。
   - **查找设备驱动:** 内核根据文件描述符找到对应的 CEC 设备驱动程序。
   - **驱动程序处理:**  CEC 驱动程序中的 `ioctl` 函数会被调用，并接收到用户空间传递的 `request` 和 `argp` 参数。
   - **操作执行:** 驱动程序根据 `request` 值执行相应的操作。例如：
     - 如果 `request` 是 `CEC_ADAP_G_CAPS`，驱动程序会读取 CEC 适配器的硬件信息，填充 `struct cec_caps` 结构体，并将数据拷贝回用户空间。
     - 如果 `request` 是 `CEC_TRANSMIT`，驱动程序会从 `struct cec_msg` 结构体中提取 CEC 消息数据，并通过硬件接口发送出去。
     - 如果 `request` 是 `CEC_RECEIVE`，驱动程序会等待接收来自 HDMI 网络的 CEC 消息，并将接收到的消息填充到 `struct cec_msg` 结构体，然后拷贝回用户空间。
   - **返回结果:**  驱动程序将执行结果返回给内核，内核再将结果返回给用户空间的应用程序。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身**不直接涉及 dynamic linker**。它是一个用于编译时包含的头文件，定义了与内核交互的接口。

**但是，实现 CEC 功能的 Android 组件（例如，一个 HAL (Hardware Abstraction Layer) 库）会使用这个头文件中定义的接口，并且这些组件会被 dynamic linker 加载。**

**so 布局样本 (假设一个名为 `android.hardware.cec@1.0-impl.so` 的 HAL 实现库):**

```
android.hardware.cec@1.0-impl.so:
    .init          # 初始化段
    .plt           # 程序链接表 (Procedure Linkage Table) - 用于延迟绑定外部符号
    .text          # 代码段，包含实现 CEC HAL 接口的函数，这些函数会调用 ioctl()
    .rodata        # 只读数据段，可能包含一些常量
    .data          # 可写数据段，可能包含全局变量
    .bss           # 未初始化数据段
    .fini          # 终止段
    ...           # 其他段
```

**链接的处理过程:**

1. **编译时链接:**  当编译使用 CEC HAL 的上层组件时，编译器会找到 CEC HAL 的头文件（其中就包含 `cec.handroid`），并根据头文件中的定义生成调用 CEC HAL 接口的代码。

2. **运行时链接 (Dynamic Linking):**
   - **加载器 (loader):** 当 Android 系统需要使用 CEC 功能时，例如，一个 Framework 服务尝试调用 CEC HAL 接口，Android 的加载器（通常是 `/system/bin/linker64`）会负责加载 CEC HAL 的实现库 (`android.hardware.cec@1.0-impl.so`)。
   - **符号解析:** Dynamic linker 会解析 `android.hardware.cec@1.0-impl.so` 中未定义的符号，找到它们在其他已加载的共享库中的定义。例如，如果 HAL 库中使用了 `ioctl()` 函数，linker 会将其链接到 `libc.so` 中的 `ioctl()` 实现。
   - **重定位:** Linker 会修改加载的共享库的代码和数据段中的地址，使其适应当前的内存布局。
   - **延迟绑定 (Lazy Binding):**  为了提高启动速度，dynamic linker 通常使用延迟绑定。这意味着在第一次调用外部函数时才解析其地址。`.plt` 段就是用来实现延迟绑定的。当第一次调用 `ioctl()` 时，会跳转到 `.plt` 中的一个条目，该条目会调用 linker 来解析 `ioctl()` 的地址，并将解析后的地址写入 `.got.plt` (全局偏移量表)。后续对 `ioctl()` 的调用将直接通过 `.got.plt` 跳转到其实现。

**假设输入与输出 (逻辑推理，基于 ioctl 调用):**

**假设输入:**

* **用户空间程序:**  一个实现了 CEC 控制逻辑的 Android 应用程序或系统服务。
* **设备文件:**  已打开的 CEC 设备文件描述符 `fd`。
* **ioctl 调用:**  调用 `ioctl(fd, CEC_TRANSMIT, &msg)`，其中 `msg` 是一个 `struct cec_msg` 结构体，包含了要发送的 "请求设备电源状态" 的 CEC 消息。

```c
struct cec_msg msg;
memset(&msg, 0, sizeof(msg));
msg.len = 2;
msg.msg[0] = 0x0F; // 源地址 (广播)
msg.msg[1] = 0x8F; // GIVE_DEVICE_POWER_STATUS 消息
```

**预期输出:**

* **内核 CEC 驱动:**  接收到 `CEC_TRANSMIT` 命令和 CEC 消息数据。
* **HDMI 网络:**  驱动程序将 "Give Device Power Status" 的 CEC 消息发送到 HDMI 网络。
* **目标设备 (例如，电视):**  接收到消息后，目标设备会发送 "Report Power Status" 的 CEC 消息作为回应。
* **内核 CEC 驱动:**  接收到 "Report Power Status" 的 CEC 消息。
* **用户空间程序:**  可以通过调用 `ioctl(fd, CEC_RECEIVE, &reply_msg)` 来接收到包含电源状态的 `reply_msg`。`reply_msg.msg` 中将包含目标设备的电源状态信息 (例如，`0x90 0x00` 表示 "开机")。

**用户或者编程常见的使用错误举例说明:**

1. **文件描述符错误:**  在调用 `ioctl()` 之前，没有正确打开 CEC 设备文件 (`/dev/cecX`)，导致传入 `ioctl()` 的文件描述符无效。

   ```c
   int fd = open("/dev/cec0", O_RDWR);
   if (fd < 0) {
       perror("打开 CEC 设备失败");
       return -1;
   }
   struct cec_msg msg;
   // ... 填充 msg ...
   if (ioctl(fd, CEC_TRANSMIT, &msg) < 0) { // 如果 fd 无效，ioctl 会失败
       perror("发送 CEC 消息失败");
   }
   close(fd);
   ```

2. **ioctl 请求码错误:**  使用了未定义的或错误的 `ioctl` 请求码。

   ```c
   struct cec_msg msg;
   // ... 填充 msg ...
   // 错误的请求码
   if (ioctl(fd, 0x12345678, &msg) < 0) {
       perror("ioctl 调用失败");
   }
   ```

3. **传递的数据结构错误:**  传递给 `ioctl()` 的数据结构指针指向的内存区域大小或内容不正确，与 `ioctl` 请求码期望的结构体不匹配。

   ```c
   struct cec_msg msg;
   // 没有初始化 msg，或者初始化不完整
   if (ioctl(fd, CEC_TRANSMIT, &msg) < 0) {
       perror("发送 CEC 消息失败");
   }

   struct cec_caps caps;
   // 错误地使用 CEC_TRANSMIT 请求码来获取设备能力
   if (ioctl(fd, CEC_TRANSMIT, &caps) < 0) {
       perror("获取 CEC 能力失败");
   }
   ```

4. **权限问题:**  用户空间程序没有足够的权限访问 CEC 设备文件。

5. **竞态条件:**  在多线程环境中，多个线程同时尝试访问 CEC 设备，可能导致数据混乱或错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 CEC 驱动的步骤 (大致流程):**

1. **应用程序或 Framework 服务:**  Android 应用程序或 Framework 服务（例如，HDMI Control Service）需要执行 CEC 相关操作。

2. **Android Framework API:**  Framework 服务会使用 Android 提供的 HDMI Control API (通常位于 `android.hardware.hdmi` 包下)。这些 API 提供了更高级的抽象，隐藏了底层的细节。

3. **HDMI Control Service (Java/Kotlin):**  Framework API 的实现通常在 `com.android.server.hdmi` 包下的 HDMI Control Service 中。这个 Service 负责管理 HDMI 连接和 CEC 通信。

4. **JNI 调用:**  HDMI Control Service 需要与 Native 层进行交互，通常会通过 JNI (Java Native Interface) 调用 Native 代码。

5. **HAL (Hardware Abstraction Layer):**  Native 代码会调用 HIDL (HAL Interface Definition Language) 定义的 CEC HAL 接口。例如，`android.hardware.cec@1.0` 或更高版本。HAL 接口定义了与硬件交互的标准方法。

6. **HAL 实现 (C++):**  具体的 HAL 实现库（例如，`android.hardware.cec@1.0-impl.so`）会实现 HIDL 接口中定义的函数。这些函数会调用底层的系统调用 `ioctl()`。

7. **Kernel CEC Driver:**  HAL 实现库中的代码会打开 CEC 设备文件（例如 `/dev/cec0`），并使用 `ioctl()` 系统调用，传入 `cec.handroid` 头文件中定义的请求码和数据结构，与内核中的 CEC 驱动程序进行通信。

8. **硬件 CEC 适配器:**  内核 CEC 驱动程序会将 CEC 消息通过硬件接口发送到 HDMI 网络，并接收来自 HDMI 网络的 CEC 消息。

**NDK 到达 CEC 驱动的步骤:**

使用 NDK 开发的应用程序可以直接调用 Native 代码，绕过部分 Framework 层。

1. **NDK 应用程序 (C/C++):**  NDK 应用程序可以直接使用 C/C++ 代码。

2. **直接调用 `ioctl()`:**  NDK 应用程序可以直接打开 CEC 设备文件 (`/dev/cec0`)，并包含 `cec.handroid` 头文件，然后调用 `ioctl()` 系统调用与内核 CEC 驱动进行交互。

**Frida Hook 示例:**

以下是一些使用 Frida Hook 拦截不同层次 CEC 交互的示例：

**1. Hook `ioctl` 系统调用 (拦截所有 CEC 相关的 ioctl):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
process = device.attach(pid)
device.resume(pid)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        if (request >= 0x6100 && request <= 0x610a) { // CEC ioctl 请求码范围 (需要根据实际情况调整)
            console.log("[*] ioctl called");
            console.log("    fd:", fd);
            console.log("    request:", request, " (0x" + request.toString(16) + ")");

            // 可以进一步解析 argp 指向的数据
            if (request === 0x6105) { // CEC_TRANSMIT
                const cec_msg_ptr = ptr(argp);
                const len = cec_msg_ptr.add(8).readU32();
                const msg_ptr = cec_msg_ptr.add(20);
                const msg_data = msg_ptr.readByteArray(len);
                console.log("    CEC Message:", hexdump(msg_data));
            }
        }
    },
    onLeave: function(retval) {
        // console.log("ioctl returned:", retval);
    }
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**2. Hook CEC HAL 实现库中的函数 (例如，发送 CEC 消息的函数):**

需要先找到 HAL 库的路径和要 Hook 的函数名。可以使用 `adb shell dumpsys media.audio_flinger` 或其他方式来定位。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
process = device.attach(pid)
device.resume(pid)

script_code = """
const cecHalModule = Process.getModuleByName("android.hardware.cec@1.0-impl.so"); // 替换为实际的 HAL 库名
const sendCecMessageAddr = cecHalModule.getExportByName("_ZN..."); // 替换为实际的发送 CEC 消息的函数符号

if (sendCecMessageAddr) {
    Interceptor.attach(sendCecMessageAddr, {
        onEnter: function(args) {
            console.log("[*] sendCecMessage called");
            // 根据函数签名解析参数
            // const cecMessagePtr = args[...];
            // ...
        },
        onLeave: function(retval) {
            console.log("[*] sendCecMessage returned:", retval);
        }
    });
} else {
    console.log("[!] sendCecMessage function not found in HAL module.");
}
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**3. Hook Android Framework 中 HDMI Control Service 的 Java 方法:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(["com.android.tv.settings"]) # 例如 Hook 电视设置应用
process = device.attach(pid)
device.resume(pid)

script_code = """
Java.perform(function() {
    const HdmiControlService = Java.use("com.android.server.hdmi.HdmiControlService"); // 或其他相关类
    HdmiControlService.sendCecCommand.overload('int', 'int', '[B').implementation = function(logicalAddress, opcode, params) {
        console.log("[*] HdmiControlService.sendCecCommand called");
        console.log("    Logical Address:", logicalAddress);
        console.log("    Opcode:", opcode);
        console.log("    Parameters:", params);
        return this.sendCecCommand.overload('int', 'int', '[B').call(this, logicalAddress, opcode, params);
    };
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**请注意:**

* Frida Hook 需要 Root 权限或在可调试的应用上进行。
* 具体的 HAL 库名称、函数符号和 Framework 类名可能因 Android 版本和设备而异，需要根据实际情况进行调整。
* 解析 `ioctl` 和 HAL 函数的参数需要了解其函数签名和数据结构。

这些 Frida Hook 示例可以帮助你调试 Android 设备上 CEC 功能的各个环节，理解数据是如何从 Framework 层一步步传递到内核驱动的。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/cec.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _CEC_UAPI_H
#define _CEC_UAPI_H
#include <linux/types.h>
#include <linux/string.h>
#define CEC_MAX_MSG_SIZE 16
struct cec_msg {
  __u64 tx_ts;
  __u64 rx_ts;
  __u32 len;
  __u32 timeout;
  __u32 sequence;
  __u32 flags;
  __u8 msg[CEC_MAX_MSG_SIZE];
  __u8 reply;
  __u8 rx_status;
  __u8 tx_status;
  __u8 tx_arb_lost_cnt;
  __u8 tx_nack_cnt;
  __u8 tx_low_drive_cnt;
  __u8 tx_error_cnt;
};
#define CEC_MSG_FL_REPLY_TO_FOLLOWERS (1 << 0)
#define CEC_MSG_FL_RAW (1 << 1)
#define CEC_MSG_FL_REPLY_VENDOR_ID (1 << 2)
#define CEC_TX_STATUS_OK (1 << 0)
#define CEC_TX_STATUS_ARB_LOST (1 << 1)
#define CEC_TX_STATUS_NACK (1 << 2)
#define CEC_TX_STATUS_LOW_DRIVE (1 << 3)
#define CEC_TX_STATUS_ERROR (1 << 4)
#define CEC_TX_STATUS_MAX_RETRIES (1 << 5)
#define CEC_TX_STATUS_ABORTED (1 << 6)
#define CEC_TX_STATUS_TIMEOUT (1 << 7)
#define CEC_RX_STATUS_OK (1 << 0)
#define CEC_RX_STATUS_TIMEOUT (1 << 1)
#define CEC_RX_STATUS_FEATURE_ABORT (1 << 2)
#define CEC_RX_STATUS_ABORTED (1 << 3)
#define CEC_LOG_ADDR_INVALID 0xff
#define CEC_PHYS_ADDR_INVALID 0xffff
#define CEC_MAX_LOG_ADDRS 4
#define CEC_LOG_ADDR_TV 0
#define CEC_LOG_ADDR_RECORD_1 1
#define CEC_LOG_ADDR_RECORD_2 2
#define CEC_LOG_ADDR_TUNER_1 3
#define CEC_LOG_ADDR_PLAYBACK_1 4
#define CEC_LOG_ADDR_AUDIOSYSTEM 5
#define CEC_LOG_ADDR_TUNER_2 6
#define CEC_LOG_ADDR_TUNER_3 7
#define CEC_LOG_ADDR_PLAYBACK_2 8
#define CEC_LOG_ADDR_RECORD_3 9
#define CEC_LOG_ADDR_TUNER_4 10
#define CEC_LOG_ADDR_PLAYBACK_3 11
#define CEC_LOG_ADDR_BACKUP_1 12
#define CEC_LOG_ADDR_BACKUP_2 13
#define CEC_LOG_ADDR_SPECIFIC 14
#define CEC_LOG_ADDR_UNREGISTERED 15
#define CEC_LOG_ADDR_BROADCAST 15
#define CEC_LOG_ADDR_TYPE_TV 0
#define CEC_LOG_ADDR_TYPE_RECORD 1
#define CEC_LOG_ADDR_TYPE_TUNER 2
#define CEC_LOG_ADDR_TYPE_PLAYBACK 3
#define CEC_LOG_ADDR_TYPE_AUDIOSYSTEM 4
#define CEC_LOG_ADDR_TYPE_SPECIFIC 5
#define CEC_LOG_ADDR_TYPE_UNREGISTERED 6
#define CEC_LOG_ADDR_MASK_TV (1 << CEC_LOG_ADDR_TV)
#define CEC_LOG_ADDR_MASK_RECORD ((1 << CEC_LOG_ADDR_RECORD_1) | (1 << CEC_LOG_ADDR_RECORD_2) | (1 << CEC_LOG_ADDR_RECORD_3))
#define CEC_LOG_ADDR_MASK_TUNER ((1 << CEC_LOG_ADDR_TUNER_1) | (1 << CEC_LOG_ADDR_TUNER_2) | (1 << CEC_LOG_ADDR_TUNER_3) | (1 << CEC_LOG_ADDR_TUNER_4))
#define CEC_LOG_ADDR_MASK_PLAYBACK ((1 << CEC_LOG_ADDR_PLAYBACK_1) | (1 << CEC_LOG_ADDR_PLAYBACK_2) | (1 << CEC_LOG_ADDR_PLAYBACK_3))
#define CEC_LOG_ADDR_MASK_AUDIOSYSTEM (1 << CEC_LOG_ADDR_AUDIOSYSTEM)
#define CEC_LOG_ADDR_MASK_BACKUP ((1 << CEC_LOG_ADDR_BACKUP_1) | (1 << CEC_LOG_ADDR_BACKUP_2))
#define CEC_LOG_ADDR_MASK_SPECIFIC (1 << CEC_LOG_ADDR_SPECIFIC)
#define CEC_LOG_ADDR_MASK_UNREGISTERED (1 << CEC_LOG_ADDR_UNREGISTERED)
#define CEC_VENDOR_ID_NONE 0xffffffff
#define CEC_MODE_NO_INITIATOR (0x0 << 0)
#define CEC_MODE_INITIATOR (0x1 << 0)
#define CEC_MODE_EXCL_INITIATOR (0x2 << 0)
#define CEC_MODE_INITIATOR_MSK 0x0f
#define CEC_MODE_NO_FOLLOWER (0x0 << 4)
#define CEC_MODE_FOLLOWER (0x1 << 4)
#define CEC_MODE_EXCL_FOLLOWER (0x2 << 4)
#define CEC_MODE_EXCL_FOLLOWER_PASSTHRU (0x3 << 4)
#define CEC_MODE_MONITOR_PIN (0xd << 4)
#define CEC_MODE_MONITOR (0xe << 4)
#define CEC_MODE_MONITOR_ALL (0xf << 4)
#define CEC_MODE_FOLLOWER_MSK 0xf0
#define CEC_CAP_PHYS_ADDR (1 << 0)
#define CEC_CAP_LOG_ADDRS (1 << 1)
#define CEC_CAP_TRANSMIT (1 << 2)
#define CEC_CAP_PASSTHROUGH (1 << 3)
#define CEC_CAP_RC (1 << 4)
#define CEC_CAP_MONITOR_ALL (1 << 5)
#define CEC_CAP_NEEDS_HPD (1 << 6)
#define CEC_CAP_MONITOR_PIN (1 << 7)
#define CEC_CAP_CONNECTOR_INFO (1 << 8)
#define CEC_CAP_REPLY_VENDOR_ID (1 << 9)
struct cec_caps {
  char driver[32];
  char name[32];
  __u32 available_log_addrs;
  __u32 capabilities;
  __u32 version;
};
struct cec_log_addrs {
  __u8 log_addr[CEC_MAX_LOG_ADDRS];
  __u16 log_addr_mask;
  __u8 cec_version;
  __u8 num_log_addrs;
  __u32 vendor_id;
  __u32 flags;
  char osd_name[15];
  __u8 primary_device_type[CEC_MAX_LOG_ADDRS];
  __u8 log_addr_type[CEC_MAX_LOG_ADDRS];
  __u8 all_device_types[CEC_MAX_LOG_ADDRS];
  __u8 features[CEC_MAX_LOG_ADDRS][12];
};
#define CEC_LOG_ADDRS_FL_ALLOW_UNREG_FALLBACK (1 << 0)
#define CEC_LOG_ADDRS_FL_ALLOW_RC_PASSTHRU (1 << 1)
#define CEC_LOG_ADDRS_FL_CDC_ONLY (1 << 2)
struct cec_drm_connector_info {
  __u32 card_no;
  __u32 connector_id;
};
#define CEC_CONNECTOR_TYPE_NO_CONNECTOR 0
#define CEC_CONNECTOR_TYPE_DRM 1
struct cec_connector_info {
  __u32 type;
  union {
    struct cec_drm_connector_info drm;
    __u32 raw[16];
  };
};
#define CEC_EVENT_STATE_CHANGE 1
#define CEC_EVENT_LOST_MSGS 2
#define CEC_EVENT_PIN_CEC_LOW 3
#define CEC_EVENT_PIN_CEC_HIGH 4
#define CEC_EVENT_PIN_HPD_LOW 5
#define CEC_EVENT_PIN_HPD_HIGH 6
#define CEC_EVENT_PIN_5V_LOW 7
#define CEC_EVENT_PIN_5V_HIGH 8
#define CEC_EVENT_FL_INITIAL_STATE (1 << 0)
#define CEC_EVENT_FL_DROPPED_EVENTS (1 << 1)
struct cec_event_state_change {
  __u16 phys_addr;
  __u16 log_addr_mask;
  __u16 have_conn_info;
};
struct cec_event_lost_msgs {
  __u32 lost_msgs;
};
struct cec_event {
  __u64 ts;
  __u32 event;
  __u32 flags;
  union {
    struct cec_event_state_change state_change;
    struct cec_event_lost_msgs lost_msgs;
    __u32 raw[16];
  };
};
#define CEC_ADAP_G_CAPS _IOWR('a', 0, struct cec_caps)
#define CEC_ADAP_G_PHYS_ADDR _IOR('a', 1, __u16)
#define CEC_ADAP_S_PHYS_ADDR _IOW('a', 2, __u16)
#define CEC_ADAP_G_LOG_ADDRS _IOR('a', 3, struct cec_log_addrs)
#define CEC_ADAP_S_LOG_ADDRS _IOWR('a', 4, struct cec_log_addrs)
#define CEC_TRANSMIT _IOWR('a', 5, struct cec_msg)
#define CEC_RECEIVE _IOWR('a', 6, struct cec_msg)
#define CEC_DQEVENT _IOWR('a', 7, struct cec_event)
#define CEC_G_MODE _IOR('a', 8, __u32)
#define CEC_S_MODE _IOW('a', 9, __u32)
#define CEC_ADAP_G_CONNECTOR_INFO _IOR('a', 10, struct cec_connector_info)
#define CEC_MSG_ACTIVE_SOURCE 0x82
#define CEC_MSG_IMAGE_VIEW_ON 0x04
#define CEC_MSG_TEXT_VIEW_ON 0x0d
#define CEC_MSG_INACTIVE_SOURCE 0x9d
#define CEC_MSG_REQUEST_ACTIVE_SOURCE 0x85
#define CEC_MSG_ROUTING_CHANGE 0x80
#define CEC_MSG_ROUTING_INFORMATION 0x81
#define CEC_MSG_SET_STREAM_PATH 0x86
#define CEC_MSG_STANDBY 0x36
#define CEC_MSG_RECORD_OFF 0x0b
#define CEC_MSG_RECORD_ON 0x09
#define CEC_OP_RECORD_SRC_OWN 1
#define CEC_OP_RECORD_SRC_DIGITAL 2
#define CEC_OP_RECORD_SRC_ANALOG 3
#define CEC_OP_RECORD_SRC_EXT_PLUG 4
#define CEC_OP_RECORD_SRC_EXT_PHYS_ADDR 5
#define CEC_OP_SERVICE_ID_METHOD_BY_DIG_ID 0
#define CEC_OP_SERVICE_ID_METHOD_BY_CHANNEL 1
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_ARIB_GEN 0x00
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_ATSC_GEN 0x01
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_DVB_GEN 0x02
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_ARIB_BS 0x08
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_ARIB_CS 0x09
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_ARIB_T 0x0a
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_ATSC_CABLE 0x10
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_ATSC_SAT 0x11
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_ATSC_T 0x12
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_DVB_C 0x18
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_DVB_S 0x19
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_DVB_S2 0x1a
#define CEC_OP_DIG_SERVICE_BCAST_SYSTEM_DVB_T 0x1b
#define CEC_OP_ANA_BCAST_TYPE_CABLE 0
#define CEC_OP_ANA_BCAST_TYPE_SATELLITE 1
#define CEC_OP_ANA_BCAST_TYPE_TERRESTRIAL 2
#define CEC_OP_BCAST_SYSTEM_PAL_BG 0x00
#define CEC_OP_BCAST_SYSTEM_SECAM_LQ 0x01
#define CEC_OP_BCAST_SYSTEM_PAL_M 0x02
#define CEC_OP_BCAST_SYSTEM_NTSC_M 0x03
#define CEC_OP_BCAST_SYSTEM_PAL_I 0x04
#define CEC_OP_BCAST_SYSTEM_SECAM_DK 0x05
#define CEC_OP_BCAST_SYSTEM_SECAM_BG 0x06
#define CEC_OP_BCAST_SYSTEM_SECAM_L 0x07
#define CEC_OP_BCAST_SYSTEM_PAL_DK 0x08
#define CEC_OP_BCAST_SYSTEM_OTHER 0x1f
#define CEC_OP_CHANNEL_NUMBER_FMT_1_PART 0x01
#define CEC_OP_CHANNEL_NUMBER_FMT_2_PART 0x02
#define CEC_MSG_RECORD_STATUS 0x0a
#define CEC_OP_RECORD_STATUS_CUR_SRC 0x01
#define CEC_OP_RECORD_STATUS_DIG_SERVICE 0x02
#define CEC_OP_RECORD_STATUS_ANA_SERVICE 0x03
#define CEC_OP_RECORD_STATUS_EXT_INPUT 0x04
#define CEC_OP_RECORD_STATUS_NO_DIG_SERVICE 0x05
#define CEC_OP_RECORD_STATUS_NO_ANA_SERVICE 0x06
#define CEC_OP_RECORD_STATUS_NO_SERVICE 0x07
#define CEC_OP_RECORD_STATUS_INVALID_EXT_PLUG 0x09
#define CEC_OP_RECORD_STATUS_INVALID_EXT_PHYS_ADDR 0x0a
#define CEC_OP_RECORD_STATUS_UNSUP_CA 0x0b
#define CEC_OP_RECORD_STATUS_NO_CA_ENTITLEMENTS 0x0c
#define CEC_OP_RECORD_STATUS_CANT_COPY_SRC 0x0d
#define CEC_OP_RECORD_STATUS_NO_MORE_COPIES 0x0e
#define CEC_OP_RECORD_STATUS_NO_MEDIA 0x10
#define CEC_OP_RECORD_STATUS_PLAYING 0x11
#define CEC_OP_RECORD_STATUS_ALREADY_RECORDING 0x12
#define CEC_OP_RECORD_STATUS_MEDIA_PROT 0x13
#define CEC_OP_RECORD_STATUS_NO_SIGNAL 0x14
#define CEC_OP_RECORD_STATUS_MEDIA_PROBLEM 0x15
#define CEC_OP_RECORD_STATUS_NO_SPACE 0x16
#define CEC_OP_RECORD_STATUS_PARENTAL_LOCK 0x17
#define CEC_OP_RECORD_STATUS_TERMINATED_OK 0x1a
#define CEC_OP_RECORD_STATUS_ALREADY_TERM 0x1b
#define CEC_OP_RECORD_STATUS_OTHER 0x1f
#define CEC_MSG_RECORD_TV_SCREEN 0x0f
#define CEC_MSG_CLEAR_ANALOGUE_TIMER 0x33
#define CEC_OP_REC_SEQ_SUNDAY 0x01
#define CEC_OP_REC_SEQ_MONDAY 0x02
#define CEC_OP_REC_SEQ_TUESDAY 0x04
#define CEC_OP_REC_SEQ_WEDNESDAY 0x08
#define CEC_OP_REC_SEQ_THURSDAY 0x10
#define CEC_OP_REC_SEQ_FRIDAY 0x20
#define CEC_OP_REC_SEQ_SATURDAY 0x40
#define CEC_OP_REC_SEQ_ONCE_ONLY 0x00
#define CEC_MSG_CLEAR_DIGITAL_TIMER 0x99
#define CEC_MSG_CLEAR_EXT_TIMER 0xa1
#define CEC_OP_EXT_SRC_PLUG 0x04
#define CEC_OP_EXT_SRC_PHYS_ADDR 0x05
#define CEC_MSG_SET_ANALOGUE_TIMER 0x34
#define CEC_MSG_SET_DIGITAL_TIMER 0x97
#define CEC_MSG_SET_EXT_TIMER 0xa2
#define CEC_MSG_SET_TIMER_PROGRAM_TITLE 0x67
#define CEC_MSG_TIMER_CLEARED_STATUS 0x43
#define CEC_OP_TIMER_CLR_STAT_RECORDING 0x00
#define CEC_OP_TIMER_CLR_STAT_NO_MATCHING 0x01
#define CEC_OP_TIMER_CLR_STAT_NO_INFO 0x02
#define CEC_OP_TIMER_CLR_STAT_CLEARED 0x80
#define CEC_MSG_TIMER_STATUS 0x35
#define CEC_OP_TIMER_OVERLAP_WARNING_NO_OVERLAP 0
#define CEC_OP_TIMER_OVERLAP_WARNING_OVERLAP 1
#define CEC_OP_MEDIA_INFO_UNPROT_MEDIA 0
#define CEC_OP_MEDIA_INFO_PROT_MEDIA 1
#define CEC_OP_MEDIA_INFO_NO_MEDIA 2
#define CEC_OP_PROG_IND_NOT_PROGRAMMED 0
#define CEC_OP_PROG_IND_PROGRAMMED 1
#define CEC_OP_PROG_INFO_ENOUGH_SPACE 0x08
#define CEC_OP_PROG_INFO_NOT_ENOUGH_SPACE 0x09
#define CEC_OP_PROG_INFO_MIGHT_NOT_BE_ENOUGH_SPACE 0x0b
#define CEC_OP_PROG_INFO_NONE_AVAILABLE 0x0a
#define CEC_OP_PROG_ERROR_NO_FREE_TIMER 0x01
#define CEC_OP_PROG_ERROR_DATE_OUT_OF_RANGE 0x02
#define CEC_OP_PROG_ERROR_REC_SEQ_ERROR 0x03
#define CEC_OP_PROG_ERROR_INV_EXT_PLUG 0x04
#define CEC_OP_PROG_ERROR_INV_EXT_PHYS_ADDR 0x05
#define CEC_OP_PROG_ERROR_CA_UNSUPP 0x06
#define CEC_OP_PROG_ERROR_INSUF_CA_ENTITLEMENTS 0x07
#define CEC_OP_PROG_ERROR_RESOLUTION_UNSUPP 0x08
#define CEC_OP_PROG_ERROR_PARENTAL_LOCK 0x09
#define CEC_OP_PROG_ERROR_CLOCK_FAILURE 0x0a
#define CEC_OP_PROG_ERROR_DUPLICATE 0x0e
#define CEC_MSG_CEC_VERSION 0x9e
#define CEC_OP_CEC_VERSION_1_3A 4
#define CEC_OP_CEC_VERSION_1_4 5
#define CEC_OP_CEC_VERSION_2_0 6
#define CEC_MSG_GET_CEC_VERSION 0x9f
#define CEC_MSG_GIVE_PHYSICAL_ADDR 0x83
#define CEC_MSG_GET_MENU_LANGUAGE 0x91
#define CEC_MSG_REPORT_PHYSICAL_ADDR 0x84
#define CEC_OP_PRIM_DEVTYPE_TV 0
#define CEC_OP_PRIM_DEVTYPE_RECORD 1
#define CEC_OP_PRIM_DEVTYPE_TUNER 3
#define CEC_OP_PRIM_DEVTYPE_PLAYBACK 4
#define CEC_OP_PRIM_DEVTYPE_AUDIOSYSTEM 5
#define CEC_OP_PRIM_DEVTYPE_SWITCH 6
#define CEC_OP_PRIM_DEVTYPE_PROCESSOR 7
#define CEC_MSG_SET_MENU_LANGUAGE 0x32
#define CEC_MSG_REPORT_FEATURES 0xa6
#define CEC_OP_ALL_DEVTYPE_TV 0x80
#define CEC_OP_ALL_DEVTYPE_RECORD 0x40
#define CEC_OP_ALL_DEVTYPE_TUNER 0x20
#define CEC_OP_ALL_DEVTYPE_PLAYBACK 0x10
#define CEC_OP_ALL_DEVTYPE_AUDIOSYSTEM 0x08
#define CEC_OP_ALL_DEVTYPE_SWITCH 0x04
#define CEC_OP_FEAT_EXT 0x80
#define CEC_OP_FEAT_RC_TV_PROFILE_NONE 0x00
#define CEC_OP_FEAT_RC_TV_PROFILE_1 0x02
#define CEC_OP_FEAT_RC_TV_PROFILE_2 0x06
#define CEC_OP_FEAT_RC_TV_PROFILE_3 0x0a
#define CEC_OP_FEAT_RC_TV_PROFILE_4 0x0e
#define CEC_OP_FEAT_RC_SRC_HAS_DEV_ROOT_MENU 0x50
#define CEC_OP_FEAT_RC_SRC_HAS_DEV_SETUP_MENU 0x48
#define CEC_OP_FEAT_RC_SRC_HAS_CONTENTS_MENU 0x44
#define CEC_OP_FEAT_RC_SRC_HAS_MEDIA_TOP_MENU 0x42
#define CEC_OP_FEAT_RC_SRC_HAS_MEDIA_CONTEXT_MENU 0x41
#define CEC_OP_FEAT_DEV_HAS_RECORD_TV_SCREEN 0x40
#define CEC_OP_FEAT_DEV_HAS_SET_OSD_STRING 0x20
#define CEC_OP_FEAT_DEV_HAS_DECK_CONTROL 0x10
#define CEC_OP_FEAT_DEV_HAS_SET_AUDIO_RATE 0x08
#define CEC_OP_FEAT_DEV_SINK_HAS_ARC_TX 0x04
#define CEC_OP_FEAT_DEV_SOURCE_HAS_ARC_RX 0x02
#define CEC_OP_FEAT_DEV_HAS_SET_AUDIO_VOLUME_LEVEL 0x01
#define CEC_MSG_GIVE_FEATURES 0xa5
#define CEC_MSG_DECK_CONTROL 0x42
#define CEC_OP_DECK_CTL_MODE_SKIP_FWD 1
#define CEC_OP_DECK_CTL_MODE_SKIP_REV 2
#define CEC_OP_DECK_CTL_MODE_STOP 3
#define CEC_OP_DECK_CTL_MODE_EJECT 4
#define CEC_MSG_DECK_STATUS 0x1b
#define CEC_OP_DECK_INFO_PLAY 0x11
#define CEC_OP_DECK_INFO_RECORD 0x12
#define CEC_OP_DECK_INFO_PLAY_REV 0x13
#define CEC_OP_DECK_INFO_STILL 0x14
#define CEC_OP_DECK_INFO_SLOW 0x15
#define CEC_OP_DECK_INFO_SLOW_REV 0x16
#define CEC_OP_DECK_INFO_FAST_FWD 0x17
#define CEC_OP_DECK_INFO_FAST_REV 0x18
#define CEC_OP_DECK_INFO_NO_MEDIA 0x19
#define CEC_OP_DECK_INFO_STOP 0x1a
#define CEC_OP_DECK_INFO_SKIP_FWD 0x1b
#define CEC_OP_DECK_INFO_SKIP_REV 0x1c
#define CEC_OP_DECK_INFO_INDEX_SEARCH_FWD 0x1d
#define CEC_OP_DECK_INFO_INDEX_SEARCH_REV 0x1e
#define CEC_OP_DECK_INFO_OTHER 0x1f
#define CEC_MSG_GIVE_DECK_STATUS 0x1a
#define CEC_OP_STATUS_REQ_ON 1
#define CEC_OP_STATUS_REQ_OFF 2
#define CEC_OP_STATUS_REQ_ONCE 3
#define CEC_MSG_PLAY 0x41
#define CEC_OP_PLAY_MODE_PLAY_FWD 0x24
#define CEC_OP_PLAY_MODE_PLAY_REV 0x20
#define CEC_OP_PLAY_MODE_PLAY_STILL 0x25
#define CEC_OP_PLAY_MODE_PLAY_FAST_FWD_MIN 0x05
#define CEC_OP_PLAY_MODE_PLAY_FAST_FWD_MED 0x06
#define CEC_OP_PLAY_MODE_PLAY_FAST_FWD_MAX 0x07
#define CEC_OP_PLAY_MODE_PLAY_FAST_REV_MIN 0x09
#define CEC_OP_PLAY_MODE_PLAY_FAST_REV_MED 0x0a
#define CEC_OP_PLAY_MODE_PLAY_FAST_REV_MAX 0x0b
#define CEC_OP_PLAY_MODE_PLAY_SLOW_FWD_MIN 0x15
#define CEC_OP_PLAY_MODE_PLAY_SLOW_FWD_MED 0x16
#define CEC_OP_PLAY_MODE_PLAY_SLOW_FWD_MAX 0x17
#define CEC_OP_PLAY_MODE_PLAY_SLOW_REV_MIN 0x19
#define CEC_OP_PLAY_MODE_PLAY_SLOW_REV_MED 0x1a
#define CEC_OP_PLAY_MODE_PLAY_SLOW_REV_MAX 0x1b
#define CEC_MSG_GIVE_TUNER_DEVICE_STATUS 0x08
#define CEC_MSG_SELECT_ANALOGUE_SERVICE 0x92
#define CEC_MSG_SELECT_DIGITAL_SERVICE 0x93
#define CEC_MSG_TUNER_DEVICE_STATUS 0x07
#define CEC_OP_REC_FLAG_NOT_USED 0
#define CEC_OP_REC_FLAG_USED 1
#define CEC_OP_TUNER_DISPLAY_INFO_DIGITAL 0
#define CEC_OP_TUNER_DISPLAY_INFO_NONE 1
#define CEC_OP_TUNER_DISPLAY_INFO_ANALOGUE 2
#define CEC_MSG_TUNER_STEP_DECREMENT 0x06
#define CEC_MSG_TUNER_STEP_INCREMENT 0x05
#define CEC_MSG_DEVICE_VENDOR_ID 0x87
#define CEC_MSG_GIVE_DEVICE_VENDOR_ID 0x8c
#define CEC_MSG_VENDOR_COMMAND 0x89
#define CEC_MSG_VENDOR_COMMAND_WITH_ID 0xa0
#define CEC_MSG_VENDOR_REMOTE_BUTTON_DOWN 0x8a
#define CEC_MSG_VENDOR_REMOTE_BUTTON_UP 0x8b
#define CEC_MSG_SET_OSD_STRING 0x64
#define CEC_OP_DISP_CTL_DEFAULT 0x00
#define CEC_OP_DISP_CTL_UNTIL_CLEARED 0x40
#define CEC_OP_DISP_CTL_CLEAR 0x80
#define CEC_MSG_GIVE_OSD_NAME 0x46
#define CEC_MSG_SET_OSD_NAME 0x47
#define CEC_MSG_MENU_REQUEST 0x8d
#define CEC_OP_MENU_REQUEST_ACTIVATE 0x00
#define CEC_OP_MENU_REQUEST_DEACTIVATE 0x01
#define CEC_OP_MENU_REQUEST_QUERY 0x02
#define CEC_MSG_MENU_STATUS 0x8e
#define CEC_OP_MENU_STATE_ACTIVATED 0x00
#define CEC_OP_MENU_STATE_DEACTIVATED 0x01
#define CEC_MSG_USER_CONTROL_PRESSED 0x44
#define CEC_OP_UI_CMD_SELECT 0x00
#define CEC_OP_UI_CMD_UP 0x01
#define CEC_OP_UI_CMD_DOWN 0x02
#define CEC_OP_UI_CMD_LEFT 0x03
#define CEC_OP_UI_CMD_RIGHT 0x04
#define CEC_OP_UI_CMD_RIGHT_UP 0x05
#define CEC_OP_UI_CMD_RIGHT_DOWN 0x06
#define CEC_OP_UI_CMD_LEFT_UP 0x07
#define CEC_OP_UI_CMD_LEFT_DOWN 0x08
#define CEC_OP_UI_CMD_DEVICE_ROOT_MENU 0x09
#define CEC_OP_UI_CMD_DEVICE_SETUP_MENU 0x0a
#define CEC_OP_UI_CMD_CONTENTS_MENU 0x0b
#define CEC_OP_UI_CMD_FAVORITE_MENU 0x0c
#define CEC_OP_UI_CMD_BACK 0x0d
#define CEC_OP_UI_CMD_MEDIA_TOP_MENU 0x10
#define CEC_OP_UI_CMD_MEDIA_CONTEXT_SENSITIVE_MENU 0x11
#define CEC_OP_UI_CMD_NUMBER_ENTRY_MODE 0x1d
#define CEC_OP_UI_CMD_NUMBER_11 0x1e
#define CEC_OP_UI_CMD_NUMBER_12 0x1f
#define CEC_OP_UI_CMD_NUMBER_0_OR_NUMBER_10 0x20
#define CEC_OP_UI_CMD_NUMBER_1 0x21
#define CEC_OP_UI_CMD_NUMBER_2 0x22
#define CEC_OP_UI_CMD_NUMBER_3 0x23
#define CEC_OP_UI_CMD_NUMBER_4 0x24
#define CEC_OP_UI_CMD_NUMBER_5 0x25
#define CEC_OP_UI_CMD_NUMBER_6 0x26
#define CEC_OP_UI_CMD_NUMBER_7 0x27
#define CEC_OP_UI_CMD_NUMBER_8 0x28
#define CEC_OP_UI_CMD_NUMBER_9 0x29
#define CEC_OP_UI_CMD_DOT 0x2a
#define CEC_OP_UI_CMD_ENTER 0x2b
#define CEC_OP_UI_CMD_CLEAR 0x2c
#define CEC_OP_UI_CMD_NEXT_FAVORITE 0x2f
#define CEC_OP_UI_CMD_CHANNEL_UP 0x30
#define CEC_OP_UI_CMD_CHANNEL_DOWN 0x31
#define CEC_OP_UI_CMD_PREVIOUS_CHANNEL 0x32
#define CEC_OP_UI_CMD_SOUND_SELECT 0x33
#define CEC_OP_UI_CMD_INPUT_SELECT 0x34
#define CEC_OP_UI_CMD_DISPLAY_INFORMATION 0x35
#define CEC_OP_UI_CMD_HELP 0x36
#define CEC_OP_UI_CMD_PAGE_UP 0x37
#define CEC_OP_UI_CMD_PAGE_DOWN 0x38
#define CEC_OP_UI_CMD_POWER 0x40
#define CEC_OP_UI_CMD_VOLUME_UP 0x41
#define CEC_OP_UI_CMD_VOLUME_DOWN 0x42
#define CEC_OP_UI_CMD_MUTE 0x43
#define CEC_OP_UI_CMD_PLAY 0x44
#define CEC_OP_UI_CMD_STOP 0x45
#define CEC_OP_UI_CMD_PAUSE 0x46
#define CEC_OP_UI_CMD_RECORD 0x47
#define CEC_OP_UI_CMD_REWIND 0x48
#define CEC_OP_UI_CMD_FAST_FORWARD 0x49
#define CEC_OP_UI_CMD_EJECT 0x4a
#define CEC_OP_UI_CMD_SKIP_FORWARD 0x4b
#define CEC_OP_UI_CMD_SKIP_BACKWARD 0x4c
#define CEC_OP_UI_CMD_STOP_RECORD 0x4d
#define CEC_OP_UI_CMD_PAUSE_RECORD 0x4e
#define CEC_OP_UI_CMD_ANGLE 0x50
#define CEC_OP_UI_CMD_SUB_PICTURE 0x51
#define CEC_OP_UI_CMD_VIDEO_ON_DEMAND 0x52
#define CEC_OP_UI_CMD_ELECTRONIC_PROGRAM_GUIDE 0x53
#define CEC_OP_UI_CMD_TIMER_PROGRAMMING 0x54
#define CEC_OP_UI_CMD_INITIAL_CONFIGURATION 0x55
#define CEC_OP_UI_CMD_SELECT_BROADCAST_TYPE 0x56
#define CEC_OP_UI_CMD_SELECT_SOUND_PRESENTATION 0x57
#define CEC_OP_UI_CMD_AUDIO_DESCRIPTION 0x58
#define CEC_OP_UI_CMD_INTERNET 0x59
#define CEC_OP_UI_CMD_3D_MODE 0x5a
#define CEC_OP_UI_CMD_PLAY_FUNCTION 0x60
#define CEC_OP_UI_CMD_PAUSE_PLAY_FUNCTION 0x61
#define CEC_OP_UI_CMD_RECORD_FUNCTION 0x62
#define CEC_OP_UI_CMD_PAUSE_RECORD_FUNCTION 0x63
#define CEC_OP_UI_CMD_STOP_FUNCTION 0x64
#define CEC_OP_UI_CMD_MUTE_FUNCTION 0x65
#define CEC_OP_UI_CMD_RESTORE_VOLUME_FUNCTION 0x66
#define CEC_OP_UI_CMD_TUNE_FUNCTION 0x67
#define CEC_OP_UI_CMD_SELECT_MEDIA_FUNCTION 0x68
#define CEC_OP_UI_CMD_SELECT_AV_INPUT_FUNCTION 0x69
#define CEC_OP_UI_CMD_SELECT_AUDIO_INPUT_FUNCTION 0x6a
#define CEC_OP_UI_CMD_POWER_TOGGLE_FUNCTION 0x6b
#define CEC_OP_UI_CMD_POWER_OFF_FUNCTION 0x6c
#define CEC_OP_UI_CMD_POWER_ON_FUNCTION 0x6d
#define CEC_OP_UI_CMD_F1_BLUE 0x71
#define CEC_OP_UI_CMD_F2_RED 0x72
#define CEC_OP_UI_CMD_F3_GREEN 0x73
#define CEC_OP_UI_CMD_F4_YELLOW 0x74
#define CEC_OP_UI_CMD_F5 0x75
#define CEC_OP_UI_CMD_DATA 0x76
#define CEC_OP_UI_BCAST_TYPE_TOGGLE_ALL 0x00
#define CEC_OP_UI_BCAST_TYPE_TOGGLE_DIG_ANA 0x01
#define CEC_OP_UI_BCAST_TYPE_ANALOGUE 0x10
#define CEC_OP_UI_BCAST_TYPE_ANALOGUE_T 0x20
#define CEC_OP_UI_BCAST_TYPE_ANALOGUE_CABLE 0x30
#define CEC_OP_UI_BCAST_TYPE_ANALOGUE_SAT 0x40
#define CEC_OP_UI_BCAST_TYPE_DIGITAL 0x50
#define CEC_OP_UI_BCAST_TYPE_DIGITAL_T 0x60
#define CEC_OP_UI_BCAST_TYPE_DIGITAL_CABLE 0x70
#define CEC_OP_UI_BCAST_TYPE_DIGITAL_SAT 0x80
#define CEC_OP_UI_BCAST_TYPE_DIGITAL_COM_SAT 0x90
#define CEC_OP_UI_BCAST_TYPE_DIGITAL_COM_SAT2 0x91
#define CEC_OP_UI_BCAST_TYPE_IP 0xa0
#define CEC_OP_UI_SND_PRES_CTL_DUAL_MONO 0x10
#define CEC_OP_UI_SND_PRES_CTL_KARAOKE 0x20
#define CEC_OP_UI_SND_PRES_CTL_DOWNMIX 0x80
#define CEC_OP_UI_SND_PRES_CTL_REVERB 0x90
#define CEC_OP_UI_SND_PRES_CTL_EQUALIZER 0xa0
#define CEC_OP_UI_SND_PRES_CTL_BASS_UP 0xb1
#define CEC_OP_UI_SND_PRES_CTL_BASS_NEUTRAL 0xb2
#define CEC_OP_UI_SND_PRES_CTL_BASS_DOWN 0xb3
#define CEC_OP_UI_SND_PRES_CTL_TREBLE_UP 0xc1
#define CEC_OP_UI_SND_PRES_CTL_TREBLE_NEUTRAL 0xc2
#define CEC_OP_UI_SND_PRES_CTL_TREBLE_DOWN 0xc3
#define CEC_MSG_USER_CONTROL_RELEASED 0x45
#define CEC_MSG_GIVE_DEVICE_POWER_STATUS 0x8f
#define CEC_MSG_REPORT_POWER_STATUS 0x90
#define CEC_OP_POWER_STATUS_ON 0
#define CEC_OP_POWER_STATUS_STANDBY 1
#define CEC_OP_POWER_STATUS_TO_ON 2
#define CEC_OP_POWER_STATUS_TO_STANDBY 3
#define CEC_MSG_FEATURE_ABORT 0x00
#define CEC_OP_ABORT_UNRECOGNIZED_OP 0
#define CEC_OP_ABORT_INCORRECT_MODE 1
#define CEC_OP_ABORT_NO_SOURCE 2
#define CEC_OP_ABORT_INVALID_OP 3
#define CEC_OP_ABORT_REFUSED 4
#define CEC_OP_ABORT_UNDETERMINED 5
#define CEC_MSG_ABORT 0xff
#define CEC_MSG_GIVE_AUDIO_STATUS 0x71
#define CEC_MSG_GIVE_SYSTEM_AUDIO_MODE_STATUS 0x7d
#define CEC_MSG_REPORT_AUDIO_STATUS 0x7a
#define CEC_OP_AUD_MUTE_STATUS_OFF 0
#define CEC_OP_AUD_MUTE_STATUS_ON 1
#define CEC_MSG_REPORT_SHORT_AUDIO_DESCRIPTOR 0xa3
#define CEC_MSG_REQUEST_SHORT_AUDIO_DESCRIPTOR 0xa4
#define CEC_MSG_SET_SYSTEM_AUDIO_MODE 0x72
#define CEC_OP_SYS_AUD_STATUS_OFF 0
#define CEC_OP_SYS_AUD_STATUS_ON 1
#define CEC_MSG_SYSTEM_AUDIO_MODE_REQUEST 0x70
#define CEC_MSG_SYSTEM_AUDIO_MODE_STATUS 0x7e
#define CEC_OP_AUD_FMT_ID_CEA861 0
#define CEC_OP_AUD_FMT_ID_CEA861_CXT 1
#define CEC_MSG_SET_AUDIO_VOLUME_LEVEL 0x73
#define CEC_MSG_SET_AUDIO_RATE 0x9a
#define CEC_OP_AUD_RATE_OFF 0
#define CEC_OP_AUD_RATE_WIDE_STD 1
#define CEC_OP_AUD_RATE_WIDE_FAST 2
#define CEC_OP_AUD_RATE_WIDE_SLOW 3
#define CEC_OP_AUD_RATE_NARROW_STD 4
#define CEC_OP_AUD_RATE_NARROW_FAST 5
#define CEC_OP_AUD_RATE_NARROW_SLOW 6
#define CEC_MSG_INITIATE_ARC 0xc0
#define CEC_MSG_REPORT_ARC_INITIATED 0xc1
#define CEC_MSG_REPORT_ARC_TERMINATED 0xc2
#define CEC_MSG_REQUEST_ARC_INITIATION 0xc3
#define CEC_MSG_REQUEST_ARC_TERMINATION 0xc4
#define CEC_MSG_TERMINATE_ARC 0xc5
#define CEC_MSG_REQUEST_CURRENT_LATENCY 0xa7
#define CEC_MSG_REPORT_CURRENT_LATENCY 0xa8
#define CEC_OP_LOW_LATENCY_MODE_OFF 0
#define CEC_OP_LOW_LATENCY_MODE_ON 1
#define CEC_OP_AUD_OUT_COMPENSATED_NA 0
#define CEC_OP_AUD_OUT_COMPENSATED_DELAY 1
#define CEC_OP_AUD_OUT_COMPENSATED_NO_DELAY 2
#define CEC_OP_AUD_OUT_COMPENSATED_PARTIAL_DELAY 3
#define CEC_MSG_CDC_MESSAGE 0xf8
#define CEC_MSG_CDC_HEC_INQUIRE_STATE 0x00
#define CEC_MSG_CDC_HEC_REPORT_STATE 0x01
#define CEC_OP_HEC_FUNC_STATE_NOT_SUPPORTED 0
#define CEC_OP_HEC_FUNC_STATE_INACTIVE 1
#define CEC_OP_HEC_FUNC_STATE_ACTIVE 2
#define CEC_OP_HEC_FUNC_STATE_ACTIVATION_FIELD 3
#define CEC_OP_HOST_FUNC_STATE_NOT_SUPPORTED 0
#define CEC_OP_HOST_FUNC_STATE_INACTIVE 1
#define CEC_OP_HOST_FUNC_STATE_ACTIVE 2
#define CEC_OP_ENC_FUNC_STATE_EXT_CON_NOT_SUPPORTED 0
#define CEC_OP_ENC_FUNC_STATE_EXT_CON_INACTIVE 1
#define CEC_OP_ENC_FUNC_STATE_EXT_CON_ACTIVE 2
#define CEC_OP_CDC_ERROR_CODE_NONE 0
#define CEC_OP_CDC_ERROR_CODE_CAP_UNSUPPORTED 1
#define CEC_OP_CDC_ERROR_CODE_WRONG_STATE 2
#define CEC_OP_CDC_ERROR_CODE_OTHER 3
#define CEC_OP_HEC_SUPPORT_NO 0
#define CEC_OP_HEC_SUPPORT_YES 1
#define CEC_OP_HEC_ACTIVATION_ON 0
#define CEC_OP_HEC_ACTIVATION_OFF 1
#define CEC_MSG_CDC_HEC_SET_STATE_ADJACENT 0x02
#define CEC_MSG_CDC_HEC_SET_STATE 0x03
#define CEC_OP_HEC_SET_STATE_DEACTIVATE 0
#define CEC_OP_HEC_SET_STATE_ACTIVATE 1
#define CEC_MSG_CDC_HEC_REQUEST_DEACTIVATION 0x04
#define CEC_MSG_CDC_HEC_NOTIFY_ALIVE 0x05
#define CEC_MSG_CDC_HEC_DISCOVER 0x06
#define CEC_MSG_CDC_HPD_SET_STATE 0x10
#define CEC_OP_HPD_STATE_CP_EDID_DISABLE 0
#define CEC_OP_HPD_STATE_CP_EDID_ENABLE 1
#define CEC_OP_HPD_STATE_CP_EDID_DISABLE_ENABLE 2
#define CEC_OP_HPD_STATE_EDID_DISABLE 3
#define CEC_OP_HPD_STATE_EDID_ENABLE 4
#define CEC_OP_HPD_STATE_EDID_DISABLE_ENABLE 5
#define CEC_MSG_CDC_HPD_REPORT_STATE 0x11
#define CEC_OP_HPD_ERROR_NONE 0
#define CEC_OP_HPD_ERROR_INITIATOR_NOT_CAPABLE 1
#define CEC_OP_HPD_ERROR_INITIATOR_WRONG_STATE 2
#define CEC_OP_HPD_ERROR_OTHER 3
#define CEC_OP_HPD_ERROR_NONE_NO_VIDEO 4
#endif
```