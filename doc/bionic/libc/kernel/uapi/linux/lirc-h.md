Response:
Let's break down the thought process for answering the request about the `lirc.h` file.

**1. Understanding the Request:**

The core request is to analyze the provided C header file (`lirc.h`) located in the Android Bionic library (`bionic/libc/kernel/uapi/linux/lirc.handroid`). The request asks for a comprehensive breakdown of its functionality, its relation to Android, implementation details (specifically for libc functions, which turns out to be a bit of a misdirection in this case), dynamic linker aspects, error handling examples, and how Android frameworks reach this level. It also asks for Frida hook examples.

**2. Initial Assessment of the File:**

The first thing to recognize is that this is a *header file*. Header files primarily define constants, macros, data structures, and function prototypes. They don't *implement* the actual logic. This is crucial for addressing the "implementation details of libc functions" part of the request. The file includes `<linux/types.h>` and `<linux/ioctl.h>`, indicating it's a low-level interface to the Linux kernel's LIRC (Linux Infrared Control) subsystem.

**3. Identifying Key Functionality Areas:**

Scanning the file, several key areas of functionality become apparent:

* **Constants Defining Pulse/Space:**  `PULSE_BIT`, `PULSE_MASK`, `LIRC_MODE2_SPACE`, `LIRC_MODE2_PULSE`, etc. clearly relate to representing infrared signals.
* **Macros for Manipulating Values:** `LIRC_SPACE`, `LIRC_PULSE`, `LIRC_VALUE`, `LIRC_MODE2`, `LIRC_IS_SPACE`, etc. provide ways to work with the encoded infrared data.
* **Mode Definitions:** `LIRC_MODE_RAW`, `LIRC_MODE_PULSE`, `LIRC_MODE_MODE2`, `LIRC_MODE_SCANCODE`, `LIRC_MODE_LIRCCODE` suggest different ways of interpreting or sending/receiving infrared signals.
* **Capability Flags:** `LIRC_CAN_SEND_RAW`, `LIRC_CAN_REC_MODE2`, `LIRC_CAN_SET_SEND_CARRIER`, etc. indicate what the underlying LIRC hardware and driver are capable of.
* **IOCTL Definitions:** `LIRC_GET_FEATURES`, `LIRC_SET_SEND_MODE`, etc. These are the interface points for user-space applications to interact with the LIRC kernel driver.
* **Data Structures:** `struct lirc_scancode` represents the decoded infrared input.
* **Enumerations:** `enum rc_proto` defines the different infrared protocols that might be encountered.

**4. Addressing Specific Parts of the Request:**

* **Functionality Listing:**  Based on the identified areas, listing the functionalities becomes straightforward: representing IR signals, defining operational modes, managing capabilities, providing IO control interfaces, defining data structures for communication, and specifying supported protocols.

* **Relationship to Android:**  Android devices with IR blasters use the LIRC subsystem. Examples include controlling TVs, air conditioners, etc. The `lirc.h` file provides the *interface* for Android to interact with the underlying hardware. Mentioning the `ConsumerIrManager` is a good way to connect this low-level header to a higher-level Android API.

* **Libc Function Implementation:** This is where the initial assessment is crucial. Since it's a header file, there are no *libc function implementations* here. The functions are defined in the kernel driver. The correct approach is to explain this distinction and point out that the header defines *constants and structures* used by libc when making system calls.

* **Dynamic Linker:**  This header file itself isn't directly involved in dynamic linking. It defines constants used in system calls. However, if a user-space library interacted with LIRC, *that* library would be linked. Therefore, providing a generic example of an SO layout and linking process is appropriate, even though this specific header isn't the focus of dynamic linking. It's important to clarify the distinction.

* **Logical Inference (Assumptions & Outputs):**  Focus on how the macros work. For instance, demonstrate how `LIRC_SPACE(100)` combines the value and the mode bit. Show the inverse operation with `LIRC_VALUE`.

* **Common Usage Errors:** Think about typical mistakes when dealing with hardware interfaces: incorrect permissions, wrong IOCTL commands, using unsupported modes, or misunderstanding the timing constraints of IR communication.

* **Android Framework/NDK Path and Frida Hook:** This requires tracing the path from the Android framework to the kernel. Start with the `ConsumerIrManager`, then explain the JNI bridge to native code (likely within the Android system server or a HAL implementation), and finally, the system calls that use the definitions in `lirc.h`. A Frida hook example should target a function that makes these IOCTL calls, demonstrating how to intercept the interaction.

**5. Structuring the Answer:**

Organize the answer logically, following the structure of the request. Use clear headings and bullet points to make it easy to read. Provide code examples where appropriate (like the Frida hook and the logical inference examples).

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe some of the inline macros are considered "libc functions."  **Correction:**  While they are part of the C code, they are expanded at compile time and don't involve separate function calls in the libc. The focus should be on the *system calls* that utilize these definitions.
* **Initial thought:** Dive deep into the LIRC driver implementation. **Correction:** The request is about the *header file*. Focus on what the header provides and how it's *used* by user-space programs and the Android framework. Avoid getting bogged down in kernel details unless directly relevant to understanding the header's purpose.
* **Consider the audience:** Assume the reader has some programming knowledge but might not be an expert in low-level Linux or Android internals. Explain concepts clearly and avoid overly technical jargon.

By following these steps and engaging in this kind of self-correction, a comprehensive and accurate answer to the request can be constructed.
好的，让我们来详细分析一下 `bionic/libc/kernel/uapi/linux/lirc.handroid` 这个头文件。

**功能列举:**

这个头文件定义了 Linux Infrared Control (LIRC) 子系统的用户空间应用程序接口。它主要包含以下功能：

1. **定义红外信号的表示方式:**
   - 定义了 `PULSE_BIT` 和 `PULSE_MASK` 用于区分红外信号的脉冲 (PULSE) 和间隔 (SPACE)。
   - 定义了 `LIRC_MODE2_SPACE` 和 `LIRC_MODE2_PULSE` 等常量，用于在 MODE2 模式下标记是脉冲还是间隔。
   - 定义了宏如 `LIRC_SPACE(val)` 和 `LIRC_PULSE(val)` 来方便地创建表示脉冲和间隔的值。

2. **定义 LIRC 的操作模式:**
   - 定义了不同的 LIRC 操作模式，例如 `LIRC_MODE_RAW` (原始模式)、`LIRC_MODE_PULSE` (脉冲模式)、`LIRC_MODE_MODE2` (MODE2 模式)、`LIRC_MODE_SCANCODE` (扫描码模式) 和 `LIRC_MODE_LIRCCODE` (LIRC 代码模式)。

3. **定义设备能力标志:**
   - 定义了 `LIRC_CAN_SEND_RAW`、`LIRC_CAN_REC_MODE2` 等宏，用于表示 LIRC 设备支持的发送和接收能力，以及可以设置的参数，例如载波频率 (`LIRC_CAN_SET_SEND_CARRIER`) 和占空比 (`LIRC_CAN_SET_SEND_DUTY_CYCLE`)。

4. **定义 ioctl 命令:**
   - 定义了一系列 `ioctl` 命令，用于用户空间程序与 LIRC 驱动程序进行交互，例如：
     - `LIRC_GET_FEATURES`: 获取设备支持的功能。
     - `LIRC_SET_SEND_MODE`: 设置发送模式。
     - `LIRC_GET_REC_MODE`: 获取接收模式。
     - `LIRC_SET_SEND_CARRIER`: 设置发送载波频率。
     - `LIRC_GET_REC_TIMEOUT`: 获取接收超时时间。
   - 这些 `ioctl` 命令使用宏 `_IOR` 和 `_IOW` 来定义，分别表示读操作和写操作。

5. **定义数据结构:**
   - 定义了 `struct lirc_scancode` 结构体，用于表示接收到的红外扫描码，包含时间戳、标志、协议类型、键码和扫描码等信息。

6. **定义红外协议枚举:**
   - 定义了 `enum rc_proto` 枚举类型，列举了常见的红外协议，例如 RC5、JVC、NEC 等。

**与 Android 功能的关系及举例说明:**

这个头文件直接关联到 Android 设备上的红外 (IR) 功能。如果 Android 设备配备了红外发射器或接收器，那么 Android Framework 或 NDK 应用程序就可以通过 LIRC 子系统来控制这些硬件。

**举例说明:**

* **遥控器功能:** Android 电视盒子或一些手机带有红外发射器，可以使用该接口来模拟遥控器，控制电视、空调等设备。例如，一个 Android 应用可以使用 `ioctl` 命令设置发送模式和发送的红外信号，从而模拟按下遥控器上的按钮。
* **红外接收功能:** 一些 Android 设备可能具备红外接收能力，可以用于某些特定的应用场景，例如接收特定的红外信号触发某些操作。

在 Android Framework 中，`android.hardware.ConsumerIrManager` 类提供了访问红外发射器的接口。虽然 `ConsumerIrManager` 本身并不直接使用 `lirc.h` 中定义的常量，但底层的硬件抽象层 (HAL) 或内核驱动程序会使用这些定义与 LIRC 子系统交互。

**libc 函数的功能实现:**

这个头文件本身**并不包含 libc 函数的实现**。它是一个定义了常量、宏和数据结构的头文件，用于用户空间程序与内核中的 LIRC 驱动程序进行交互。

用户空间程序（包括 Android Framework 的组件或 NDK 应用）会使用标准的 libc 函数，例如 `open()`, `close()`, `ioctl()` 等，来与 LIRC 设备进行交互。

* **`open()`:** 用于打开 LIRC 设备文件，通常是 `/dev/lirc0` 或类似的文件。
* **`ioctl()`:**  是与 LIRC 驱动程序通信的关键函数。应用程序通过 `ioctl()` 函数，并传入 `lirc.h` 中定义的命令（例如 `LIRC_SET_SEND_MODE`、`LIRC_GET_FEATURES`），以及相应的数据，来配置 LIRC 设备或获取设备状态。
* **`read()`/`write()`:**  在某些 LIRC 模式下，可以使用 `read()` 从设备读取接收到的红外信号，或者使用 `write()` 发送原始的红外脉冲/间隔序列。

**详细解释 `ioctl()` 的工作原理 (与 LIRC 相关):**

1. **用户空间调用 `ioctl()`:** 用户空间程序调用 `ioctl()` 函数，提供文件描述符（LIRC 设备文件）、`ioctl` 命令（`lirc.h` 中定义的常量），以及一个可选的指向数据的指针。
2. **系统调用:** `ioctl()` 是一个系统调用，会陷入内核。
3. **内核处理:** 内核接收到 `ioctl` 系统调用后，会根据文件描述符找到对应的设备驱动程序（LIRC 驱动程序）。
4. **驱动程序处理:** LIRC 驱动程序会根据传入的 `ioctl` 命令执行相应的操作。例如，如果命令是 `LIRC_SET_SEND_CARRIER`，驱动程序会设置红外发射器的载波频率。如果命令是 `LIRC_GET_FEATURES`，驱动程序会返回设备支持的功能信息。
5. **返回结果:**  驱动程序执行完毕后，会将结果返回给内核，内核再将结果返回给用户空间程序。

**涉及 dynamic linker 的功能:**

这个头文件本身不涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 到进程的内存空间，并解析和绑定符号。

然而，如果用户空间的库或应用程序使用了 LIRC 的功能，那么这些库或应用程序本身会由 dynamic linker 加载。

**so 布局样本:**

假设有一个名为 `liblirc_wrapper.so` 的共享库，它封装了对 LIRC 设备的访问。

```
liblirc_wrapper.so 的内存布局 (简化示例):

    .text   (代码段): 包含库的函数代码 (例如 open_lirc_device, send_ir_code, receive_ir_signal)
    .rodata (只读数据段): 包含常量字符串，例如 LIRC 设备路径 "/dev/lirc0"
    .data   (数据段): 包含全局变量和静态变量
    .bss    (未初始化数据段): 包含未初始化的全局变量和静态变量

```

**链接的处理过程:**

1. **编译时链接:** 当编译链接 `liblirc_wrapper.so` 时，链接器会记录下它需要的一些外部符号（例如 libc 中的 `open`, `ioctl` 等函数）。
2. **加载时链接:** 当应用程序启动并加载 `liblirc_wrapper.so` 时，dynamic linker 会：
   - 将 `liblirc_wrapper.so` 加载到进程的内存空间。
   - 遍历 `liblirc_wrapper.so` 的重定位表，找到需要解析的外部符号。
   - 在已加载的共享库（例如 `libc.so`）中查找这些符号的地址。
   - 将找到的地址填入 `liblirc_wrapper.so` 相应的代码位置，完成符号的绑定。

**假设输入与输出 (逻辑推理):**

假设我们使用 `ioctl` 设置 LIRC 的发送模式为 `LIRC_MODE_PULSE`：

**假设输入:**

* `fd`:  打开的 LIRC 设备文件描述符。
* `request`: `LIRC_SET_SEND_MODE` (0x00000011)。
* `argp`: 指向包含 `LIRC_MODE_PULSE` 值的 `__u32` 变量的指针。

**预期输出:**

* 如果 `ioctl` 调用成功，返回 0。
* LIRC 设备的发送模式被设置为脉冲模式。
* 后续的发送操作将以脉冲序列的方式进行。

**用户或编程常见的使用错误:**

1. **权限错误:** 用户没有足够的权限访问 LIRC 设备文件 (`/dev/lirc0`)。
   ```c
   // 错误示例：没有检查 open() 的返回值
   int fd = open("/dev/lirc0", O_RDWR);
   // 如果 open 失败 (例如权限不足)，fd 的值可能为 -1，后续操作会出错
   ioctl(fd, LIRC_SET_SEND_MODE, &mode);
   ```
   **正确做法:** 检查 `open()` 的返回值，并处理错误。

2. **使用错误的 ioctl 命令或参数:**  传递了错误的 `ioctl` 命令或参数类型不匹配。
   ```c
   // 错误示例：传递了错误的 ioctl 命令
   ioctl(fd, LIRC_GET_REC_MODE + 1, &mode); // 假设 LIRC_GET_REC_MODE + 1 是一个无效的命令
   ```
   **正确做法:** 仔细查阅文档，确保使用正确的 `ioctl` 命令和参数。

3. **未正确处理错误返回值:** `ioctl()` 调用失败时会返回 -1，并设置 `errno`。开发者需要检查返回值并根据 `errno` 进行错误处理。
   ```c
   int ret = ioctl(fd, LIRC_SET_SEND_MODE, &mode);
   if (ret == -1) {
       perror("ioctl LIRC_SET_SEND_MODE failed"); // 输出错误信息
       // 进行错误处理
   }
   ```

4. **尝试设置设备不支持的功能:** 例如，尝试设置载波频率，但设备不支持该功能。这会导致 `ioctl` 调用失败。

5. **竞争条件:**  多个进程或线程同时访问 LIRC 设备，可能导致冲突。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

**Android Framework 到 LIRC 的路径 (大致流程):**

1. **应用程序调用 `ConsumerIrManager`:**  Android 应用程序通过 `android.hardware.ConsumerIrManager` 类提供的高级 API 来控制红外发射器。
2. **Framework 调用 HIDL/AIDL 接口:** `ConsumerIrManager` 的方法会通过 HIDL (Hardware Interface Definition Language) 或 AIDL (Android Interface Definition Language) 与底层的硬件服务通信。
3. **HAL 实现:**  Android 的硬件抽象层 (HAL) 提供了硬件服务的具体实现。对于 IR 功能，可能会有一个 `android.hardware.ir@1.0.IService` 或类似的 HAL 接口。
4. **JNI 调用:**  Java 代码会通过 JNI (Java Native Interface) 调用到 HAL 层的 C/C++ 代码。
5. **HAL 代码使用系统调用:** HAL 的 C/C++ 代码会打开 LIRC 设备文件 (`/dev/lirc0`)，并使用 `ioctl()` 系统调用，传入 `lirc.h` 中定义的命令和参数，与 LIRC 驱动程序交互。
6. **内核驱动程序:** Linux 内核中的 LIRC 驱动程序接收到 `ioctl` 调用，并控制底层的红外硬件。

**NDK 到 LIRC 的路径:**

1. **NDK 应用直接使用系统调用:** NDK 应用程序可以直接使用 libc 提供的系统调用接口，例如 `open()`, `ioctl()`。
2. **包含 `lirc.h`:** NDK 应用需要包含 `lirc.h` 头文件以使用其中定义的常量和结构体。
3. **直接操作设备:** NDK 应用可以打开 `/dev/lirc0`，并使用 `ioctl()` 发送命令到 LIRC 驱动程序。

**Frida Hook 示例:**

假设我们想 hook HAL 层中调用 `ioctl` 与 LIRC 驱动交互的函数。

```python
import frida
import sys

# 目标进程，可能是 system_server 或一个 HAL 进程
process_name = "system_server"  # 或者具体的 HAL 进程名

try:
    session = frida.attach(process_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{process_name}' 未找到，请检查进程名。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 检查是否是与 LIRC 相关的 ioctl 调用 (可以通过设备文件名或其他特征判断)
        const pathbuf = Memory.allocUtf8String(256);
        const ret = syscall(frida. platform === 'linux' ? 'readlinkat' : 'readlink', parseInt(fd), pathbuf, 256);
        if (ret > 0) {
            const path = pathbuf.readUtf8String();
            if (path.startsWith("/dev/lirc")) {
                console.log("发现 LIRC ioctl 调用:");
                console.log("  文件描述符:", fd);
                console.log("  ioctl 命令:", request, "(" + request.toString(16) + ")");

                // 你可以进一步解析 request，判断是哪个 LIRC_XXX 命令
                // 例如：
                if (request === 0x00000011) { // LIRC_SET_SEND_MODE
                    console.log("  命令: LIRC_SET_SEND_MODE");
                    const modePtr = ptr(args[2]);
                    const mode = modePtr.readU32();
                    console.log("  发送模式:", mode);
                } else if (request === 0xc0046900) { // 假设 LIRC_GET_FEATURES 的值
                    console.log("  命令: LIRC_GET_FEATURES");
                }
                // ... 其他 LIRC 命令
            }
        }
    },
    onLeave: function(retval) {
        // console.log("ioctl 返回值:", retval);
    }
});
"""

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **Attach 到目标进程:**  使用 `frida.attach()` 连接到可能执行 LIRC 相关 `ioctl` 调用的进程，例如 `system_server` 或特定的 HAL 进程。
2. **Hook `ioctl` 函数:** 使用 `Interceptor.attach()` hook `libc.so` 中的 `ioctl` 函数。
3. **检查文件描述符:** 在 `onEnter` 中，获取 `ioctl` 的文件描述符参数，并通过 `readlink` 系统调用尝试获取文件路径，判断是否是与 `/dev/lirc*` 相关的调用。
4. **解析 `ioctl` 命令:** 获取 `ioctl` 的命令参数，并将其转换为十六进制和十进制输出。你可以根据 `lirc.h` 中定义的常量值，判断具体的 LIRC 命令。
5. **解析参数 (可选):** 对于某些 `ioctl` 命令，可以进一步解析其参数，例如 `LIRC_SET_SEND_MODE` 的参数是指向模式值的指针。
6. **输出信息:** 将捕获到的信息打印到控制台。

这个 Frida 脚本可以帮助你动态地观察 Android 系统中哪些进程在与 LIRC 设备进行交互，以及它们发送了哪些 `ioctl` 命令和参数。

希望以上详细的解答能够帮助你理解 `bionic/libc/kernel/uapi/linux/lirc.handroid` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/lirc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_LIRC_H
#define _LINUX_LIRC_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define PULSE_BIT 0x01000000
#define PULSE_MASK 0x00FFFFFF
#define LIRC_MODE2_SPACE 0x00000000
#define LIRC_MODE2_PULSE 0x01000000
#define LIRC_MODE2_FREQUENCY 0x02000000
#define LIRC_MODE2_TIMEOUT 0x03000000
#define LIRC_MODE2_OVERFLOW 0x04000000
#define LIRC_VALUE_MASK 0x00FFFFFF
#define LIRC_MODE2_MASK 0xFF000000
#define LIRC_SPACE(val) (((val) & LIRC_VALUE_MASK) | LIRC_MODE2_SPACE)
#define LIRC_PULSE(val) (((val) & LIRC_VALUE_MASK) | LIRC_MODE2_PULSE)
#define LIRC_FREQUENCY(val) (((val) & LIRC_VALUE_MASK) | LIRC_MODE2_FREQUENCY)
#define LIRC_TIMEOUT(val) (((val) & LIRC_VALUE_MASK) | LIRC_MODE2_TIMEOUT)
#define LIRC_OVERFLOW(val) (((val) & LIRC_VALUE_MASK) | LIRC_MODE2_OVERFLOW)
#define LIRC_VALUE(val) ((val) & LIRC_VALUE_MASK)
#define LIRC_MODE2(val) ((val) & LIRC_MODE2_MASK)
#define LIRC_IS_SPACE(val) (LIRC_MODE2(val) == LIRC_MODE2_SPACE)
#define LIRC_IS_PULSE(val) (LIRC_MODE2(val) == LIRC_MODE2_PULSE)
#define LIRC_IS_FREQUENCY(val) (LIRC_MODE2(val) == LIRC_MODE2_FREQUENCY)
#define LIRC_IS_TIMEOUT(val) (LIRC_MODE2(val) == LIRC_MODE2_TIMEOUT)
#define LIRC_IS_OVERFLOW(val) (LIRC_MODE2(val) == LIRC_MODE2_OVERFLOW)
#define lirc_t int
#define LIRC_MODE2SEND(x) (x)
#define LIRC_SEND2MODE(x) (x)
#define LIRC_MODE2REC(x) ((x) << 16)
#define LIRC_REC2MODE(x) ((x) >> 16)
#define LIRC_MODE_RAW 0x00000001
#define LIRC_MODE_PULSE 0x00000002
#define LIRC_MODE_MODE2 0x00000004
#define LIRC_MODE_SCANCODE 0x00000008
#define LIRC_MODE_LIRCCODE 0x00000010
#define LIRC_CAN_SEND_RAW LIRC_MODE2SEND(LIRC_MODE_RAW)
#define LIRC_CAN_SEND_PULSE LIRC_MODE2SEND(LIRC_MODE_PULSE)
#define LIRC_CAN_SEND_MODE2 LIRC_MODE2SEND(LIRC_MODE_MODE2)
#define LIRC_CAN_SEND_LIRCCODE LIRC_MODE2SEND(LIRC_MODE_LIRCCODE)
#define LIRC_CAN_SEND_MASK 0x0000003f
#define LIRC_CAN_SET_SEND_CARRIER 0x00000100
#define LIRC_CAN_SET_SEND_DUTY_CYCLE 0x00000200
#define LIRC_CAN_SET_TRANSMITTER_MASK 0x00000400
#define LIRC_CAN_REC_RAW LIRC_MODE2REC(LIRC_MODE_RAW)
#define LIRC_CAN_REC_PULSE LIRC_MODE2REC(LIRC_MODE_PULSE)
#define LIRC_CAN_REC_MODE2 LIRC_MODE2REC(LIRC_MODE_MODE2)
#define LIRC_CAN_REC_SCANCODE LIRC_MODE2REC(LIRC_MODE_SCANCODE)
#define LIRC_CAN_REC_LIRCCODE LIRC_MODE2REC(LIRC_MODE_LIRCCODE)
#define LIRC_CAN_REC_MASK LIRC_MODE2REC(LIRC_CAN_SEND_MASK)
#define LIRC_CAN_SET_REC_CARRIER (LIRC_CAN_SET_SEND_CARRIER << 16)
#define LIRC_CAN_SET_REC_CARRIER_RANGE 0x80000000
#define LIRC_CAN_GET_REC_RESOLUTION 0x20000000
#define LIRC_CAN_SET_REC_TIMEOUT 0x10000000
#define LIRC_CAN_MEASURE_CARRIER 0x02000000
#define LIRC_CAN_USE_WIDEBAND_RECEIVER 0x04000000
#define LIRC_CAN_SEND(x) ((x) & LIRC_CAN_SEND_MASK)
#define LIRC_CAN_REC(x) ((x) & LIRC_CAN_REC_MASK)
#define LIRC_CAN_SET_REC_FILTER 0
#define LIRC_CAN_NOTIFY_DECODE 0
#define LIRC_GET_FEATURES _IOR('i', 0x00000000, __u32)
#define LIRC_GET_SEND_MODE _IOR('i', 0x00000001, __u32)
#define LIRC_GET_REC_MODE _IOR('i', 0x00000002, __u32)
#define LIRC_GET_REC_RESOLUTION _IOR('i', 0x00000007, __u32)
#define LIRC_GET_MIN_TIMEOUT _IOR('i', 0x00000008, __u32)
#define LIRC_GET_MAX_TIMEOUT _IOR('i', 0x00000009, __u32)
#define LIRC_GET_LENGTH _IOR('i', 0x0000000f, __u32)
#define LIRC_SET_SEND_MODE _IOW('i', 0x00000011, __u32)
#define LIRC_SET_REC_MODE _IOW('i', 0x00000012, __u32)
#define LIRC_SET_SEND_CARRIER _IOW('i', 0x00000013, __u32)
#define LIRC_SET_REC_CARRIER _IOW('i', 0x00000014, __u32)
#define LIRC_SET_SEND_DUTY_CYCLE _IOW('i', 0x00000015, __u32)
#define LIRC_SET_TRANSMITTER_MASK _IOW('i', 0x00000017, __u32)
#define LIRC_SET_REC_TIMEOUT _IOW('i', 0x00000018, __u32)
#define LIRC_SET_REC_TIMEOUT_REPORTS _IOW('i', 0x00000019, __u32)
#define LIRC_SET_MEASURE_CARRIER_MODE _IOW('i', 0x0000001d, __u32)
#define LIRC_SET_REC_CARRIER_RANGE _IOW('i', 0x0000001f, __u32)
#define LIRC_SET_WIDEBAND_RECEIVER _IOW('i', 0x00000023, __u32)
#define LIRC_GET_REC_TIMEOUT _IOR('i', 0x00000024, __u32)
struct lirc_scancode {
  __u64 timestamp;
  __u16 flags;
  __u16 rc_proto;
  __u32 keycode;
  __u64 scancode;
};
#define LIRC_SCANCODE_FLAG_TOGGLE 1
#define LIRC_SCANCODE_FLAG_REPEAT 2
enum rc_proto {
  RC_PROTO_UNKNOWN = 0,
  RC_PROTO_OTHER = 1,
  RC_PROTO_RC5 = 2,
  RC_PROTO_RC5X_20 = 3,
  RC_PROTO_RC5_SZ = 4,
  RC_PROTO_JVC = 5,
  RC_PROTO_SONY12 = 6,
  RC_PROTO_SONY15 = 7,
  RC_PROTO_SONY20 = 8,
  RC_PROTO_NEC = 9,
  RC_PROTO_NECX = 10,
  RC_PROTO_NEC32 = 11,
  RC_PROTO_SANYO = 12,
  RC_PROTO_MCIR2_KBD = 13,
  RC_PROTO_MCIR2_MSE = 14,
  RC_PROTO_RC6_0 = 15,
  RC_PROTO_RC6_6A_20 = 16,
  RC_PROTO_RC6_6A_24 = 17,
  RC_PROTO_RC6_6A_32 = 18,
  RC_PROTO_RC6_MCE = 19,
  RC_PROTO_SHARP = 20,
  RC_PROTO_XMP = 21,
  RC_PROTO_CEC = 22,
  RC_PROTO_IMON = 23,
  RC_PROTO_RCMM12 = 24,
  RC_PROTO_RCMM24 = 25,
  RC_PROTO_RCMM32 = 26,
  RC_PROTO_XBOX_DVD = 27,
  RC_PROTO_MAX = RC_PROTO_XBOX_DVD,
};
#endif

"""

```