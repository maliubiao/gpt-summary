Response:
Let's break down the thought process for answering the user's request about `tty_flags.h`.

**1. Understanding the Core Request:**

The user provides a header file (`tty_flags.h`) from the Android bionic library. They want to understand its purpose, how it relates to Android, and any relevant implementation details, potential issues, and debugging methods. Crucially, they are asking for explanations of *libc functions* and *dynamic linker* aspects, which seems like a slight misinterpretation of the file's content.

**2. Initial Analysis of the File:**

The first thing I notice is that the file consists almost entirely of `#define` preprocessor directives. These define constants (macros). The names of the constants (`ASYNCB_...` and `ASYNC_...`) strongly suggest they are related to asynchronous serial communication (TTY). The comments at the beginning confirm it's auto-generated and related to the Linux kernel.

**3. Addressing the "libc Function" Misconception:**

A critical step is recognizing that this header file *doesn't contain any libc function implementations*. It only defines constants. Therefore, directly explaining the implementation of libc functions within this specific file is impossible. I need to address this discrepancy politely and informatively. I can mention that the *use* of these flags might occur within libc functions related to terminal I/O.

**4. Identifying the Purpose and Functionality:**

The core functionality is defining flags for configuring TTY (teletypewriter, referring to terminal devices). The names themselves provide good clues:

* `ASYNCB_HUP_NOTIFY`: Hang up notification
* `ASYNCB_FOURPORT`: Multi-port serial cards
* `ASYNCB_SAK`: Secure Attention Key (like Ctrl+Alt+Del)
* `ASYNCB_SPD_HI`, `ASYNCB_SPD_VHI`, `ASYNCB_SPD_SHI`:  High, very high, and super high speeds.
* `ASYNCB_LOW_LATENCY`: Optimize for lower latency.
* `ASYNCB_CTS_FLOW`:  Clear To Send flow control.

And so on. The `ASYNC_...` versions are bitmasks created using left bit shifts (`1U << ...`). This allows combining multiple flags using bitwise OR.

**5. Connecting to Android Functionality:**

The key here is to think about where TTY devices are used in Android:

* **adb shell:**  This is the most direct use. When you connect via `adb shell`, you're interacting with a pseudo-terminal. These flags can influence its behavior.
* **Serial Ports:** Although less common on modern phones, Android devices might expose serial ports for debugging or specific hardware interactions.
* **Bluetooth Serial Port Profile (SPP):**  This emulates a serial connection over Bluetooth.
* **Kernel Drivers:** Ultimately, the kernel drivers for serial devices will use these flags.

**6. Illustrating with Examples:**

Concrete examples are essential.

* **`adb shell`:**  Explain how settings might affect the terminal experience (though the average user won't directly manipulate these flags).
* **Custom Hardware:**  Emphasize how device manufacturers might need to configure these flags for specific serial hardware.

**7. Addressing the "Dynamic Linker" Misconception:**

Similar to the libc function point, this header file itself doesn't directly involve the dynamic linker. However, *code that uses these flags* might be part of a shared library. Therefore, I need to explain the concept of shared libraries (.so files) and how the dynamic linker loads and links them. A simple .so layout example and a brief explanation of the linking process would be helpful.

**8. Logical Reasoning and Assumptions:**

Since there's no direct "logic" within the header file itself, I need to frame the reasoning around how these flags are *used*. I can create hypothetical scenarios:

* **Input:**  A program tries to open a serial port and set the `ASYNC_LOW_LATENCY` flag.
* **Output:**  The serial driver might prioritize low latency communication.

**9. Common Usage Errors:**

The primary user error isn't directly about *misusing* this header file (as it's just definitions). Instead, errors occur when *incorrect values* (based on these flags) are passed to system calls that configure TTY devices. For example, setting conflicting flags or using deprecated flags.

**10. Tracing the Path from Android Framework/NDK:**

This is a layered approach:

* **NDK:**  Developers using the NDK might interact with low-level TTY functionalities if they are building drivers or applications that directly communicate with serial devices. They would use standard POSIX functions (like `ioctl`) and these flags.
* **Android Framework:**  Higher-level framework components (like the `Terminal` app or services managing serial connections) would indirectly use these flags by calling lower-level system services.
* **Kernel:** Ultimately, the kernel's TTY drivers are where these flags are interpreted and acted upon.

**11. Frida Hook Example:**

A Frida example should target a relevant system call, like `ioctl`, which is commonly used to configure TTY devices. The example needs to show how to intercept the call and inspect the arguments, including the flags.

**12. Structuring the Answer:**

Finally, I need to organize the information logically, addressing each part of the user's request:

* Start with a summary of the file's purpose.
* Explain its relation to Android with examples.
* Address the libc function and dynamic linker misconceptions.
* Provide examples of logical reasoning and potential errors.
* Describe the path from the framework/NDK to the header file.
* Include a Frida hook example.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:** Focus too much on individual flags. **Correction:**  Emphasize the overall purpose and how the flags work together.
* **Initial thought:** Try to find specific libc functions that use these exact flags within *this* file. **Correction:** Realize that the flags are used by *other* parts of the system (kernel drivers, libc functions related to terminal I/O) and this file just defines the constants.
* **Initial thought:**  Provide very technical details about serial communication. **Correction:** Keep the explanation accessible to a broader audience while still being informative. Focus on the high-level concepts.
* **Initial thought:** Overcomplicate the dynamic linker explanation. **Correction:** Provide a simple and clear overview relevant to the context.

By following this structured thought process and incorporating self-correction, I can generate a comprehensive and accurate answer that addresses the user's request effectively, even accounting for potential misunderstandings in their initial question.
这是一个Linux内核头文件，定义了用于配置TTY（Teletypewriter，即终端设备）的各种标志位。这些标志位主要用于异步串口通信的配置。由于Android的底层是基于Linux内核的，因此这些定义也会被包含在Android的Bionic C库中。

**它的功能：**

该文件定义了一系列宏，这些宏代表了TTY设备的不同配置选项。这些选项可以控制串口的行为，例如：

* **流控制 (Flow Control):**  例如 `ASYNC_CTS_FLOW` 和 `ASYNC_CONS_FLOW`，用于硬件和软件流控制，防止数据溢出。
* **速度 (Speed):** 例如 `ASYNC_SPD_HI`, `ASYNC_SPD_VHI`, `ASYNC_SPD_SHI`，代表不同的串口波特率。
* **挂断信号 (Hang Up):** 例如 `ASYNC_HUP_NOTIFY`，当载波检测（CD）信号丢失时是否发送挂断信号。
* **特殊功能:** 例如 `ASYNC_SAK` (Secure Attention Key)，模拟安全关注键（通常是Ctrl+Alt+Del）。
* **状态标志:** 例如 `ASYNC_SUSPENDED`, `ASYNC_INITIALIZED`, `ASYNC_CLOSING`，表示TTY设备的当前状态。
* **其他杂项配置:** 例如低延迟模式 (`ASYNC_LOW_LATENCY`)，错误的UART处理 (`ASYNC_BUGGY_UART`) 等。

**与Android功能的关联及举例说明：**

虽然普通Android应用开发者不太会直接接触到这些底层的TTY标志，但它们在Android的底层系统中起着重要的作用，特别是在以下方面：

1. **`adb shell` 连接:** 当你使用 `adb shell` 连接到Android设备时，实际上是通过一个虚拟的TTY设备进行通信。这些标志可能影响 `adb shell` 会话的行为，例如字符编码、行缓冲等。

2. **串口通信 (Serial Communication):** 一些Android设备（特别是嵌入式设备或具有特殊硬件功能的设备）可能通过物理串口与其他设备通信。在这种情况下，开发者可能需要使用这些标志来配置串口参数，例如波特率、流控制、校验位等。

   **举例：** 假设一个Android设备连接了一个外部传感器，该传感器通过串口进行数据传输。Android系统可能需要设置 `ASYNC_SPD_HI` 或其他速度相关的标志来匹配传感器的波特率。如果传感器需要硬件流控制，则可能需要设置 `ASYNC_CTS_FLOW`。

3. **蓝牙串口 (Bluetooth Serial Port Profile - SPP):** 蓝牙SPP协议在底层模拟了一个串口连接。Android的蓝牙驱动程序和相关服务可能会使用这些标志来配置虚拟串口的行为。

4. **内核驱动程序 (Kernel Drivers):**  负责管理串口硬件的内核驱动程序会使用这些标志来配置硬件。Android的硬件抽象层 (HAL) 可能会调用内核接口来设置这些标志。

**详细解释每一个libc函数的功能是如何实现的：**

**这个 `tty_flags.h` 文件本身并不包含任何 C 函数的实现。** 它只是定义了一些预处理宏。这些宏常量会被传递给其他 libc 函数或内核系统调用，以配置TTY设备。

通常，与TTY设备交互的 libc 函数包括：

* **`open()`:** 打开一个终端设备文件（例如 `/dev/ttyS0`）。
* **`read()` 和 `write()`:**  从/向终端设备读取和写入数据。
* **`ioctl()`:**  一个通用的输入/输出控制接口，用于执行各种设备特定的操作。这是设置这些 TTY 标志的关键函数。  开发者会使用 `ioctl()` 函数，并传入相关的 `TTY` 相关的请求码（通常定义在 `<asm/ioctls.h>` 或其他内核头文件中）以及指向包含标志的结构体的指针。

**`ioctl()` 的基本工作原理：**

1. **用户空间调用 `ioctl()`:** 用户空间的程序调用 `ioctl()` 函数，指定要操作的文件描述符（通常是终端设备的文件描述符）、一个请求码（用于指示要执行的操作，例如设置终端属性）以及一个指向数据的指针（例如，包含要设置的标志的结构体）。

2. **系统调用陷入内核:**  `ioctl()` 是一个系统调用，当用户空间程序调用它时，会触发一个从用户态到内核态的切换。

3. **内核处理:** 内核接收到 `ioctl()` 系统调用后，会根据文件描述符找到对应的设备驱动程序。

4. **驱动程序处理:** 设备驱动程序根据 `ioctl()` 的请求码和传入的数据执行相应的操作。对于设置 TTY 标志的情况，驱动程序会解析传入的标志位，并配置底层的串口硬件或软件模拟的串口。

5. **返回用户空间:**  驱动程序完成操作后，内核会将结果返回给用户空间的程序。

**对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程：**

**这个 `tty_flags.h` 文件本身不直接涉及动态链接器。** 它只是一个头文件，在编译时会被包含到其他源文件中。

然而，如果一个共享库 (`.so` 文件) 中的代码使用了这些 TTY 标志（例如，某个库提供了串口通信的功能），那么动态链接器会在加载该共享库时发挥作用。

**`.so` 布局样本：**

一个典型的 `.so` 文件布局包含以下部分：

* **ELF Header:**  包含有关 `.so` 文件类型、目标架构、入口点等元数据。
* **Program Headers:** 描述了如何将文件的各个段加载到内存中。
* **Sections:** 包含实际的代码、数据和其他信息。一些重要的 sections 包括：
    * `.text`:  可执行代码
    * `.data`:  已初始化的全局变量和静态变量
    * `.bss`:  未初始化的全局变量和静态变量
    * `.rodata`:  只读数据
    * `.symtab`:  符号表，包含导出的和导入的符号信息（例如函数名、变量名）。
    * `.strtab`:  字符串表，存储符号表中使用的字符串。
    * `.dynsym`:  动态符号表，用于动态链接。
    * `.dynstr`:  动态字符串表，用于动态链接。
    * `.rel.dyn`:  动态重定位表，用于在加载时调整代码和数据中的地址。
    * `.rel.plt`:  PLT (Procedure Linkage Table) 重定位表，用于延迟绑定函数调用。
    * `.plt`:  Procedure Linkage Table，用于外部函数的延迟绑定。
    * `.got`:  Global Offset Table，存储全局变量的地址。

**链接的处理过程：**

1. **编译时:** 当编译一个使用 TTY 标志的源文件时，编译器会将这些宏定义嵌入到生成的机器码中。如果代码调用了与串口操作相关的函数（可能来自 libc 或其他共享库），编译器会生成对这些外部函数的符号引用。

2. **链接时:**  静态链接器（在构建可执行文件时）或动态链接器（在运行时加载共享库时）负责解析这些符号引用，并将它们指向正确的内存地址。

3. **动态链接器加载 `.so`:** 当 Android 系统需要加载一个 `.so` 文件时，动态链接器（通常是 `linker` 或 `linker64`）会执行以下步骤：
    * **加载 `.so` 文件到内存:**  根据 Program Headers 的描述，将 `.so` 文件的各个段加载到内存中的合适位置。
    * **解析依赖关系:** 检查 `.so` 文件的依赖关系（记录在 ELF header 中），并加载所需的其他共享库。
    * **重定位:** 根据 `.rel.dyn` 和 `.rel.plt` 表中的信息，调整代码和数据中的地址。这包括：
        * **GOT (Global Offset Table) 填充:**  动态链接器会填充 GOT 表，使其包含全局变量的实际地址。
        * **PLT (Procedure Linkage Table) 绑定 (延迟绑定):**  对于外部函数调用，初始时 PLT 条目会跳转到动态链接器的代码。当第一次调用该函数时，动态链接器会解析函数的实际地址，并更新 PLT 条目，以便后续调用直接跳转到该地址。
    * **符号解析:** 动态链接器会根据 `.dynsym` 和 `.dynstr` 表解析符号引用。如果 `.so` 文件中使用了 libc 中的串口操作函数，动态链接器会找到 libc `.so` 文件中对应函数的地址。

**假设输入与输出 (逻辑推理):**

由于这个文件只包含宏定义，直接的逻辑推理输入和输出不太适用。但是，我们可以假设一个使用这些标志的场景：

**假设输入:**

* 用户空间程序尝试打开串口设备 `/dev/ttyS0`。
* 程序通过 `ioctl()` 调用设置了以下标志：`ASYNC_HUP_NOTIFY | ASYNC_SPD_115200 | ASYNC_CTS_FLOW` (假设 `ASYNC_SPD_115200` 是一个代表 115200 波特率的假设宏)。

**逻辑推理过程:**

1. `ASYNC_HUP_NOTIFY`:  内核的串口驱动程序被配置为当载波检测信号丢失时，向进程发送挂断信号 (SIGHUP)。
2. `ASYNC_SPD_115200`: 内核的串口驱动程序将串口的波特率设置为 115200 bps。
3. `ASYNC_CTS_FLOW`: 内核的串口驱动程序启用硬件流控制，使用 CTS (Clear To Send) 信号。只有当外部设备的 CTS 信号线为有效状态时，串口才会发送数据。

**假设输出:**

* 当串口连接的外部设备断开连接（CD 信号丢失）时，程序会收到 `SIGHUP` 信号。
* 串口以 115200 bps 的速度进行数据传输。
* 只有当外部设备的 CTS 信号线有效时，程序才能通过串口发送数据。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **使用了已弃用的标志:** 某些标志可能在新的内核版本中被弃用，使用这些标志可能导致警告或未定义的行为。例如，代码中定义了 `ASYNC_DEPRECATED` 宏，包含了被认为过时的标志。

2. **设置了冲突的标志:**  某些标志的组合可能没有意义或相互冲突。例如，同时启用两种不同的流控制机制可能会导致意外行为。

3. **波特率设置不匹配:** 如果程序设置的波特率与连接的外部设备的波特率不一致，会导致数据传输错误或乱码。

4. **忘记处理挂断信号:** 如果程序设置了 `ASYNC_HUP_NOTIFY`，但没有正确地处理 `SIGHUP` 信号，可能会导致程序在串口断开连接时崩溃或出现异常行为。

5. **权限问题:** 尝试打开串口设备可能需要特定的权限。如果程序没有足够的权限，`open()` 调用会失败。

**说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。**

1. **NDK 开发 (C/C++):**
   - 如果开发者使用 NDK 编写本地代码，并且需要进行串口通信，他们可能会直接包含 `<linux/tty_flags.h>` 头文件。
   - 他们会使用 POSIX 标准的串口操作函数，例如 `open()`, `read()`, `write()`, 和 `ioctl()`。
   - 在调用 `ioctl()` 时，他们会使用 `TTY` 相关的请求码，并传递包含这些标志的结构体。

2. **Android Framework (Java/Kotlin):**
   - Android Framework 本身并没有直接使用这些底层的 TTY 标志。Framework 提供了更高级的 API，例如 `android.hardware.SerialManager` 用于串口通信。
   - `SerialManager` 的实现可能会调用底层的 native 代码 (通过 JNI)。
   - 这些 native 代码最终可能会使用 `ioctl()` 系统调用，并间接地涉及到 `tty_flags.h` 中定义的标志。

3. **系统服务 (System Services):**
   - 一些系统服务，例如管理蓝牙串口连接的服务，可能会在底层使用 native 代码来配置串口，从而涉及到这些标志。

**Frida Hook 示例：**

我们可以使用 Frida 来 hook `ioctl()` 系统调用，观察哪些标志被传递给串口设备。

```python
import frida
import sys

# 要 hook 的 ioctl 系统调用
ioctl_address = None

# 尝试从 libc.so 中找到 ioctl 的地址
session = frida.attach('com.example.myapp') # 替换为你的应用进程名

try:
    libc = session.modules.find_module_by_name("libc.so")
    if libc:
        ioctl_symbol = libc.get_symbol_by_name("__ioctl") # 根据目标架构可能有所不同，例如 "__syscall_ioctl"
        if ioctl_symbol:
            ioctl_address = ioctl_symbol.address
            print(f"找到 ioctl 地址: {ioctl_address}")
        else:
            print("未找到 ioctl 符号")
    else:
        print("未找到 libc.so")
except Exception as e:
    print(f"查找 ioctl 地址时出错: {e}")
    sys.exit(1)

if ioctl_address:
    script = session.create_script(f"""
    Interceptor.attach(ptr('{ioctl_address}'), {{
        onEnter: function(args) {{
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            // 检查是否是与 TTY 相关的 ioctl 请求 (请求码通常以 'T' 开头)
            if (request > 0x5400 && request < 0x54FF) {{ // 这是一个大致的范围，需要根据实际情况调整
                console.log("ioctl called with fd:", fd, "request:", request);
                // 可以尝试读取 arg[2] 指向的内存，解析 TTY 标志
                // 这需要了解具体的 ioctl 请求码和数据结构
            }}
        }}
    }});
    """)
    script.load()
    sys.stdin.read()
else:
    print("无法 hook ioctl，请检查是否成功找到地址")

```

**说明:**

1. **找到 `ioctl` 地址:**  首先需要找到 `ioctl` 系统调用在内存中的地址。这个地址可能因 Android 版本和架构而异。我们尝试在 `libc.so` 中查找 `__ioctl` 符号。
2. **Frida Script:**  Frida 脚本使用 `Interceptor.attach` 来 hook `ioctl` 函数。
3. **`onEnter`:**  当 `ioctl` 被调用时，`onEnter` 函数会被执行。
4. **检查请求码:**  我们检查 `ioctl` 的 `request` 参数，通常 TTY 相关的请求码会落在特定的范围内（这个范围需要根据实际情况和 `<asm/ioctls.h>` 等头文件来确定）。
5. **解析标志:**  如果请求码是 TTY 相关的，我们可以尝试读取 `args[2]` 指向的内存，但这需要我们事先知道该请求码对应的数据结构，才能正确解析出 TTY 标志的值。

**更精细的 Hook:**

要更精确地 hook 特定类型的 TTY `ioctl` 调用并解析标志，你需要：

1. **确定目标 `ioctl` 请求码:**  例如，设置 TTY 属性的请求码可能是 `TCSETS`, `TCSETSW` 等。
2. **了解数据结构:**  查阅内核头文件，了解这些请求码对应的数据结构（通常是 `termios` 结构体）。
3. **在 Frida 脚本中读取和解析数据结构:**  使用 `Memory.readByteArray` 或 `Memory.readU32()` 等方法读取 `args[2]` 指向的内存，并根据数据结构的定义解析出标志位。

例如，如果目标是 hook `TCSETS` 并查看设置的标志，你可能需要读取 `termios` 结构体，并从中提取 `c_cflag` 字段来查看控制模式标志。

请注意，直接解析内核数据结构可能比较复杂，并且容易受到内核版本变化的影响。

总而言之，`bionic/libc/kernel/uapi/linux/tty_flags.h` 定义了用于配置 Linux 终端设备的底层标志，这些标志在 Android 系统的串口通信、`adb shell` 连接以及相关的内核驱动程序中发挥着重要作用。虽然普通 Android 应用开发者不太会直接操作这些标志，但理解它们的功能有助于深入了解 Android 系统的底层机制。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/tty_flags.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_TTY_FLAGS_H
#define _LINUX_TTY_FLAGS_H
#define ASYNCB_HUP_NOTIFY 0
#define ASYNCB_FOURPORT 1
#define ASYNCB_SAK 2
#define ASYNCB_SPLIT_TERMIOS 3
#define ASYNCB_SPD_HI 4
#define ASYNCB_SPD_VHI 5
#define ASYNCB_SKIP_TEST 6
#define ASYNCB_AUTO_IRQ 7
#define ASYNCB_SESSION_LOCKOUT 8
#define ASYNCB_PGRP_LOCKOUT 9
#define ASYNCB_CALLOUT_NOHUP 10
#define ASYNCB_HARDPPS_CD 11
#define ASYNCB_SPD_SHI 12
#define ASYNCB_LOW_LATENCY 13
#define ASYNCB_BUGGY_UART 14
#define ASYNCB_AUTOPROBE 15
#define ASYNCB_MAGIC_MULTIPLIER 16
#define ASYNCB_LAST_USER 16
#define ASYNCB_INITIALIZED 31
#define ASYNCB_SUSPENDED 30
#define ASYNCB_NORMAL_ACTIVE 29
#define ASYNCB_BOOT_AUTOCONF 28
#define ASYNCB_CLOSING 27
#define ASYNCB_CTS_FLOW 26
#define ASYNCB_CHECK_CD 25
#define ASYNCB_SHARE_IRQ 24
#define ASYNCB_CONS_FLOW 23
#define ASYNCB_FIRST_KERNEL 22
#define ASYNC_HUP_NOTIFY (1U << ASYNCB_HUP_NOTIFY)
#define ASYNC_SUSPENDED (1U << ASYNCB_SUSPENDED)
#define ASYNC_FOURPORT (1U << ASYNCB_FOURPORT)
#define ASYNC_SAK (1U << ASYNCB_SAK)
#define ASYNC_SPLIT_TERMIOS (1U << ASYNCB_SPLIT_TERMIOS)
#define ASYNC_SPD_HI (1U << ASYNCB_SPD_HI)
#define ASYNC_SPD_VHI (1U << ASYNCB_SPD_VHI)
#define ASYNC_SKIP_TEST (1U << ASYNCB_SKIP_TEST)
#define ASYNC_AUTO_IRQ (1U << ASYNCB_AUTO_IRQ)
#define ASYNC_SESSION_LOCKOUT (1U << ASYNCB_SESSION_LOCKOUT)
#define ASYNC_PGRP_LOCKOUT (1U << ASYNCB_PGRP_LOCKOUT)
#define ASYNC_CALLOUT_NOHUP (1U << ASYNCB_CALLOUT_NOHUP)
#define ASYNC_HARDPPS_CD (1U << ASYNCB_HARDPPS_CD)
#define ASYNC_SPD_SHI (1U << ASYNCB_SPD_SHI)
#define ASYNC_LOW_LATENCY (1U << ASYNCB_LOW_LATENCY)
#define ASYNC_BUGGY_UART (1U << ASYNCB_BUGGY_UART)
#define ASYNC_AUTOPROBE (1U << ASYNCB_AUTOPROBE)
#define ASYNC_MAGIC_MULTIPLIER (1U << ASYNCB_MAGIC_MULTIPLIER)
#define ASYNC_FLAGS ((1U << (ASYNCB_LAST_USER + 1)) - 1)
#define ASYNC_DEPRECATED (ASYNC_SPLIT_TERMIOS | ASYNC_SESSION_LOCKOUT | ASYNC_PGRP_LOCKOUT | ASYNC_CALLOUT_NOHUP | ASYNC_AUTOPROBE)
#define ASYNC_USR_MASK (ASYNC_SPD_MASK | ASYNC_CALLOUT_NOHUP | ASYNC_LOW_LATENCY)
#define ASYNC_SPD_CUST (ASYNC_SPD_HI | ASYNC_SPD_VHI)
#define ASYNC_SPD_WARP (ASYNC_SPD_HI | ASYNC_SPD_SHI)
#define ASYNC_SPD_MASK (ASYNC_SPD_HI | ASYNC_SPD_VHI | ASYNC_SPD_SHI)
#define ASYNC_INITIALIZED (1U << ASYNCB_INITIALIZED)
#define ASYNC_NORMAL_ACTIVE (1U << ASYNCB_NORMAL_ACTIVE)
#define ASYNC_BOOT_AUTOCONF (1U << ASYNCB_BOOT_AUTOCONF)
#define ASYNC_CLOSING (1U << ASYNCB_CLOSING)
#define ASYNC_CTS_FLOW (1U << ASYNCB_CTS_FLOW)
#define ASYNC_CHECK_CD (1U << ASYNCB_CHECK_CD)
#define ASYNC_SHARE_IRQ (1U << ASYNCB_SHARE_IRQ)
#define ASYNC_CONS_FLOW (1U << ASYNCB_CONS_FLOW)
#define ASYNC_INTERNAL_FLAGS (~((1U << ASYNCB_FIRST_KERNEL) - 1))
#endif
```