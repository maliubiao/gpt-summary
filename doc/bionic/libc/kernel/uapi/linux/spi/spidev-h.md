Response:
Let's break down the thought process for generating the comprehensive response to the provided `spidev.h` header file.

**1. Understanding the Request:**

The request asks for a detailed analysis of the `spidev.h` file within the context of Android's Bionic library. Key areas of focus include:

* **Functionality:** What does this file do?
* **Android Relevance:** How does it relate to Android's operation?
* **libc Function Explanation:** Detailed explanation of each `libc` function used.
* **Dynamic Linker:** Explanation of relevant dynamic linker aspects.
* **Logic Reasoning:**  Hypothetical inputs and outputs.
* **Common Errors:** User programming mistakes.
* **Android Framework/NDK Path:** How is this reached from higher layers?
* **Frida Hooking:** Example for debugging.

**2. Initial Analysis of the Header File:**

* **Filename and Location:**  `bionic/libc/kernel/uapi/linux/spi/spidev.handroid` suggests this is a header file defining the user-space API for interacting with SPI devices on Android. The `.handroid` likely indicates Android-specific modifications or adaptations.
* **`#ifndef SPIDEV_H`, `#define SPIDEV_H`, `#endif`:**  Standard header guard to prevent multiple inclusions.
* **Includes:**
    * `<linux/types.h>`:  Defines basic Linux data types like `__u64`, `__u32`, `__u16`, `__u8`.
    * `<linux/ioctl.h>`: Defines macros and structures for the `ioctl` system call. This immediately signals that this header is about controlling hardware devices.
    * `<linux/spi/spi.h>`: Contains core SPI definitions, likely data structures related to SPI transfers.
* **`SPI_IOC_MAGIC 'k'`:**  A magic number used in `ioctl` commands to identify operations related to SPI.
* **`struct spi_ioc_transfer`:** A crucial structure defining a single SPI transfer operation. It includes fields for transmit/receive buffers, length, speed, timing, and chip select control. The `__u64` for buffers hints at the potential need for user-space memory mapping.
* **`SPI_MSGSIZE(N)`:** A macro to calculate the size of an array of `spi_ioc_transfer` structures for a batch of transfers. The check against `(1 << _IOC_SIZEBITS)` suggests a limitation on the size of `ioctl` data.
* **`SPI_IOC_MESSAGE(N)`:**  A macro defining an `ioctl` command to send a sequence of SPI transfers. The `_IOW` macro indicates this is for writing data (the transfer descriptions) to the kernel.
* **`SPI_IOC_RD_*` and `SPI_IOC_WR_*`:**  A series of macros defining `ioctl` commands for reading and writing various SPI device settings like mode, bit order, bits per word, and maximum speed. The `_IOR` and `_IOW` macros indicate read and write operations, respectively.

**3. Connecting to Android:**

* **Hardware Interaction:**  SPI is a common interface for communicating with hardware components like sensors, displays, and memory chips. Android devices heavily rely on such components.
* **HAL (Hardware Abstraction Layer):**  The most likely point of interaction is through the Android HAL. HAL modules provide a standardized interface for the Android framework to interact with specific hardware.
* **NDK:**  Developers can use the NDK to write native code that interacts with hardware, potentially using these `ioctl` commands.

**4. Explaining libc Functions:**

The header itself doesn't *define* `libc` functions. It *uses* concepts and structures that are handled by the kernel and accessed through `libc`'s system call wrappers. The key `libc` function involved is `ioctl`.

* **`ioctl`:**  This is the central system call. The explanation focuses on its purpose (device control), arguments (file descriptor, request code, optional argument), and how the macros in the header relate to the request code.

**5. Addressing the Dynamic Linker:**

This header file itself doesn't directly involve the dynamic linker. However, *using* these definitions in a shared library would.

* **SO Layout Sample:** A basic example showing how a hypothetical `libspi.so` might be structured.
* **Linking Process:**  Explains how the dynamic linker resolves symbols and maps the library into memory. It highlights that this header defines *data structures* and *macros*, not functions that need to be dynamically linked in this specific file.

**6. Logic and Examples:**

* **Assumption:**  The code will be used to communicate with an SPI device.
* **Input/Output:** A simple example of setting the SPI mode.
* **User Errors:** Common mistakes when using `ioctl` with SPI, such as incorrect arguments or permissions.

**7. Tracing the Path from Framework/NDK:**

* **Framework:**  Illustrates a plausible path from a Java-level API (like `android.hardware.spi`) down through the JNI, native HAL implementation, and finally to the `open()` and `ioctl()` system calls using the definitions from this header.
* **NDK:**  Shows a simpler direct path from C/C++ code using file operations and `ioctl`.

**8. Frida Hooking:**

* **Hooking Points:**  Focuses on hooking the `ioctl` system call, as that's where the SPI commands are issued. Provides examples of hooking both at the generic `ioctl` level and at a specific SPI `ioctl` command.

**9. Structuring the Response:**

The key to a good response is organization. Using clear headings, bullet points, and code blocks makes the information easier to digest. Starting with a general overview and then diving into specifics is a good strategy. The request specifically asked for Chinese output, so ensuring accurate translation and natural language flow is essential.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe I should explain the `include` files in detail.
* **Correction:** The request focuses on `spidev.h`. Briefly mentioning the included files' purpose is enough.
* **Initial thought:**  Focus on every possible `ioctl` command.
* **Correction:**  Focus on explaining the *general mechanism* of `ioctl` and provide examples for common commands. Going into exhaustive detail for every `SPI_IOC_*` macro might be overwhelming.
* **Initial thought:**  This file doesn't have functions, so how can I explain libc function implementation?
* **Correction:** The *use* of this header file leads to the use of `libc` functions like `open` and `ioctl`. Explain those in that context.
* **Initial thought:** How to illustrate the dynamic linker when this is just a header?
* **Correction:** Explain how a *library using* these definitions would be laid out and linked.

By following this structured analysis and self-correction process, the detailed and informative response can be generated. The key is to understand the context of the request and prioritize the most relevant information.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/spi/spidev.handroid` 这个头文件。

**功能列举:**

这个头文件定义了用户空间程序与 Linux SPI (Serial Peripheral Interface) 设备驱动进行交互的接口。它主要包含以下功能：

1. **数据结构定义 (`struct spi_ioc_transfer`)**:  定义了用于描述一次 SPI 数据传输操作的结构体。这个结构体包含了传输和接收缓冲区地址、数据长度、传输速度、延迟、数据位宽等关键参数。
2. **`ioctl` 命令定义**: 定义了一系列用于控制 SPI 设备驱动行为的 `ioctl` 命令宏。这些命令宏允许用户空间程序配置 SPI 设备的模式、位序、速度等参数，以及执行实际的数据传输。
3. **常量定义 (`SPI_IOC_MAGIC`)**: 定义了一个魔数，用于标识 `ioctl` 命令属于 SPI 设备。
4. **宏定义 (`SPI_MSGSIZE`)**:  定义了一个宏，用于计算批量 SPI 传输消息的大小。

**与 Android 功能的关系及举例说明:**

SPI 是嵌入式系统中常用的串行通信协议，Android 设备中许多硬件模块（例如传感器、显示屏、某些类型的存储器）都可能使用 SPI 接口进行通信。

* **硬件抽象层 (HAL):** Android 的 HAL 层是连接 Android 框架和硬件驱动的关键层。  通常，Android 框架会通过 HAL 调用来访问硬件功能。  对于 SPI 设备，HAL 模块会使用这里定义的 `ioctl` 命令与 SPI 设备驱动进行交互。
    * **举例:** 假设一个 Android 设备使用 SPI 连接了一个温度传感器。Android 框架需要读取传感器数据时，会调用相应的 HAL 接口。HAL 模块会将读取操作转换为一个或多个 `spi_ioc_transfer` 结构体，并使用 `ioctl` 系统调用，传入相应的 `SPI_IOC_MESSAGE` 命令，将这些结构体传递给 SPI 驱动。
* **Android NDK (Native Development Kit):**  NDK 允许开发者使用 C/C++ 代码直接与底层硬件交互。开发者可以使用 NDK 提供的 API (通常是对 `open` 和 `ioctl` 系统调用的封装)  来操作 SPI 设备，直接使用这个头文件中定义的结构体和宏。
    * **举例:** 一个使用 NDK 开发的应用程序可能需要直接控制一个连接到 SPI 总线的外部显示屏。该应用会打开 `/dev/spidevX.Y` 设备文件，然后构造 `spi_ioc_transfer` 结构体来描述要发送到显示屏的初始化命令或图像数据，并使用 `ioctl` 和相应的 `SPI_IOC_MESSAGE` 命令发送这些数据。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并不包含 `libc` 函数的实现，它只是定义了一些数据结构和宏。然而，当用户空间程序使用这些定义来操作 SPI 设备时，会涉及到 `libc` 提供的系统调用接口，最核心的就是 `ioctl`。

* **`ioctl` 函数:**
    * **功能:** `ioctl` (input/output control) 是一个 Linux 系统调用，用于执行设备特定的控制操作。它允许用户空间程序向设备驱动发送命令并传递数据。
    * **实现:**  当用户空间程序调用 `ioctl` 时，内核会进行以下处理：
        1. **系统调用入口:** 程序陷入内核态，执行 `ioctl` 系统调用对应的内核代码。
        2. **参数解析:** 内核会解析 `ioctl` 的参数，包括文件描述符 `fd` (指向打开的 SPI 设备文件)、请求码 `request` (例如 `SPI_IOC_MESSAGE`) 和可选的参数 `argp` (通常是指向 `spi_ioc_transfer` 结构体的指针)。
        3. **设备驱动查找:** 内核根据文件描述符 `fd` 找到对应的设备驱动程序。
        4. **驱动处理:** 内核调用 SPI 设备驱动程序中与 `ioctl` 请求码 `request` 相对应的处理函数。
        5. **命令执行:** SPI 驱动程序会根据 `ioctl` 命令和传入的参数执行相应的操作，例如配置 SPI 控制器的参数、启动 SPI 数据传输等。这通常涉及到与硬件 SPI 控制器的交互。
        6. **结果返回:** 驱动程序将执行结果返回给内核，内核再将结果返回给用户空间程序。

    **在这个上下文中，`ioctl` 的关键作用是:**
    * **配置 SPI 设备:**  通过 `SPI_IOC_WR_MODE`、`SPI_IOC_WR_BITS_PER_WORD` 等命令，配置 SPI 设备的工作模式、数据位宽等。
    * **执行 SPI 数据传输:** 通过 `SPI_IOC_MESSAGE` 命令，将包含多个 `spi_ioc_transfer` 结构体的数组传递给驱动，驱动根据这些结构体描述执行一系列 SPI 数据传输操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及动态链接器的功能。它只是一个头文件，会被编译到使用它的代码中。动态链接器主要负责加载共享库 (`.so` 文件) 并解析符号引用。

如果一个共享库 (例如一个 SPI HAL 模块 `libspi_hal.so`) 使用了这个头文件中定义的结构体和宏，那么在加载该共享库时，动态链接器会参与链接过程。

**SO 布局样本 (`libspi_hal.so`):**

```
libspi_hal.so:
    .init         # 初始化代码段
    .plt          # 程序链接表 (Procedure Linkage Table)
    .text         # 代码段 (包含使用 spidev.h 中定义的结构体和宏的函数)
        spi_open_device:
            ; ... 调用 open("/dev/spidev0.0", ...) ...
        spi_transfer:
            ; ... 构造 spi_ioc_transfer 结构体 ...
            ; ... 调用 ioctl(fd, SPI_IOC_MESSAGE(N), &transfers) ...
    .rodata       # 只读数据段 (可能包含一些常量)
    .data         # 数据段 (可能包含一些全局变量)
    .bss          # 未初始化数据段
    .dynamic      # 动态链接信息
    .symtab       # 符号表
    .strtab       # 字符串表
    ...
```

**链接的处理过程:**

1. **加载:** 当 Android 系统需要加载 `libspi_hal.so` 时 (例如，当一个使用 SPI HAL 的应用启动时)，`linker` (动态链接器) 会将该 `.so` 文件加载到内存中。
2. **符号解析:**  `linker` 会解析 `libspi_hal.so` 中对外部符号的引用。虽然 `spidev.h` 中定义的是结构体和宏，不是函数，但如果 `libspi_hal.so` 中有函数调用了 `libc` 的 `open` 或 `ioctl`，那么 `linker` 需要找到这些函数的实现。这些 `libc` 函数通常位于 `libc.so` 中。
3. **重定位:**  `linker` 会修改代码和数据段中的地址，以确保函数调用和数据访问指向正确的内存位置。这包括将 `.plt` 中的条目指向实际的函数地址。
4. **依赖加载:** 如果 `libspi_hal.so` 依赖于其他共享库，`linker` 也会加载这些依赖库。

**注意:**  `spidev.h` 本身不需要动态链接，因为它只是一个头文件，在编译时会被包含到源文件中。动态链接器处理的是编译后的共享库文件。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们编写了一个简单的程序，使用 `spidev.h` 中的定义来设置 SPI 设备的模式和速度，并发送一些数据。

**假设输入:**

* 打开 SPI 设备文件: `/dev/spidev0.0`
* 设置 SPI 模式为模式 0 (CPHA=0, CPOL=0)
* 设置 SPI 位序为 MSB first (Most Significant Bit first)
* 设置 SPI 最大速度为 1MHz (1000000 Hz)
* 发送数据: `uint8_t tx_data[] = {0x01, 0x02, 0x03};`

**预期输出:**

* 成功打开设备文件 (返回一个有效的文件描述符)。
* 成功设置 SPI 模式和速度 ( `ioctl` 调用返回 0)。
* SPI 设备驱动程序会将 `tx_data` 中的字节通过 SPI 总线发送出去。具体的硬件行为取决于连接到 SPI 总线的设备。

**用户或编程常见的使用错误，请举例说明:**

1. **`ioctl` 命令使用错误:**
   * **错误的请求码:** 使用了不存在或者不适用的 `ioctl` 命令。例如，试图使用一个用于读取属性的命令来写入属性。
   * **参数类型不匹配:** 传递给 `ioctl` 的参数类型与命令要求的类型不匹配。例如，本应传递 `__u8` 的地方传递了 `int`。
   * **参数值错误:** 传递了超出范围或者无效的参数值。例如，设置了一个负的 SPI 速度。

   ```c
   // 错误示例：使用了错误的请求码
   int ret = ioctl(fd, SPI_IOC_RD_MODE32, &mode); // 假设想读取 8 位模式，却使用了 32 位的命令
   if (ret == -1) {
       perror("ioctl SPI_IOC_RD_MODE32 failed");
   }
   ```

2. **`spi_ioc_transfer` 结构体配置错误:**
   * **缓冲区指针无效:** `tx_buf` 或 `rx_buf` 指向无效的内存地址。
   * **长度错误:** `len` 的值与实际缓冲区的大小不匹配。
   * **位宽错误:** `bits_per_word` 设置了硬件不支持的值。

   ```c
   // 错误示例：缓冲区指针未分配或为空
   struct spi_ioc_transfer tr;
   tr.tx_buf = (uintptr_t)NULL;
   tr.len = 3;
   int ret = ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
   if (ret == -1) {
       perror("ioctl SPI_IOC_MESSAGE failed");
   }
   ```

3. **设备文件权限问题:** 用户程序没有足够的权限打开 `/dev/spidevX.Y` 设备文件。

4. **忘记设置必要的参数:**  例如，在执行传输之前没有设置 SPI 模式或速度。

5. **竞争条件:**  在多线程环境下，多个线程同时访问同一个 SPI 设备，可能导致数据 corruption 或不可预测的行为。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `spidev.h` 的路径 (大致流程):**

1. **Java Framework API:**  Android 应用通常使用 Java Framework 提供的 API 来访问硬件功能。对于 SPI，可能存在一个 `android.hardware.spi` 或类似的 Java API (实际情况可能比较复杂，可能通过 HAL 抽象)。

2. **JNI (Java Native Interface):** Java Framework API 的底层实现通常会调用 Native 代码 (C/C++) 通过 JNI 进行交互。

3. **HAL (Hardware Abstraction Layer):** Native 代码会与硬件抽象层 (HAL) 模块进行通信。Android 的 HAL 提供了一组标准的接口，供 Framework 调用，屏蔽了不同硬件实现的差异。对于 SPI，可能存在一个 `spi.h` 的 HAL 定义。

4. **HAL 实现:** 具体的 HAL 模块 (例如 `spi_hal.so`) 实现了 HAL 定义的接口。在这个 HAL 模块中，会使用底层的 Linux 系统调用来操作 SPI 设备。

5. **System Calls:** HAL 模块会调用 `libc` 提供的系统调用，例如 `open()` 打开 `/dev/spidevX.Y` 设备文件，然后使用 `ioctl()` 和 `spidev.h` 中定义的命令和结构体与 SPI 设备驱动进行通信。

**Android NDK 到 `spidev.h` 的路径:**

1. **NDK API:**  NDK 允许开发者直接使用 C/C++ 代码访问底层 Linux API。

2. **System Calls:**  NDK 代码可以直接使用 `open()` 和 `ioctl()` 等系统调用，并包含 `<linux/spi/spidev.h>` 头文件来定义相关的结构体和宏。

**Frida Hook 示例:**

我们可以使用 Frida 来 hook `ioctl` 系统调用，查看传递给 SPI 驱动的命令和数据。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
    session = device.attach(pid)
    script = session.create_script("""
        // Hook ioctl 系统调用
        Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
            onEnter: function(args) {
                const fd = args[0].toInt32();
                const request = args[1].toInt32();

                // 判断是否是 SPI 相关的 ioctl 命令 (可以根据 SPI_IOC_MAGIC 或其他特征判断)
                if ((request & 0xFF) == 107) { // 107 是 'k' 的 ASCII 码，SPI_IOC_MAGIC
                    console.log("[*] ioctl called with fd:", fd, "request:", request);

                    // 可以进一步解析参数，例如当 request 是 SPI_IOC_MESSAGE 时，解析 spi_ioc_transfer 结构体
                    if ((request & 0xFF00) == 0x0000) { // SPI_IOC_MESSAGE
                        const num_transfers = (request >> 8) & 0xFF;
                        const transfers_ptr = ptr(args[2]);
                        console.log("[*] Number of transfers:", num_transfers);
                        for (let i = 0; i < num_transfers; i++) {
                            const transfer = transfers_ptr.add(i * 48); // sizeof(struct spi_ioc_transfer) = 48
                            const tx_buf = transfer.readU64();
                            const rx_buf = transfer.readU64();
                            const len = transfer.readU32();
                            console.log(`[*] Transfer ${i}: tx_buf: ${tx_buf}, rx_buf: ${rx_buf}, len: ${len}`);
                            if (tx_buf.compare(ptr(0)) !== 0 && len > 0) {
                                console.log("[*] TX Data:", hexdump(ptr(tx_buf), { length: len, ansi: true }));
                            }
                            if (rx_buf.compare(ptr(0)) !== 0 && len > 0) {
                                console.log("[*] RX Buffer Address:", rx_buf);
                            }
                        }
                    } else if (request == 0x40046b01) { // SPI_IOC_WR_MODE
                        const mode = Memory.readU8(ptr(args[2]));
                        console.log("[*] Setting SPI mode:", mode);
                    } else if (request == 0x40046b04) { // SPI_IOC_WR_MAX_SPEED_HZ
                        const speed = Memory.readU32(ptr(args[2]));
                        console.log("[*] Setting SPI speed:", speed);
                    }
                }
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    input()
    session.detach()

except frida.exceptions.FailedToSpawnProcessError as e:
    print(f"Error spawning process: {e}")
except frida.ServerNotRunningError as e:
    print(f"Frida server not running: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

```

**Frida Hook 解释:**

1. **连接到设备和进程:** 代码首先连接到 USB 设备，然后启动或附加到目标 Android 应用程序的进程。
2. **Hook `ioctl`:**  使用 `Interceptor.attach` 函数 hook `libc.so` 中的 `ioctl` 函数。
3. **`onEnter` 函数:** 当 `ioctl` 被调用时，`onEnter` 函数会被执行。
4. **检查请求码:** 代码检查 `ioctl` 的第二个参数 `request`，判断是否是 SPI 相关的命令。这里使用了 `SPI_IOC_MAGIC` 的值来初步判断。
5. **解析参数:**  对于 SPI 消息传输 (`SPI_IOC_MESSAGE`)，代码会解析 `spi_ioc_transfer` 结构体，并打印出发送和接收缓冲区的地址和长度，以及发送的数据。对于其他 SPI 控制命令，会解析相应的参数。
6. **打印信息:**  使用 `console.log` 打印出 `ioctl` 的调用信息和参数内容。
7. **加载和运行脚本:**  加载 Frida 脚本并恢复目标进程的执行。

通过运行这个 Frida 脚本，你可以观察到应用程序在操作 SPI 设备时，传递给 `ioctl` 系统调用的具体命令和数据，从而帮助你调试和理解 Android Framework 或 NDK 是如何一步步地使用 `spidev.h` 中定义的接口与 SPI 设备进行交互的。

希望这个详细的解答能够帮助你理解 `bionic/libc/kernel/uapi/linux/spi/spidev.handroid` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/spi/spidev.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef SPIDEV_H
#define SPIDEV_H
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/spi/spi.h>
#define SPI_IOC_MAGIC 'k'
struct spi_ioc_transfer {
  __u64 tx_buf;
  __u64 rx_buf;
  __u32 len;
  __u32 speed_hz;
  __u16 delay_usecs;
  __u8 bits_per_word;
  __u8 cs_change;
  __u8 tx_nbits;
  __u8 rx_nbits;
  __u8 word_delay_usecs;
  __u8 pad;
};
#define SPI_MSGSIZE(N) ((((N) * (sizeof(struct spi_ioc_transfer))) < (1 << _IOC_SIZEBITS)) ? ((N) * (sizeof(struct spi_ioc_transfer))) : 0)
#define SPI_IOC_MESSAGE(N) _IOW(SPI_IOC_MAGIC, 0, char[SPI_MSGSIZE(N)])
#define SPI_IOC_RD_MODE _IOR(SPI_IOC_MAGIC, 1, __u8)
#define SPI_IOC_WR_MODE _IOW(SPI_IOC_MAGIC, 1, __u8)
#define SPI_IOC_RD_LSB_FIRST _IOR(SPI_IOC_MAGIC, 2, __u8)
#define SPI_IOC_WR_LSB_FIRST _IOW(SPI_IOC_MAGIC, 2, __u8)
#define SPI_IOC_RD_BITS_PER_WORD _IOR(SPI_IOC_MAGIC, 3, __u8)
#define SPI_IOC_WR_BITS_PER_WORD _IOW(SPI_IOC_MAGIC, 3, __u8)
#define SPI_IOC_RD_MAX_SPEED_HZ _IOR(SPI_IOC_MAGIC, 4, __u32)
#define SPI_IOC_WR_MAX_SPEED_HZ _IOW(SPI_IOC_MAGIC, 4, __u32)
#define SPI_IOC_RD_MODE32 _IOR(SPI_IOC_MAGIC, 5, __u32)
#define SPI_IOC_WR_MODE32 _IOW(SPI_IOC_MAGIC, 5, __u32)
#endif
```