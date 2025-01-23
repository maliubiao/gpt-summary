Response:
Let's break down the thought process for answering this request.

**1. Understanding the Core Request:**

The primary goal is to analyze a C header file related to the Linux I2C subsystem and explain its relevance to Android, its functions, and how it's used. The keywords are "功能", "android的关系", "libc函数", "dynamic linker", "逻辑推理", "用户错误", "android framework/ndk", and "frida hook". This means I need to cover the technical details, its connection to Android, potential issues, and debugging methods.

**2. Initial Analysis of the Header File:**

* **Header Guards:** The `#ifndef _UAPI_LINUX_I2C_H` and `#define _UAPI_LINUX_I2C_H` indicate this is a standard C header file designed to prevent multiple inclusions.
* **Includes:**  `#include <linux/types.h>` suggests this header relies on fundamental Linux data types.
* **`struct i2c_msg`:** This structure clearly defines the components of an I2C message. The members `addr`, `flags`, `len`, and `buf` are crucial for understanding I2C communication. The defined constants starting with `I2C_M_` are flags that modify the behavior of I2C messages.
* **`I2C_FUNC_` Defines:** These constants describe the capabilities or features supported by an I2C adapter or device.
* **`union i2c_smbus_data`:**  This union provides different ways to interpret the data received or sent over the SMBus protocol (a subset of I2C). It can be a byte, a word, or a block of bytes.
* **`I2C_SMBUS_` Defines:** These constants specify the types of SMBus transactions.

**3. Connecting to Android:**

The prompt explicitly mentions `bionic`, Android's C library. This header file, being within the `bionic/libc/kernel/uapi/linux/` structure, implies it's a *user-space interface* to the Linux kernel's I2C driver. Therefore, Android applications (through the NDK) can use system calls that eventually interact with these kernel structures to control I2C devices. This forms the core connection.

**4. Addressing Specific Requirements:**

* **功能 (Functions):**  The header file *doesn't* define C *functions* in the typical sense. Instead, it defines *data structures* and *constants* used to interact with the I2C subsystem. I need to clarify this distinction. The *functionality* is provided by the *kernel driver* and accessed through system calls using these structures.
* **与android的功能有关系 (Relationship with Android functions):**  The key is explaining how Android's hardware abstraction layer (HAL) and NDK expose I2C functionality. Sensors, touchscreens, and other peripherals are common examples of I2C devices on Android.
* **libc函数的功能是如何实现的 (How libc functions are implemented):** This is tricky because this header *isn't* part of the standard libc. It's a kernel header exposed to user-space. Therefore, I need to talk about the *system calls* that *use* these definitions, like `ioctl()`. I need to explain that libc provides wrappers for these system calls.
* **dynamic linker (Dynamic Linker):** This header itself doesn't directly involve the dynamic linker. However, the libraries that *use* these definitions (like those providing I2C access) *do* get linked dynamically. I need to provide a conceptual example of such a library's layout and the linking process.
* **逻辑推理 (Logical Deduction):**  I can reason about typical I2C usage scenarios, like reading data from a sensor. This helps illustrate how the `i2c_msg` structure is used.
* **用户或者编程常见的使用错误 (Common user/programming errors):** Incorrect address, flag settings, buffer sizes, and not handling errors are all typical pitfalls.
* **android framework or ndk是如何一步步的到达这里 (How Android Framework/NDK reaches here):** This requires tracing the path from high-level Android APIs down to the kernel. The framework interacts with HAL, which then uses ioctl system calls with the structures defined in this header.
* **frida hook示例调试这些步骤 (Frida hook example):** A Frida example demonstrating how to intercept the `ioctl` system call with the relevant I2C command is a powerful way to illustrate debugging.

**5. Structuring the Answer:**

A logical flow is essential for clarity. I decided to organize the answer as follows:

* **Introduction:** Briefly explain the file and its context.
* **功能 (Functions):** Clarify that it defines data structures and constants, not actual functions.
* **与 Android 的关系 (Relationship with Android):** Explain the role of HAL and NDK.
* **libc 函数的实现 (libc Function Implementation):** Focus on the system calls and how libc provides wrappers.
* **Dynamic Linker:** Explain how *other* libraries using this header are linked.
* **逻辑推理 (Logical Deduction):** Provide a concrete example of I2C communication.
* **常见用户错误 (Common User Errors):** List potential mistakes.
* **Android Framework/NDK 到达这里的路径 (Path from Framework/NDK):** Trace the call stack.
* **Frida Hook 示例 (Frida Hook Example):** Provide a practical debugging example.

**6. Refining the Language:**

Using clear and precise Chinese is crucial. I aimed for a balance between technical accuracy and readability. For instance, explaining the difference between a header file defining structures and actual C functions is important.

**7. Self-Correction/Refinement during Thought Process:**

* **Initial thought:** Focus too much on libc *functions* within this header.
* **Correction:** Realize this is a kernel UAPI header, so the interaction is primarily through *system calls*.
* **Initial thought:**  Directly link this header to the dynamic linker.
* **Correction:**  Clarify that it's the libraries *using* these definitions that are dynamically linked. The header itself is just a declaration.
* **Initial thought:** Provide complex, low-level C code examples.
* **Correction:** Focus on explaining the *concepts* and provide a high-level Frida hook example for debugging.

By following this structured thinking process and constantly refining my understanding of the request and the provided code, I could generate a comprehensive and accurate answer.
这是一个定义 Linux 内核用户空间 API 的头文件，专门用于与 I2C (Inter-Integrated Circuit) 总线进行通信。由于它位于 `bionic/libc/kernel/uapi/linux/` 路径下，说明 Android 的 C 库 Bionic 提供了对这些内核接口的封装，使得用户空间的应用程序可以通过 Bionic 库来访问和控制 I2C 设备。

**它的功能：**

这个头文件定义了以下关键的结构体和宏，用于在用户空间和 Linux 内核 I2C 驱动之间传递信息：

1. **`struct i2c_msg`**:  定义了 I2C 消息的结构。一个 I2C 事务可以包含一个或多个这样的消息。
    *   `addr`:  7 位或 10 位 I2C 从设备地址。
    *   `flags`:  控制消息行为的标志位。
        *   `I2C_M_RD`:  表示这是一条读消息。
        *   `I2C_M_TEN`: 表示使用 10 位地址。
        *   `I2C_M_DMA_SAFE`:  指示缓冲区可以安全地用于 DMA。
        *   `I2C_M_RECV_LEN`: 用于接收长度未知的 I2C 块读操作。
        *   `I2C_M_NO_RD_ACK`:  读操作时不发送 ACK (应答)。
        *   `I2C_M_IGNORE_NAK`:  忽略 NAK (非应答)。
        *   `I2C_M_REV_DIR_ADDR`:  反转方向位的地址（用于某些特定设备）。
        *   `I2C_M_NOSTART`:  在消息开始时不发送 START 位（用于重复启动）。
        *   `I2C_M_STOP`:  在消息结束时发送 STOP 位。
    *   `len`:  消息中数据的长度（字节）。
    *   `buf`:  指向消息数据的缓冲区指针。

2. **`I2C_FUNC_` 开头的宏**:  定义了 I2C 适配器（控制器）支持的功能。用户空间程序可以通过 ioctl 系统调用来查询适配器支持的功能，从而确定它能执行哪些 I2C 操作。
    *   例如，`I2C_FUNC_I2C` 表示基本的 I2C 传输功能，`I2C_FUNC_10BIT_ADDR` 表示支持 10 位 I2C 地址，而 `I2C_FUNC_SMBUS_*` 开头的宏定义了对 SMBus (System Management Bus，一种基于 I2C 的协议) 的支持。

3. **`union i2c_smbus_data`**:  定义了用于 SMBus 通信的数据联合体，可以表示一个字节、一个字或者一个数据块。

4. **`I2C_SMBUS_` 开头的宏**:  定义了 SMBus 通信的类型，例如读/写操作、快速命令、字节数据读写、字数据读写、块数据读写等。

**与 Android 功能的关系及举例说明：**

这个头文件是 Android 系统底层硬件交互的基础。Android 设备上有很多硬件组件通过 I2C 总线进行通信，例如：

*   **传感器 (Sensors)**： 陀螺仪、加速度计、磁力计、光线传感器、接近传感器等，通常使用 I2C 与主处理器通信。Android Framework 中的 Sensor Service 通过 HAL (Hardware Abstraction Layer) 调用底层的 I2C 驱动来读取传感器数据。
*   **触摸屏控制器 (Touchscreen Controller)**： 一些触摸屏控制器也使用 I2C 与主处理器通信，报告触摸事件。
*   **摄像头模组 (Camera Module)**：  摄像头模组中的某些控制芯片可能通过 I2C 进行配置和控制。
*   **电源管理芯片 (Power Management IC, PMIC)**： PMIC 通常使用 I2C 来控制电压、电流等，并报告电源状态。

**举例说明:**

假设一个 Android 应用需要读取环境光线传感器的数值。

1. **Android Framework (Java):**  应用程序通过 SensorManager 获取光线传感器对象。
2. **Android HAL (C/C++):**  SensorManager 调用对应的 HAL 模块 (例如 `lightsensor.so`)。
3. **Native 代码 (C/C++):**  HAL 模块会打开 I2C 设备文件 (例如 `/dev/i2c-0`)，并使用 `ioctl` 系统调用来与 I2C 设备通信。在 `ioctl` 调用中，会使用到 `struct i2c_msg` 结构体来构造 I2C 读操作，指定传感器的 I2C 地址、寄存器地址、读取的数据长度等。  `#include <linux/i2c.h>` (或类似的路径)  会将这里定义的结构体和宏包含进来。
4. **Linux Kernel (C):**  内核的 I2C 驱动接收到 `ioctl` 调用，解析 `i2c_msg` 结构体，然后控制 I2C 控制器硬件发出相应的 I2C 信号，与光线传感器进行通信。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身 **并没有定义任何 libc 函数**。它定义的是内核 API 使用的数据结构和宏。libc (Bionic) 提供的与 I2C 交互的功能通常是通过封装 **系统调用** 来实现的，例如 `open()`, `close()`, `ioctl()`。

*   **`open()`**:  用于打开 I2C 设备文件 (例如 `/dev/i2c-0`)，返回一个文件描述符，后续的操作将基于这个文件描述符进行。`open()` 函数的具体实现涉及到内核的 VFS (Virtual File System) 层和设备驱动模型。
*   **`close()`**: 用于关闭打开的 I2C 设备文件，释放相关的内核资源。
*   **`ioctl()`**:  这是一个通用的输入/输出控制系统调用，用于执行设备特定的操作。对于 I2C 设备，`ioctl()` 可以用来发送 I2C 消息、获取适配器功能等。`ioctl()` 的实现涉及到将用户空间的命令和数据传递到内核空间，然后由相应的设备驱动程序进行处理。对于 I2C 驱动，`ioctl()` 会根据传入的命令 (例如 `I2C_RDWR`) 和数据结构 (例如 `struct i2c_rdwr_ioctl_data`) 来执行 I2C 传输。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身并不直接涉及 dynamic linker。Dynamic linker 负责将共享库加载到进程的地址空间，并解析库之间的符号依赖关系。  与 I2C 相关的动态链接发生在使用了 I2C 功能的共享库中，例如 Android 的 HAL 模块。

**so 布局样本 (假设一个名为 `lightsensor.so` 的 HAL 模块):**

```
lightsensor.so:
    .text        # 代码段
        # ... 实现 HAL 接口的代码，可能调用了 open(), ioctl() 等 libc 函数来访问 I2C
    .rodata      # 只读数据段
        # ... 常量数据
    .data        # 可写数据段
        # ... 全局变量
    .bss         # 未初始化数据段
        # ... 未初始化的全局变量
    .dynamic     # 动态链接信息
        NEEDED libc.so  # 依赖 libc.so
        SONAME lightsensor.so
        # ... 其他动态链接信息
    .symtab      # 符号表
        # ... 定义的符号 (函数名、变量名等)
    .strtab      # 字符串表
        # ... 符号名称字符串
    .rel.dyn     # 动态重定位表
        # ... 记录需要在加载时进行重定位的信息，例如对 libc.so 中函数的引用
    .rel.plt     # PLT (Procedure Linkage Table) 重定位表
        # ... 用于延迟绑定
```

**链接的处理过程:**

1. 当 Android 系统加载 `lightsensor.so` 时，dynamic linker (例如 `linker64` 或 `linker`) 会被调用。
2. Dynamic linker 首先读取 `lightsensor.so` 的 `.dynamic` 段，获取其依赖的共享库列表 (例如 `libc.so`)。
3. Dynamic linker 会尝试找到并加载这些依赖库。
4. Dynamic linker 会解析 `lightsensor.so` 中的重定位信息 (`.rel.dyn` 和 `.rel.plt`)。这些信息指示了 `lightsensor.so` 中对外部符号 (例如 `open`, `ioctl`) 的引用。
5. Dynamic linker 会在已加载的共享库 (例如 `libc.so`) 的符号表中查找这些外部符号的地址。
6. Dynamic linker 会更新 `lightsensor.so` 的代码和数据段，将对外部符号的引用指向实际的地址。这个过程称为 **重定位**。
7. 对于通过 PLT 调用的函数 (通常是延迟绑定的)，第一次调用时会触发 dynamic linker 解析符号地址并更新 PLT 表项。后续调用将直接跳转到已解析的地址。

**如果做了逻辑推理，请给出假设输入与输出：**

假设用户空间程序需要读取 I2C 地址 `0x50` 上的一个字节的数据。

**假设输入：**

*   I2C 设备文件描述符 `fd` 已打开。
*   需要读取的从设备地址 `addr = 0x50`。
*   读取操作的标志 `flags = I2C_M_RD`。
*   读取数据的长度 `len = 1`。
*   一个用于存放读取数据的缓冲区 `buf`。

**逻辑推理过程 (构建 `struct i2c_msg`):**

1. 创建一个 `struct i2c_msg` 结构体。
2. 设置 `msg.addr = 0x50`。
3. 设置 `msg.flags = I2C_M_RD`。
4. 设置 `msg.len = 1`。
5. 设置 `msg.buf` 指向用户空间的缓冲区。

**ioctl 调用:**

用户空间程序会调用 `ioctl(fd, I2C_RDWR, &rds)`，其中 `rds` 是一个 `struct i2c_rdwr_ioctl_data` 结构体，包含了要发送的 `i2c_msg` 数组。

**假设输出 (如果 I2C 设备工作正常):**

*   `ioctl` 调用成功返回 `0`。
*   `buf` 缓冲区中包含从 I2C 设备读取的一个字节的数据。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **错误的 I2C 地址:**  使用了错误的从设备地址，导致无法与目标设备通信。
    ```c
    struct i2c_msg msgs[1];
    msgs[0].addr = 0x51; // 正确地址是 0x50
    msgs[0].flags = I2C_M_RD;
    msgs[0].len = 1;
    // ...
    ioctl(fd, I2C_RDWR, &rds); // 可能导致错误，设备无响应
    ```

2. **未正确设置 `I2C_M_RD` 标志:**  尝试读取数据但未设置 `I2C_M_RD` 标志。
    ```c
    struct i2c_msg msgs[1];
    msgs[0].addr = 0x50;
    msgs[0].flags = 0; // 缺少 I2C_M_RD
    msgs[0].len = 1;
    // ...
    ioctl(fd, I2C_RDWR, &rds); // 可能导致错误，内核或设备驱动无法理解操作意图
    ```

3. **缓冲区大小不足:**  读取操作请求的字节数超过了提供的缓冲区大小，导致内存访问错误。
    ```c
    uint8_t buffer[1];
    struct i2c_msg msgs[1];
    msgs[0].addr = 0x50;
    msgs[0].flags = I2C_M_RD;
    msgs[0].len = 2; // 尝试读取 2 个字节
    msgs[0].buf = buffer;
    // ...
    ioctl(fd, I2C_RDWR, &rds); // 可能导致缓冲区溢出
    ```

4. **没有处理 `ioctl` 的返回值:**  `ioctl` 调用可能失败 (返回 `-1`)，但程序没有检查返回值并处理错误，导致后续操作基于错误的数据进行。
    ```c
    int ret = ioctl(fd, I2C_RDWR, &rds);
    if (ret < 0) {
        perror("ioctl error"); // 应该处理错误
    }
    ```

5. **忘记打开 I2C 设备文件:**  在调用 `ioctl` 之前没有使用 `open()` 打开 I2C 设备文件。
    ```c
    int fd; // fd 没有被赋值
    // ...
    ioctl(fd, I2C_RDWR, &rds); // 使用了未初始化的文件描述符，导致错误
    ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达这里的路径：**

1. **Android Framework (Java):**  应用程序通过 Android Framework 提供的 API 与硬件交互，例如 `android.hardware.SensorManager` 获取传感器数据。
2. **Android Framework (Native - JNI):**  Framework 的 Java 代码会调用 Native 代码 (C/C++)，通常通过 JNI (Java Native Interface) 实现。例如，Sensor Service 的 Native 实现。
3. **Hardware Abstraction Layer (HAL):**  Native 代码会与 HAL 模块进行交互。HAL 提供了一组标准的接口，用于访问硬件功能。例如，对于传感器，可能会调用 `ASensorDevice::poll()` 方法。HAL 模块通常以 `.so` 文件的形式存在，例如 `sensorservice.so` 和特定的传感器 HAL 模块 `lightsensor.so`。
4. **HAL Implementation (C/C++):** HAL 模块的实现会打开 I2C 设备文件 (例如 `/dev/i2c-0`)，并使用 `ioctl()` 系统调用来与 I2C 设备通信。这里会用到 `linux/i2c.h` 中定义的结构体和宏。
5. **Bionic libc:**  `open()` 和 `ioctl()` 等系统调用是由 Bionic libc 提供的封装函数。
6. **Linux Kernel:**  Bionic libc 中的系统调用最终会陷入内核，由内核的 I2C 驱动程序处理。

**Frida Hook 示例调试步骤：**

以下是一个使用 Frida Hook 拦截 `ioctl` 系统调用的示例，可以用于观察 Android 系统如何与 I2C 设备进行交互：

```python
import frida
import sys

# 要 Hook 的进程名称
package_name = "com.example.myapp" # 替换为你的应用包名

# Frida 脚本
script_code = """
Interceptor.attach(Module.getExportByName(null, "ioctl"), {
    onEnter: function (args) {
        const fd = args[0].toInt3d();
        const request = args[1].toInt32();
        const argp = args[2];

        // 打印文件描述符和 ioctl 命令
        console.log("ioctl called with fd:", fd, "request:", request.toString(16));

        // 如果是 I2C_RDWR 命令，尝试解析 i2c_rdwr_ioctl_data 结构
        if (request === 0x707) { // I2C_RDWR 的值
            const i2c_rdwr_ptr = ptr(argp);
            const msgs_ptr = i2c_rdwr_ptr.readPointer();
            const nmsgs = i2c_rdwr_ptr.add(Process.pointerSize).readU32();

            console.log("Number of messages:", nmsgs);

            for (let i = 0; i < nmsgs; i++) {
                const msg_ptr = msgs_ptr.add(i * 12); // struct i2c_msg 大小为 12 字节 (addr:2, flags:2, len:2, buf:pointer)
                const addr = msg_ptr.readU16();
                const flags = msg_ptr.add(2).readU16();
                const len = msg_ptr.add(4).readU16();
                const buf_ptr = msg_ptr.add(8).readPointer();

                console.log("  Message", i + 1, "- Addr:", addr.toString(16), "Flags:", flags.toString(16), "Len:", len);

                // 如果是读操作，尝试读取数据
                if (flags & 0x1) { // I2C_M_RD
                    try {
                        const data = buf_ptr.readByteArray(len);
                        console.log("    Read data:", hexdump(data, { ansi: true }));
                    } catch (e) {
                        console.log("    Error reading data:", e);
                    }
                } else {
                    try {
                        const data = buf_ptr.readByteArray(len);
                        console.log("    Write data:", hexdump(data, { ansi: true }));
                    } catch (e) {
                        console.log("    Error reading data:", e);
                    }
                }
            }
        }
    }
});
""";

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(script_code)
    script.load()
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
except Exception as e:
    print(e)
```

**使用步骤：**

1. 确保你的 Android 设备已连接并通过 USB 调试模式连接到电脑。
2. 安装 Frida 和 Python 的 Frida 模块 (`pip install frida-tools`).
3. 将上面的 Python 脚本保存为 `hook_i2c.py` (或其他名字)。
4. 将 `com.example.myapp` 替换为你要调试的 Android 应用的包名。
5. 运行脚本： `python hook_i2c.py`
6. 在你的 Android 设备上操作该应用程序，例如读取传感器数据。
7. Frida 会拦截 `ioctl` 系统调用，并打印相关信息，包括文件描述符、ioctl 命令、I2C 消息的地址、标志、长度以及读写的数据。

这个 Frida 脚本会拦截所有进程的 `ioctl` 调用。为了更精确地调试特定组件，你可能需要找到负责 I2C 通信的进程或库，并将 Hook 目标限定在该进程或库中。 你可以使用 `frida-ps -U` 命令列出正在运行的进程。 你也可以 Hook `open` 系统调用来观察哪些进程打开了 `/dev/i2c-*` 设备文件，从而定位相关的进程。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/i2c.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_I2C_H
#define _UAPI_LINUX_I2C_H
#include <linux/types.h>
struct i2c_msg {
  __u16 addr;
  __u16 flags;
#define I2C_M_RD 0x0001
#define I2C_M_TEN 0x0010
#define I2C_M_DMA_SAFE 0x0200
#define I2C_M_RECV_LEN 0x0400
#define I2C_M_NO_RD_ACK 0x0800
#define I2C_M_IGNORE_NAK 0x1000
#define I2C_M_REV_DIR_ADDR 0x2000
#define I2C_M_NOSTART 0x4000
#define I2C_M_STOP 0x8000
  __u16 len;
  __u8 * buf;
};
#define I2C_FUNC_I2C 0x00000001
#define I2C_FUNC_10BIT_ADDR 0x00000002
#define I2C_FUNC_PROTOCOL_MANGLING 0x00000004
#define I2C_FUNC_SMBUS_PEC 0x00000008
#define I2C_FUNC_NOSTART 0x00000010
#define I2C_FUNC_SLAVE 0x00000020
#define I2C_FUNC_SMBUS_BLOCK_PROC_CALL 0x00008000
#define I2C_FUNC_SMBUS_QUICK 0x00010000
#define I2C_FUNC_SMBUS_READ_BYTE 0x00020000
#define I2C_FUNC_SMBUS_WRITE_BYTE 0x00040000
#define I2C_FUNC_SMBUS_READ_BYTE_DATA 0x00080000
#define I2C_FUNC_SMBUS_WRITE_BYTE_DATA 0x00100000
#define I2C_FUNC_SMBUS_READ_WORD_DATA 0x00200000
#define I2C_FUNC_SMBUS_WRITE_WORD_DATA 0x00400000
#define I2C_FUNC_SMBUS_PROC_CALL 0x00800000
#define I2C_FUNC_SMBUS_READ_BLOCK_DATA 0x01000000
#define I2C_FUNC_SMBUS_WRITE_BLOCK_DATA 0x02000000
#define I2C_FUNC_SMBUS_READ_I2C_BLOCK 0x04000000
#define I2C_FUNC_SMBUS_WRITE_I2C_BLOCK 0x08000000
#define I2C_FUNC_SMBUS_HOST_NOTIFY 0x10000000
#define I2C_FUNC_SMBUS_BYTE (I2C_FUNC_SMBUS_READ_BYTE | I2C_FUNC_SMBUS_WRITE_BYTE)
#define I2C_FUNC_SMBUS_BYTE_DATA (I2C_FUNC_SMBUS_READ_BYTE_DATA | I2C_FUNC_SMBUS_WRITE_BYTE_DATA)
#define I2C_FUNC_SMBUS_WORD_DATA (I2C_FUNC_SMBUS_READ_WORD_DATA | I2C_FUNC_SMBUS_WRITE_WORD_DATA)
#define I2C_FUNC_SMBUS_BLOCK_DATA (I2C_FUNC_SMBUS_READ_BLOCK_DATA | I2C_FUNC_SMBUS_WRITE_BLOCK_DATA)
#define I2C_FUNC_SMBUS_I2C_BLOCK (I2C_FUNC_SMBUS_READ_I2C_BLOCK | I2C_FUNC_SMBUS_WRITE_I2C_BLOCK)
#define I2C_FUNC_SMBUS_EMUL (I2C_FUNC_SMBUS_QUICK | I2C_FUNC_SMBUS_BYTE | I2C_FUNC_SMBUS_BYTE_DATA | I2C_FUNC_SMBUS_WORD_DATA | I2C_FUNC_SMBUS_PROC_CALL | I2C_FUNC_SMBUS_WRITE_BLOCK_DATA | I2C_FUNC_SMBUS_I2C_BLOCK | I2C_FUNC_SMBUS_PEC)
#define I2C_FUNC_SMBUS_EMUL_ALL (I2C_FUNC_SMBUS_EMUL | I2C_FUNC_SMBUS_READ_BLOCK_DATA | I2C_FUNC_SMBUS_BLOCK_PROC_CALL)
#define I2C_SMBUS_BLOCK_MAX 32
union i2c_smbus_data {
  __u8 byte;
  __u16 word;
  __u8 block[I2C_SMBUS_BLOCK_MAX + 2];
};
#define I2C_SMBUS_READ 1
#define I2C_SMBUS_WRITE 0
#define I2C_SMBUS_QUICK 0
#define I2C_SMBUS_BYTE 1
#define I2C_SMBUS_BYTE_DATA 2
#define I2C_SMBUS_WORD_DATA 3
#define I2C_SMBUS_PROC_CALL 4
#define I2C_SMBUS_BLOCK_DATA 5
#define I2C_SMBUS_I2C_BLOCK_BROKEN 6
#define I2C_SMBUS_BLOCK_PROC_CALL 7
#define I2C_SMBUS_I2C_BLOCK_DATA 8
#endif
```