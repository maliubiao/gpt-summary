Response:
Let's break down the thought process to answer the user's request about the `pmu.h` header file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of this header file, its relationship to Android, how its functions are implemented (especially libc and dynamic linker aspects), potential usage errors, and how Android code reaches it, along with Frida hooking examples.

**2. Initial Analysis of the Header File:**

* **Auto-generated:** The comment at the top is crucial. It immediately tells us this isn't manually written code but rather a generated file based on some other definition (likely a kernel header). This impacts how we discuss implementation details. We won't find C code *here*.
* **`#ifndef _UAPI_LINUX_PMU_H`:** This is a standard include guard, preventing multiple inclusions.
* **`#define PMU_DRIVER_VERSION 2`:** A version number for the PMU driver interface.
* **`#define PMU_... 0x...`:**  A large number of `#define` directives. These are preprocessor macros that define symbolic names for numerical constants (likely register addresses or bitmasks). This strongly suggests interaction with hardware.
* **`enum { ... }`:** Enumerated types defining possible values for PMU states, modes, and events.
* **`#include <linux/ioctl.h>`:**  This is a *major* clue. `ioctl` is the standard Linux system call for device-specific control operations. This confirms that the PMU is being treated as a device driver.
* **`#define PMU_IOC_... _IO(...)`, `_IOR(...)`, `_IOW(...)`:** These are macros related to `ioctl`. They define specific `ioctl` commands with associated request types (none, read, write) and data sizes.

**3. Deconstructing the Request - and Forming a Plan:**

Now, let's address each part of the user's request systematically:

* **功能 (Functionality):**  The core functionality is clearly related to *Power Management Unit* (PMU) control. The `#define` and `enum` values indicate operations like setting/getting backlight, reading battery status, initiating shutdown, controlling I2C, etc.

* **与 Android 的关系 (Relationship to Android):**  Since this is part of the Android bionic library (specifically the kernel UAPI part), it's a *low-level* interface to the hardware PMU. Android's power management framework (Java layer, native services) will eventually use these lower-level interfaces. We need to illustrate this with examples like setting screen brightness.

* **libc 函数实现 (libc Function Implementation):** This is where the "auto-generated" comment is key. *This file doesn't contain libc function implementations.*  The implementation will be in the kernel driver. The *libc* part comes into play when user-space Android code *uses* the `ioctl` system call with these defined `PMU_IOC_*` constants. We need to explain how `ioctl` works.

* **dynamic linker 功能 (dynamic linker Functionality):**  This header file itself doesn't directly involve the dynamic linker. The dynamic linker is responsible for loading shared libraries. However, *code that uses* this header might reside in a shared library. We need to provide a general example of a shared library layout and how it's linked. The *connection* is that if a native Android component interacts with the PMU, that component is likely a shared library.

* **逻辑推理 (Logical Inference):** We can infer the purpose of specific constants and enums based on their names (e.g., `PMU_SHUTDOWN`, `PMU_BATTERY_STATE`). We can create hypothetical input/output scenarios for `ioctl` calls.

* **用户/编程常见错误 (Common User/Programming Errors):**  Incorrect `ioctl` usage is a primary error – wrong command code, incorrect data size, permission issues.

* **Android framework/NDK 到达这里 (Android Framework/NDK path):**  We need to trace the path from the high-level framework (e.g., `PowerManager` in Java) down to the native layer and eventually to the `ioctl` system call using the constants defined here.

* **Frida hook 示例 (Frida Hook Example):**  Since the interaction happens via `ioctl`, we need to show how to hook the `ioctl` system call and filter for calls related to the PMU.

**4. Structuring the Answer:**

A logical flow for the answer would be:

1. **Introduction:** State what the file is and its purpose.
2. **Functionality:** List the main categories of PMU operations.
3. **Relationship to Android:** Explain the connection to Android's power management and provide examples.
4. **libc Function Implementation:**  Crucially, clarify that the *implementation* is in the kernel, not *this* file. Explain how `ioctl` works as the bridge.
5. **Dynamic Linker:** Explain that the file itself isn't part of the dynamic linker but that code using it might be in shared libraries. Provide a generic SO layout and linking explanation.
6. **Logical Inference:** Give examples of inferring the purpose of constants.
7. **Common Errors:** List typical mistakes.
8. **Android Framework/NDK Path:** Detail the steps from Java to native code and `ioctl`.
9. **Frida Hook:** Provide a practical Frida example.

**5. Refining the Language and Detail:**

Throughout the process, it's important to use clear and precise Chinese, explaining technical terms. Provide concrete examples where possible. For instance, when discussing the Android framework, mention specific classes like `PowerManager`. For `ioctl`, explain the arguments.

By following this thought process, systematically addressing each part of the user's request and considering the technical details of the header file, we can construct a comprehensive and accurate answer. The key insight is recognizing that this header file is an interface definition, not the implementation itself.
这是一个定义 Linux PMU (Power Management Unit) 用户空间 API 的头文件，用于 Android 系统。它定义了一些常量、宏和枚举，用于与 PMU 硬件进行交互。PMU 负责管理设备的电源，包括电压调节、电池管理、睡眠模式控制等。由于该文件位于 `bionic/libc/kernel/uapi/linux/` 目录下，这意味着它是从 Linux 内核头文件中复制过来的，供用户空间程序使用。

**功能列举:**

这个头文件定义了以下主要功能相关的常量和宏：

1. **PMU 驱动版本:** `PMU_DRIVER_VERSION 2` 定义了 PMU 驱动的接口版本。

2. **电源控制:**
   - `PMU_POWER_CTRL0`, `PMU_POWER_CTRL`:  可能用于控制电源状态。
   - `PMU_POW0_ON`, `PMU_POW0_OFF`, `PMU_POW_ON`, `PMU_POW_OFF`:  用于打开或关闭特定电源域，例如硬盘、背光灯、充电器等。
   - `PMU_SLEEP`:  用于使系统进入睡眠模式。
   - `PMU_SHUTDOWN`:  用于关闭系统。
   - `PMU_RESET`:  用于重启系统。

3. **ADB 控制:**
   - `PMU_ADB_CMD`, `PMU_ADB_POLL_OFF`:  可能用于控制通过 ADB (Android Debug Bridge) 进行的通信。

4. **存储访问:**
   - `PMU_WRITE_XPRAM`, `PMU_WRITE_NVRAM`:  用于写入 XPRAM 和 NVRAM (非易失性随机访问存储器)。
   - `PMU_READ_XPRAM`, `PMU_READ_NVRAM`:  用于读取 XPRAM 和 NVRAM。

5. **实时时钟 (RTC):**
   - `PMU_SET_RTC`:  用于设置 RTC 时间。
   - `PMU_READ_RTC`:  用于读取 RTC 时间。

6. **按键控制:**
   - `PMU_SET_VOLBUTTON`:  可能用于设置音量按钮状态。
   - `PMU_GET_VOLBUTTON`:  用于获取音量按钮状态。
   - `PMU_GET_BRIGHTBUTTON`: 用于获取亮度调节按钮状态。

7. **背光控制:**
   - `PMU_BACKLIGHT_BRIGHT`:  用于控制背光亮度。

8. **弹出控制:**
   - `PMU_PCEJECT`:  可能用于控制 PC 卡弹出。

9. **电池状态:**
   - `PMU_BATTERY_STATE`:  用于获取基本的电池状态。
   - `PMU_SMART_BATTERY_STATE`:  用于获取更详细的智能电池状态。

10. **中断控制:**
    - `PMU_SET_INTR_MASK`:  用于设置中断屏蔽。
    - `PMU_INT_ACK`:  用于应答中断。
    - `PMU_INT_PCEJECT`, `PMU_INT_SNDBRT`, `PMU_INT_ADB`, `PMU_INT_BATTERY`, `PMU_INT_ENVIRONMENT`, `PMU_INT_TICK`, `PMU_INT_ADB_AUTO`, `PMU_INT_WAITING_CHARGER`, `PMU_INT_AUTO_SRQ_POLL`: 定义了各种中断类型。

11. **CPU 速度:**
    - `PMU_CPU_SPEED`:  可能用于获取或设置 CPU 速度。

12. **电源事件:**
    - `PMU_POWER_EVENTS`:  可能用于获取电源相关的事件。

13. **I2C 通信:**
    - `PMU_I2C_CMD`:  用于发送 I2C 命令。
    - `PMU_I2C_MODE_SIMPLE`, `PMU_I2C_MODE_STDSUB`, `PMU_I2C_MODE_COMBINED`: 定义了 I2C 通信模式。
    - `PMU_I2C_BUS_STATUS`, `PMU_I2C_BUS_SYSCLK`, `PMU_I2C_BUS_POWER`: 定义了 I2C 总线相关状态。
    - `PMU_I2C_STATUS_OK`, `PMU_I2C_STATUS_DATAREAD`, `PMU_I2C_STATUS_BUSY`: 定义了 I2C 通信状态。

14. **其他:**
    - `PMU_GET_COVER`:  可能用于获取设备盖子的状态。
    - `PMU_SYSTEM_READY`:  可能用于指示系统是否准备就绪。
    - `PMU_GET_VERSION`:  用于获取 PMU 的版本信息。

15. **电源开关状态:**
    - `PMU_POW0_HARD_DRIVE`, `PMU_POW_BACKLIGHT`, `PMU_POW_CHARGER`, `PMU_POW_IRLED`, `PMU_POW_MEDIABAY`:  定义了特定硬件设备的电源开关状态。

16. **环境状态:**
    - `PMU_ENV_LID_CLOSED`:  用于指示设备盖子是否关闭。

17. **PMU 型号枚举:**
    - `PMU_UNKNOWN`, `PMU_OHARE_BASED`, `PMU_HEATHROW_BASED`, `PMU_PADDINGTON_BASED`, `PMU_KEYLARGO_BASED`, `PMU_68K_V1`, `PMU_68K_V2`: 定义了不同 PMU 型号。

18. **电源事件类型枚举:**
    - `PMU_PWR_GET_POWERUP_EVENTS`, `PMU_PWR_SET_POWERUP_EVENTS`, `PMU_PWR_CLR_POWERUP_EVENTS`, `PMU_PWR_GET_WAKEUP_EVENTS`, `PMU_PWR_SET_WAKEUP_EVENTS`, `PMU_PWR_CLR_WAKEUP_EVENTS`: 定义了获取和设置电源启动和唤醒事件的类型。
    - `PMU_PWR_WAKEUP_KEY`, `PMU_PWR_WAKEUP_AC_INSERT`, `PMU_PWR_WAKEUP_AC_CHANGE`, `PMU_PWR_WAKEUP_LID_OPEN`, `PMU_PWR_WAKEUP_RING`: 定义了不同的唤醒源。

19. **ioctl 命令:**
    - `PMU_IOC_SLEEP`, `PMU_IOC_GET_BACKLIGHT`, `PMU_IOC_SET_BACKLIGHT`, `PMU_IOC_GET_MODEL`, `PMU_IOC_HAS_ADB`, `PMU_IOC_CAN_SLEEP`, `PMU_IOC_GRAB_BACKLIGHT`:  定义了与 PMU 驱动进行交互的 `ioctl` (input/output control) 命令。这些命令允许用户空间程序向内核 PMU 驱动发送控制指令或获取信息。

**与 Android 功能的关系及举例说明:**

这个头文件直接关联着 Android 设备的电源管理功能。Android Framework 或 NDK 中的相关组件会使用这里定义的常量和 `ioctl` 命令与底层的 PMU 驱动进行通信，从而实现各种电源管理相关的操作。

**举例说明:**

* **屏幕亮度控制:** 当用户在 Android 设置中调节屏幕亮度时，Android Framework 会调用相应的 native 代码。native 代码最终会通过 `ioctl` 系统调用，使用 `PMU_IOC_SET_BACKLIGHT` 命令和相应的亮度值来设置 PMU 的背光亮度寄存器，从而改变屏幕亮度。

* **设备休眠与唤醒:** 当设备进入休眠状态时，Android 系统会通过 PMU 控制硬件进入低功耗模式。唤醒事件（例如按下电源键）会触发 PMU 的中断，PMU 驱动会通知 Android 系统，从而唤醒设备。这里 `PMU_SLEEP` 和 `PMU_PWR_WAKEUP_KEY` 等常量就发挥了作用。

* **电池状态显示:**  Android 系统中的电池管理服务会定期读取电池信息，例如电量、充电状态等。这可以通过 `ioctl` 调用，使用 `PMU_IOC_GET_MODEL` 或其他相关的命令来获取 PMU 提供的电池状态信息。

* **ADB 功能:**  `PMU_ADB_CMD` 和 `PMU_ADB_POLL_OFF` 等常量可能用于控制 ADB 连接的电源状态，例如在某些情况下，PMU 可以控制 ADB 的开关。

**libc 函数的功能实现:**

这个头文件本身 **并不包含 libc 函数的实现**。它只是定义了一些宏和常量，用于用户空间程序与内核驱动进行交互。

真正的功能实现位于 Linux 内核的 PMU 驱动程序中。用户空间的程序（例如 Android Framework 的 native 组件）会使用 `ioctl` 系统调用，并带上这里定义的 `PMU_IOC_*` 命令和相关参数，来与内核驱动进行通信。

当用户空间程序调用 `ioctl` 时，系统会进行以下步骤：

1. **系统调用:** 用户空间程序通过 libc 提供的 `ioctl` 函数发起系统调用。
2. **内核处理:** 内核接收到 `ioctl` 系统调用，并根据传入的文件描述符（通常是打开的 PMU 设备节点，例如 `/dev/pmu`）和命令码（例如 `PMU_IOC_SET_BACKLIGHT`）来找到对应的设备驱动程序。
3. **驱动处理:** PMU 驱动程序接收到 `ioctl` 请求，并根据命令码执行相应的操作。这通常涉及到读写 PMU 硬件的寄存器。
4. **结果返回:** 驱动程序将操作结果返回给内核，内核再将结果返回给用户空间程序。

**涉及 dynamic linker 的功能:**

这个头文件本身 **不直接涉及 dynamic linker 的功能**。Dynamic linker (例如 Android 中的 `linker64` 或 `linker`) 负责在程序启动时加载共享库，并解析符号引用。

然而，使用这个头文件的代码 **可能会存在于共享库中**。例如，负责电源管理的 Android 系统服务可能被编译成一个共享库。

**so 布局样本:**

假设一个名为 `libpower.so` 的共享库使用了 `pmu.h` 中定义的常量和 `ioctl` 命令：

```
libpower.so:
  LOAD           0x00000000  0x00000000  0x0001000  R E
  LOAD           0x00001000  0x00001000  0x0000100  RW
  ... (其他段)

  .text          (代码段，包含调用 ioctl 的函数)
  .rodata        (只读数据段，可能包含 PMU 相关的常量)
  .data          (可写数据段)
  .bss           (未初始化数据段)
  .dynamic       (动态链接信息)
  .symtab        (符号表)
  .strtab        (字符串表)
  .rel.dyn       (动态重定位表)
  .rel.plt       (PLT 重定位表)
```

**链接的处理过程:**

1. **编译时:** 当编译 `libpower.so` 的源代码时，编译器会识别出对 `ioctl` 函数的调用。由于 `ioctl` 是 libc 的一部分，编译器会生成对 `ioctl` 的外部符号引用。同时，`pmu.h` 中定义的宏会在编译时被替换为相应的数值。

2. **链接时:** 静态链接器将目标文件链接成共享库。它会记录下 `ioctl` 这个未定义的符号，以及其他需要动态链接的符号。

3. **运行时:** 当 Android 系统启动并需要加载 `libpower.so` 时，dynamic linker 会执行以下步骤：
   - **加载共享库:** 将 `libpower.so` 加载到内存中的合适地址。
   - **解析依赖:** 确定 `libpower.so` 依赖于 libc (通常是 `libc.so`)。
   - **加载依赖:** 加载 `libc.so` 到内存。
   - **符号解析 (重定位):**  遍历 `libpower.so` 的重定位表 (`.rel.dyn` 和 `.rel.plt`)，找到对外部符号（例如 `ioctl`）的引用。Dynamic linker 会在 `libc.so` 的符号表 (`.symtab`) 中查找 `ioctl` 的地址，并将该地址填入 `libpower.so` 中相应的位置，从而完成符号的解析和重定位。

**逻辑推理 (假设输入与输出):**

假设我们想通过 `ioctl` 设置背光亮度。

**假设输入:**

* 打开 PMU 设备节点的描述符 `fd`。
* `ioctl` 命令码: `PMU_IOC_SET_BACKLIGHT`
* 背光亮度值: `100` (假设亮度值用整数表示)

**输出:**

* 如果 `ioctl` 调用成功，返回 `0`。
* 如果 `ioctl` 调用失败（例如，权限不足，设备不存在等），返回 `-1`，并设置 `errno` 变量指示错误类型。

**用户或编程常见的使用错误:**

1. **错误的 ioctl 命令码:** 使用了错误的 `PMU_IOC_*` 常量，导致内核驱动无法识别请求。
   ```c
   // 错误地使用了 PMU_IOC_GET_MODEL 来设置背光
   ioctl(fd, PMU_IOC_GET_MODEL, &brightness);
   ```

2. **传递了错误的数据大小或类型:** `ioctl` 命令可能需要特定的数据结构或大小。传递错误的数据会导致内核驱动解析错误或崩溃。
   ```c
   size_t brightness = 100;
   // 假设 PMU_IOC_SET_BACKLIGHT 需要一个 int，传递 size_t 可能导致问题
   ioctl(fd, PMU_IOC_SET_BACKLIGHT, brightness);
   ```

3. **没有正确打开设备节点:** 在调用 `ioctl` 之前，必须先使用 `open` 函数打开 PMU 的设备节点（通常是 `/dev/pmu`），并获得有效的文件描述符。
   ```c
   int fd;
   // 忘记打开设备节点
   // fd = open("/dev/pmu", O_RDWR);
   ioctl(fd, PMU_IOC_SET_BACKLIGHT, &brightness); // fd 未初始化，导致错误
   ```

4. **权限问题:** 用户空间程序可能没有足够的权限访问 PMU 设备节点，导致 `open` 或 `ioctl` 调用失败。

5. **错误的参数顺序或数量:** 某些 `ioctl` 命令可能需要额外的参数。传递错误的参数会导致内核驱动处理错误。

**Android framework or ndk 如何一步步的到达这里:**

1. **Android Framework (Java层):** 用户在界面上进行操作，例如调整屏幕亮度。`android.provider.Settings` 或 `android.os.PowerManager` 等 Java 类会捕获这些操作。

2. **System Server (Java/Native):**  Framework 层会将请求传递给 System Server 中的相关服务，例如 `PowerManagerService`。`PowerManagerService` 通常会调用 native 方法来执行底层的硬件控制。

3. **Native 代码 (NDK):** `PowerManagerService` 会通过 JNI (Java Native Interface) 调用到 native 代码。这部分 native 代码通常是用 C/C++ 编写的，可能位于一个共享库中（例如 `libpower.so`）。

4. **访问 PMU 设备:** Native 代码会使用标准 C 库函数（例如 `open` 和 `ioctl`）来与 PMU 驱动进行交互。

   ```c++
   #include <fcntl.h>
   #include <sys/ioctl.h>
   #include <linux/pmu.h> // 包含 pmu.h 头文件
   #include <unistd.h>
   #include <errno.h>
   #include <stdio.h>

   int set_backlight(int brightness) {
       int fd = open("/dev/pmu", O_RDWR);
       if (fd < 0) {
           perror("open /dev/pmu failed");
           return -1;
       }

       if (ioctl(fd, PMU_IOC_SET_BACKLIGHT, &brightness) < 0) {
           perror("ioctl PMU_IOC_SET_BACKLIGHT failed");
           close(fd);
           return -1;
       }

       close(fd);
       return 0;
   }
   ```

5. **PMU 驱动 (Kernel):** 内核中的 PMU 驱动程序会接收到 `ioctl` 请求，并执行相应的硬件操作，例如修改 PMU 芯片中控制背光的寄存器。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与 PMU 设备相关的调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['message']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(['com.android.systemui']) # Hook SystemUI 进程，可能涉及到电源管理
    session = device.attach(pid)
except frida.TimedOutError:
    print("[-] 无法找到 USB 设备。")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print("[-] 无法找到指定的进程。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var pathname = null;

        // 尝试读取文件路径
        try {
            var pathbuf = Memory.allocUtf8String(256);
            var ret = syscall(frida. platform === 'linux' ? 'readlinkat' : 'GetFinalPathNameByHandleA', -100, pathbuf, 256, 0); // -100 代表 AT_FDCWD
            if (ret > 0) {
                pathname = Memory.readUtf8String(pathbuf);
            }
        } catch (e) {
            // 读取路径可能失败，忽略
        }

        if (pathname && pathname.indexOf("pmu") !== -1) {
            this.is_pmu = true;
            var request_str = '0x' + request.toString(16);
            var argp = args[2];
            var arg_value = null;

            // 尝试读取第三个参数的值 (可能需要根据 request 的类型进行更精确的解析)
            if (request === 0xc0084202 || request === 0x40084201) { // 假设 PMU_IOC_SET_BACKLIGHT 和 PMU_IOC_GET_BACKLIGHT 的值
                arg_value = Memory.readU32(argp);
            }

            send({
                tag: "ioctl (PMU)",
                message: "fd: " + fd + ", request: " + request_str + (arg_value !== null ? ", arg: " + arg_value : "")
            });
        }
    },
    onLeave: function(retval) {
        if (this.is_pmu) {
            send({
                tag: "ioctl (PMU)",
                message: "返回: " + retval
            });
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**代码解释:**

1. **连接 Frida:**  代码首先尝试连接到 USB 设备上的 `com.android.systemui` 进程 (这是一个与系统界面相关的进程，可能涉及到电源管理)。
2. **Hook `ioctl`:** 使用 `Interceptor.attach` 函数 hook 了 `ioctl` 系统调用。
3. **`onEnter`:** 在 `ioctl` 调用进入时执行：
   - 获取文件描述符 `fd` 和请求码 `request`。
   - 尝试通过文件描述符读取对应的文件路径，判断是否涉及到 "pmu"。
   - 如果涉及到 PMU，则打印相关信息，包括文件描述符、请求码以及尝试读取第三个参数的值（这里需要根据具体的 `ioctl` 命令码进行解析）。
4. **`onLeave`:** 在 `ioctl` 调用返回时执行：
   - 如果是 PMU 相关的调用，则打印返回值。

**使用方法:**

1. 将上述 Python 代码保存为 `.py` 文件 (例如 `hook_pmu.py`)。
2. 确保已安装 Frida 和 frida-tools (`pip install frida frida-tools`)。
3. 运行手机上的 Frida 服务。
4. 在 PC 上运行 `python hook_pmu.py`。
5. 在 Android 设备上进行涉及电源管理的操作（例如调节屏幕亮度）。
6. Frida 会打印出与 PMU 相关的 `ioctl` 调用信息，包括请求码和参数，可以帮助你调试和理解 Android 系统如何与 PMU 硬件进行交互。

这个回复详细解释了 `bionic/libc/kernel/uapi/linux/pmu.h` 文件的功能、与 Android 的关系、相关的 libc 和 dynamic linker 概念，并提供了用户错误示例以及 Frida hook 示例，希望能帮助你理解这个文件的作用和使用方式。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/pmu.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_PMU_H
#define _UAPI_LINUX_PMU_H
#define PMU_DRIVER_VERSION 2
#define PMU_POWER_CTRL0 0x10
#define PMU_POWER_CTRL 0x11
#define PMU_ADB_CMD 0x20
#define PMU_ADB_POLL_OFF 0x21
#define PMU_WRITE_XPRAM 0x32
#define PMU_WRITE_NVRAM 0x33
#define PMU_READ_XPRAM 0x3a
#define PMU_READ_NVRAM 0x3b
#define PMU_SET_RTC 0x30
#define PMU_READ_RTC 0x38
#define PMU_SET_VOLBUTTON 0x40
#define PMU_BACKLIGHT_BRIGHT 0x41
#define PMU_GET_VOLBUTTON 0x48
#define PMU_PCEJECT 0x4c
#define PMU_BATTERY_STATE 0x6b
#define PMU_SMART_BATTERY_STATE 0x6f
#define PMU_SET_INTR_MASK 0x70
#define PMU_INT_ACK 0x78
#define PMU_SHUTDOWN 0x7e
#define PMU_CPU_SPEED 0x7d
#define PMU_SLEEP 0x7f
#define PMU_POWER_EVENTS 0x8f
#define PMU_I2C_CMD 0x9a
#define PMU_RESET 0xd0
#define PMU_GET_BRIGHTBUTTON 0xd9
#define PMU_GET_COVER 0xdc
#define PMU_SYSTEM_READY 0xdf
#define PMU_GET_VERSION 0xea
#define PMU_POW0_ON 0x80
#define PMU_POW0_OFF 0x00
#define PMU_POW0_HARD_DRIVE 0x04
#define PMU_POW_ON 0x80
#define PMU_POW_OFF 0x00
#define PMU_POW_BACKLIGHT 0x01
#define PMU_POW_CHARGER 0x02
#define PMU_POW_IRLED 0x04
#define PMU_POW_MEDIABAY 0x08
#define PMU_INT_PCEJECT 0x04
#define PMU_INT_SNDBRT 0x08
#define PMU_INT_ADB 0x10
#define PMU_INT_BATTERY 0x20
#define PMU_INT_ENVIRONMENT 0x40
#define PMU_INT_TICK 0x80
#define PMU_INT_ADB_AUTO 0x04
#define PMU_INT_WAITING_CHARGER 0x01
#define PMU_INT_AUTO_SRQ_POLL 0x02
#define PMU_ENV_LID_CLOSED 0x01
#define PMU_I2C_MODE_SIMPLE 0
#define PMU_I2C_MODE_STDSUB 1
#define PMU_I2C_MODE_COMBINED 2
#define PMU_I2C_BUS_STATUS 0
#define PMU_I2C_BUS_SYSCLK 1
#define PMU_I2C_BUS_POWER 2
#define PMU_I2C_STATUS_OK 0
#define PMU_I2C_STATUS_DATAREAD 1
#define PMU_I2C_STATUS_BUSY 0xfe
enum {
  PMU_UNKNOWN,
  PMU_OHARE_BASED,
  PMU_HEATHROW_BASED,
  PMU_PADDINGTON_BASED,
  PMU_KEYLARGO_BASED,
  PMU_68K_V1,
  PMU_68K_V2,
};
enum {
  PMU_PWR_GET_POWERUP_EVENTS = 0x00,
  PMU_PWR_SET_POWERUP_EVENTS = 0x01,
  PMU_PWR_CLR_POWERUP_EVENTS = 0x02,
  PMU_PWR_GET_WAKEUP_EVENTS = 0x03,
  PMU_PWR_SET_WAKEUP_EVENTS = 0x04,
  PMU_PWR_CLR_WAKEUP_EVENTS = 0x05,
};
enum {
  PMU_PWR_WAKEUP_KEY = 0x01,
  PMU_PWR_WAKEUP_AC_INSERT = 0x02,
  PMU_PWR_WAKEUP_AC_CHANGE = 0x04,
  PMU_PWR_WAKEUP_LID_OPEN = 0x08,
  PMU_PWR_WAKEUP_RING = 0x10,
};
#include <linux/ioctl.h>
#define PMU_IOC_SLEEP _IO('B', 0)
#define PMU_IOC_GET_BACKLIGHT _IOR('B', 1, size_t)
#define PMU_IOC_SET_BACKLIGHT _IOW('B', 2, size_t)
#define PMU_IOC_GET_MODEL _IOR('B', 3, size_t)
#define PMU_IOC_HAS_ADB _IOR('B', 4, size_t)
#define PMU_IOC_CAN_SLEEP _IOR('B', 5, size_t)
#define PMU_IOC_GRAB_BACKLIGHT _IOR('B', 6, size_t)
#endif

"""

```