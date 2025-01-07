Response:
Let's break down the thought process for analyzing this header file.

**1. Initial Scan and Keyword Recognition:**

First, I quickly skimmed the file, looking for recognizable patterns and keywords. I noticed:

* **Copyright/Licensing Comments:**  The "auto-generated" comment and the reference to the Android source code repository immediately signal this is a kernel header file related to Android.
* **Include Directive:** `#include <linux/types.h>` indicates this interacts with the Linux kernel's type system.
* **Macros:** A large number of `#define` directives stood out. These are clearly defining constants.
* **Structure Definition:** The `struct _MGSL_PARAMS` definition signals a data structure.
* **`typedef`:**  The `typedef` for `MGSL_PARAMS` and `PMGSL_PARAMS` is standard C practice.
* **Device IDs:**  Constants like `MICROGATE_VENDOR_ID`, `SYNCLINK_DEVICE_ID`, etc., strongly suggest hardware interaction.
* **Status Codes:**  `DiagStatus_OK`, `DiagStatus_AddressFailure`, etc., hint at some kind of diagnostic or error reporting mechanism.
* **Signal Names:** `SerialSignal_DCD`, `SerialSignal_TXD`, etc., clearly point to serial communication signals.
* **Counter Structure:** `struct mgsl_icount` suggests keeping track of various communication statistics.
* **GPIO Structure:** `struct gpio_desc` indicates interaction with General Purpose Input/Output pins.
* **Debug Levels:**  `DEBUG_LEVEL_DATA`, `DEBUG_LEVEL_ERROR`, etc., are for logging and debugging.
* **Event Flags:**  `MgslEvent_DsrActive`, `MgslEvent_CtsInactive`, etc., suggest an event-driven system.
* **IOCTL Definitions:**  The `#define MGSL_MAGIC_IOC 'm'` and the subsequent `MGSL_IOCS...` lines are clearly Input/Output Control commands, a common way for user-space programs to interact with device drivers in Linux.

**2. Grouping and Categorization:**

Based on the keywords, I started mentally grouping the definitions:

* **Bitmasks:** The `BIT0` to `BIT31` definitions are simply creating bit flags.
* **Size Limits:** `HDLC_MAX_FRAME_SIZE`, `MAX_ASYNC_TRANSMIT`, etc., are defining upper bounds for certain parameters.
* **Enumerated Types (Implicit):**  The `ASYNC_PARITY_NONE`, `ASYNC_PARITY_EVEN`, etc., definitions, while not using an `enum`, effectively create a set of options for asynchronous communication. Similarly for `HDLC_FLAG_...`, `HDLC_CRC_...`, `HDLC_TXIDLE_...`, `HDLC_ENCODING_...`, `HDLC_PREAMBLE_LENGTH_...`, `HDLC_PREAMBLE_PATTERN_...`, `MGSL_MODE_...`, `MGSL_BUS_TYPE_...`, `MGSL_INTERFACE_...`.
* **Data Structures:** `MGSL_PARAMS`, `mgsl_icount`, `gpio_desc`.
* **Constants:** `MICROGATE_VENDOR_ID`, `SYNCLINK_DEVICE_ID`, `MGSL_MAX_SERIAL_NUMBER`, `DiagStatus_...`, `SerialSignal_...`, `DEBUG_LEVEL_...`, `MgslEvent_...`.
* **IOCTLs:** `MGSL_IOCSPARAMS`, `MGSL_IOCGPARAMS`, etc.

**3. Inferring Functionality:**

Now, with the categorized definitions, I started to infer the overall purpose of this header file:

* **Serial Communication:** The abundance of HDLC, Async, and signal-related constants strongly suggests this is related to serial communication protocols.
* **Hardware Interaction:** The device IDs, bus types, and GPIO definitions point towards interaction with specific hardware. The `SYNCLINK` prefix in many names is a clue about the type of hardware.
* **Configuration:** The `MGSL_PARAMS` structure and the `MGSL_IOCSPARAMS` IOCTL indicate a way to configure the serial communication interface (mode, loopback, flags, encoding, baud rate, etc.).
* **Status and Statistics:** `mgsl_icount` and `MGSL_IOCGSTATS` suggest mechanisms to retrieve performance and error information.
* **Event Handling:** The `MgslEvent_...` constants and `MGSL_IOCWAITEVENT` indicate a way for applications to be notified of specific events on the serial line.
* **GPIO Control:**  The `gpio_desc` structure and associated IOCTLs allow for controlling General Purpose Input/Output pins, likely on the associated hardware.

**4. Connecting to Android:**

Knowing this is part of Android's Bionic library, I considered how such a low-level interface would be used:

* **Hardware Abstraction Layer (HAL):**  This header is almost certainly used by a HAL module that provides a higher-level interface for interacting with the specific serial hardware. The framework wouldn't directly use these low-level definitions.
* **NDK (Less Likely but Possible):** While less common for direct hardware interaction, it's *possible* that a very specific NDK library might expose some functionality related to this. However, given the kernel nature, it's more likely confined to the system level.

**5. Dynamic Linker Considerations:**

Since the prompt specifically asked about the dynamic linker, I considered if this header file directly involved it. Header files themselves don't participate in the dynamic linking process in the same way as shared libraries (.so files). However:

* **Usage by Shared Libraries:** The definitions in this header would be used by a shared library (likely the HAL) that *is* dynamically linked.
* **No Direct Linking:**  There are no function declarations or definitions in this header that would be linked against. It's purely definitions.

**6. Example Scenarios and Potential Errors:**

I started thinking about how developers might use (or misuse) the functionality defined here *if* they had direct access (which is unlikely in typical Android app development):

* **Incorrect Parameter Settings:** Setting invalid flags or parameters in `MGSL_PARAMS` would be a common error.
* **Misunderstanding IOCTLs:** Using the wrong IOCTL or passing incorrect data structures could lead to errors.
* **Race Conditions:**  If multiple threads tried to configure or control the serial port simultaneously without proper synchronization, it could cause issues.

**7. Frida Hooking (Conceptual):**

For Frida, I considered *where* these definitions would be used. Since it's a kernel-level interface, the hooks would likely target:

* **Kernel System Calls:** The IOCTLs translate to system calls. Hooking these would be the most direct way to observe the interaction.
* **HAL Implementation:**  Hooking functions within the HAL library that uses these definitions would also be possible, although at a higher level.

**8. Structuring the Response:**

Finally, I organized the information into the requested sections: functionality, relation to Android, libc function explanation (though this header doesn't *define* libc functions), dynamic linker aspects, example usage/errors, and Frida hooking. I made sure to clearly state the limitations – for example, that this header itself doesn't implement libc functions or participate directly in dynamic linking, but its definitions are used by components that do. I also emphasized the kernel-level nature and how user-space access is typically mediated through HALs.
这是一个定义了与 `synclink` 相关的常量、数据结构和 ioctl 命令的头文件。`synclink` 很可能指的是一种同步/异步串行链路通信协议或硬件接口，由 Microgate 公司生产。这个头文件被设计为用户空间程序与 Linux 内核中的 `synclink` 设备驱动程序进行交互的接口。

**它的功能:**

1. **定义位掩码:**  `BIT0` 到 `BIT31` 定义了用于操作位字段的位掩码。
2. **定义通信参数常量:**
   - `HDLC_MAX_FRAME_SIZE`, `MAX_ASYNC_TRANSMIT`, `MAX_ASYNC_BUFFER_SIZE`: 定义了数据帧或缓冲区的大小限制。
   - `ASYNC_PARITY_NONE`, `ASYNC_PARITY_EVEN`, `ASYNC_PARITY_ODD`, `ASYNC_PARITY_SPACE`: 定义了异步通信的校验位类型。
   - `HDLC_FLAG_*`: 定义了 HDLC (高级数据链路控制) 通信的各种标志，例如帧尾处理、自动流控、时钟源等。
   - `HDLC_CRC_*`: 定义了 HDLC 通信的循环冗余校验 (CRC) 类型。
   - `HDLC_TXIDLE_*`: 定义了发送空闲时的填充模式。
   - `HDLC_ENCODING_*`: 定义了数据编码方式。
   - `HDLC_PREAMBLE_LENGTH_*`, `HDLC_PREAMBLE_PATTERN_*`: 定义了前导码的长度和模式。
3. **定义通信模式常量:**
   - `MGSL_MODE_ASYNC`, `MGSL_MODE_HDLC`, `MGSL_MODE_MONOSYNC`, `MGSL_MODE_BISYNC`, `MGSL_MODE_RAW`, `MGSL_MODE_BASE_CLOCK`, `MGSL_MODE_XSYNC`: 定义了不同的通信模式。
4. **定义总线类型常量:**
   - `MGSL_BUS_TYPE_ISA`, `MGSL_BUS_TYPE_EISA`, `MGSL_BUS_TYPE_PCI`: 定义了硬件接口所使用的总线类型。
5. **定义接口类型常量:**
   - `MGSL_INTERFACE_*`: 定义了物理接口类型 (RS232, V35, RS422) 以及相关的控制信号。
6. **定义数据结构:**
   - `MGSL_PARAMS`:  定义了一个结构体，用于设置和获取 `synclink` 设备的各种通信参数。
   - `mgsl_icount`: 定义了一个结构体，用于记录 `synclink` 设备的通信统计信息 (例如发送/接收的字节数、错误数等)。
   - `gpio_desc`: 定义了一个结构体，用于描述和控制设备的 GPIO (通用输入/输出) 引脚的状态。
7. **定义设备 ID 常量:**
   - `MICROGATE_VENDOR_ID`, `SYNCLINK_DEVICE_ID`, `MGSCC_DEVICE_ID`, `SYNCLINK_SCA_DEVICE_ID`, `SYNCLINK_GT_DEVICE_ID`, `SYNCLINK_GT4_DEVICE_ID`, `SYNCLINK_AC_DEVICE_ID`, `SYNCLINK_GT2_DEVICE_ID`:  定义了不同 `synclink` 设备的供应商 ID 和设备 ID。
8. **定义诊断状态常量:**
   - `DiagStatus_*`: 定义了设备诊断的各种状态代码。
9. **定义串行信号常量:**
   - `SerialSignal_*`: 定义了串行通信中常见的信号 (DCD, TXD, RI, RXD, CTS, RTS, DSR, DTR)。
10. **定义调试级别常量:**
    - `DEBUG_LEVEL_*`: 定义了调试信息的级别。
11. **定义事件常量:**
    - `MgslEvent_*`: 定义了可能发生的设备事件，例如信号线的状态变化。
12. **定义 IOCTL 命令:**
    - `MGSL_MAGIC_IOC`: 定义了 IOCTL 命令的魔数。
    - `MGSL_IOCSPARAMS`, `MGSL_IOCGPARAMS`, ..., `MGSL_IOCGXCTRL`: 定义了用于与 `synclink` 设备驱动程序进行通信的各种 IOCTL 命令，用于设置参数、获取状态、发送控制命令等。

**与 Android 功能的关系和举例说明:**

这个头文件位于 `bionic/libc/kernel/uapi/linux/`，说明它是 Android 使用的 Linux 内核 API 的一部分。尽管这个特定的头文件不太可能被直接用于编写常见的 Android 应用程序，但它在以下方面与 Android 功能相关：

* **硬件抽象层 (HAL):** Android 的 HAL 负责抽象底层的硬件细节。与 `synclink` 硬件交互的 HAL 模块很可能会使用这个头文件中定义的常量和数据结构。例如，如果 Android 设备使用了基于 `synclink` 技术的串口通信模块，那么相应的 HAL 可能会使用 `MGSL_PARAMS` 结构体来配置串口的波特率、校验位等，并使用 IOCTL 命令与内核驱动程序进行通信。
* **系统服务:**  某些系统服务可能需要与特定的硬件进行通信，如果该硬件是基于 `synclink` 的，那么这些服务可能会间接地依赖于这个头文件。
* **驱动开发:**  为 Android 开发 `synclink` 设备的内核驱动程序时，会直接使用这个头文件来定义用户空间和内核空间之间通信的接口。

**举例说明:**

假设 Android 设备内部使用了一个 `synclink` 控制器来连接一个特定的传感器或外设。

1. **HAL 层:** 一个名为 `synclink.default.so` 的 HAL 模块可能会使用 `MGSL_IOCSPARAMS` IOCTL 和 `MGSL_PARAMS` 结构体来初始化 `synclink` 控制器的通信参数，例如设置波特率为 115200，无校验位，8 个数据位。

   ```c
   #include <linux/synclink.h>
   #include <sys/ioctl.h>
   #include <fcntl.h>
   #include <unistd.h>

   int fd = open("/dev/synclink0", O_RDWR);
   if (fd < 0) {
       perror("open /dev/synclink0 failed");
       return -1;
   }

   struct MGSL_PARAMS params;
   params.mode = MGSL_MODE_ASYNC;
   params.clock_speed = 0; // 异步模式下不使用
   params.data_rate = 115200;
   params.data_bits = 8;
   params.stop_bits = 1;
   params.parity = ASYNC_PARITY_NONE;

   if (ioctl(fd, MGSL_IOCSPARAMS, &params) < 0) {
       perror("ioctl MGSL_IOCSPARAMS failed");
       close(fd);
       return -1;
   }

   // ... 进行数据收发 ...

   close(fd);
   return 0;
   ```

2. **系统服务层:** 一个管理特定传感器的系统服务可能会调用 HAL 模块提供的接口来读取传感器数据。HAL 模块内部会使用上述代码与 `synclink` 驱动程序通信。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**不包含任何 libc 函数的实现**。它只是定义了常量、数据结构和 IOCTL 命令。`libc` (Bionic) 提供了诸如 `open`, `close`, `ioctl` 等系统调用封装函数，但这些函数的实际实现在内核中。

* **`open()`:**  `open()` 是一个 libc 函数，用于打开一个文件或设备文件。它的实现会发起一个 `open` 系统调用到 Linux 内核。内核根据传入的路径名查找对应的文件系统或设备驱动程序，并建立文件描述符。
* **`close()`:** `close()` 是一个 libc 函数，用于关闭一个打开的文件描述符。它的实现会发起一个 `close` 系统调用到内核，内核会释放与该文件描述符相关的资源。
* **`ioctl()`:** `ioctl()` 是一个 libc 函数，用于向设备驱动程序发送设备特定的控制命令。它的实现会发起一个 `ioctl` 系统调用到内核。内核根据传入的文件描述符和命令号，找到对应的设备驱动程序，并将命令和数据传递给驱动程序的 `ioctl` 处理函数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的作用是在程序启动时加载共享库 (`.so` 文件) 并解析符号依赖关系。

然而，使用这个头文件中定义的常量和数据结构的 HAL 模块（如上面提到的 `synclink.default.so`）是一个共享库，它会被 dynamic linker 加载。

**`synclink.default.so` 的布局样本:**

```
synclink.default.so:
    LOAD           0x00000000  0x00000000  00001000  R E   1000
    LOAD           0x00001000  0x00001000  00000800  R     1000
    LOAD           0x00002000  0x00002000  00000400  RW    1000
    DYNAMIC        0x00002000
    NOTE           0x00000190  0x000001ec  NT_GNU_ABI_TAG
    NOTE           0x000001ec  0x00000024  NT_AOSP_PREBUILT_TYPE
    GNU_HASH       0x00000208
    STRTAB         0x000002a8
    SYMTAB         0x00000490
    VERSYM         0x00000618
    RELA           0x00000660
    RELASZ         0x00000030
    RELAENT        0x00000018
    STRTAB         0x00000690
    SYMTAB         0x00000778
    VERSYM         0x000008e0
    VERNEED        0x00000910
    VERNEEDNUM     0x00000001
```

**链接的处理过程:**

1. **加载:** 当一个需要 `synclink.default.so` 的进程启动时，dynamic linker 会根据程序的依赖关系找到 `synclink.default.so` 文件。
2. **内存映射:** dynamic linker 将 `.so` 文件的不同段 (如代码段 `.text`、只读数据段 `.rodata`、可读写数据段 `.data`) 映射到进程的地址空间。
3. **符号解析:**  `synclink.default.so` 可能会调用 Bionic libc 中的函数 (例如 `open`, `ioctl`)。Dynamic linker 会解析这些符号依赖，确保 `synclink.default.so` 中对这些函数的调用能正确链接到 Bionic libc 中对应的函数地址。同样，如果其他共享库依赖于 `synclink.default.so` 提供的符号，dynamic linker 也会处理这些依赖关系。
4. **重定位:**  由于共享库被加载到进程的任意地址空间，dynamic linker 需要修改 `.so` 文件中的某些地址引用，使其指向正确的内存位置。

**如果做了逻辑推理，请给出假设输入与输出:**

这个头文件本身主要是常量定义，不涉及复杂的逻辑推理。逻辑推理通常发生在使用了这些定义的代码中，例如驱动程序或 HAL 模块。

**假设输入与输出示例 (HAL 模块中的代码):**

假设一个 HAL 函数需要根据配置字符串设置 `synclink` 设备的通信模式。

**假设输入:**  配置字符串 "mode=hdlc,crc=ccitt"

**逻辑推理:** HAL 代码会解析这个字符串：
   - 识别出 "mode" 参数为 "hdlc"，对应 `MGSL_MODE_HDLC`。
   - 识别出 "crc" 参数为 "ccitt"，对应 `HDLC_CRC_16_CCITT`。

**输出 (ioctl 调用):**  HAL 代码会构造 `MGSL_PARAMS` 结构体，并将 `mode` 字段设置为 `MGSL_MODE_HDLC`，`crc_type` 字段设置为 `HDLC_CRC_16_CCITT`，然后调用 `ioctl(fd, MGSL_IOCSPARAMS, &params)`。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的 IOCTL 命令号:**  使用了错误的 `ioctl` 命令号，例如将 `MGSL_IOCSPARAMS` 误写成其他值，会导致内核返回错误。
2. **传递错误的数据结构:**  传递给 `ioctl` 的数据结构 (`MGSL_PARAMS`, `gpio_desc`) 中的字段设置了无效的值，例如波特率设置为 0 或校验位类型设置为不支持的值。
3. **忘记打开设备文件:**  在调用 `ioctl` 之前没有使用 `open()` 打开对应的设备文件 (`/dev/synclinkX`)。
4. **权限不足:**  尝试操作 `synclink` 设备的用户没有足够的权限。
5. **并发访问冲突:** 多个进程或线程同时尝试配置或控制同一个 `synclink` 设备，可能导致状态混乱。
6. **未处理 `ioctl` 返回的错误:**  调用 `ioctl` 后没有检查返回值，忽略了可能发生的错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤 (间接):**

1. **应用程序 (Java/Kotlin):**  一个应用程序可能需要使用连接到 `synclink` 设备的硬件功能（例如一个特殊的传感器）。
2. **Android Framework API:** 应用程序会调用 Android Framework 提供的相关 API，这些 API 通常位于 `android.hardware` 包下。
3. **HAL Interface Definition Language (HIDL) 或 Android Interface Definition Language (AIDL):** Framework API 的实现会调用对应的 HAL 接口。这些接口使用 HIDL 或 AIDL 定义。
4. **HAL Implementation (.so):**  具体的 HAL 模块（例如 `synclink.default.so`）实现了这些 HAL 接口。HAL 模块的代码会包含 C/C++ 代码，并会包含 `<linux/synclink.h>` 头文件。
5. **系统调用 (通过 Bionic libc):**  HAL 模块中的代码会使用 Bionic libc 提供的系统调用封装函数 (如 `open`, `ioctl`) 来与 `synclink` 设备驱动程序进行交互。`ioctl` 调用最终会到达内核中的 `synclink` 驱动程序，该驱动程序会处理通过 `MGSL_IOC*` 命令传递的参数。

**NDK 到达这里的步骤 (更直接，但较少见):**

1. **NDK 应用程序 (C/C++):** 一个使用 NDK 开发的应用程序可以直接访问底层的 Linux API。
2. **Bionic libc:** NDK 应用程序可以使用 Bionic libc 提供的函数，例如 `open`, `ioctl`。
3. **系统调用:**  类似于 HAL 模块，NDK 应用程序通过 Bionic libc 发起系统调用来与 `synclink` 驱动程序交互。

**Frida Hook 示例:**

以下是一个使用 Frida hook `ioctl` 系统调用的示例，用于观察与 `synclink` 相关的 IOCTL 调用。

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
    pid = device.spawn(["com.example.myapp"]) # 替换为目标应用的包名
    session = device.attach(pid)
except frida.ServerNotStartedError:
    print("Frida server not started. Please ensure frida-server is running on the device.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var pathname = null;

        try {
            var fdPath = Socket.getLocalAddress(fd);
            if (fdPath) {
                pathname = fdPath.path;
            }
        } catch (e) {}

        if (!pathname) {
            try {
                pathname = Memory.readCString(ptr(args[0]).readPointer()); // 尝试读取路径名 (可能不可靠)
            } catch (e) {
                pathname = "unknown";
            }
        }

        if (pathname && pathname.includes("synclink")) {
            console.log("[-] ioctl called for synclink device:");
            console.log("    fd: " + fd);
            console.log("    request: " + request + " (0x" + request.toString(16) + ")");
            // 可以进一步解析 request 参数，判断是哪个 MGSL_IOC* 命令
            if (request == 0x40086d00) { // 替换为 MGSL_IOCWAITEVENT 的值
                console.log("    MGSL_IOCWAITEVENT");
                // 可以进一步解析 argp 参数
            }
        }
    },
    onLeave: function(retval) {
        // console.log("[-] ioctl returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

device.resume(pid)
sys.stdin.read()
session.detach()
```

**Frida Hook 说明:**

1. **目标:** Hook `ioctl` 系统调用，因为与 `synclink` 设备的交互主要通过 `ioctl` 进行。
2. **`onEnter`:** 在 `ioctl` 调用前执行的代码。
3. **获取文件描述符和命令号:** 从 `ioctl` 的参数中获取文件描述符 (`fd`) 和命令号 (`request`).
4. **检查设备路径:** 尝试获取与文件描述符关联的设备路径名，如果路径名包含 "synclink"，则认为是与 `synclink` 设备相关的调用。
5. **打印信息:** 打印文件描述符和命令号。
6. **解析命令号:** 可以根据 `request` 的值判断具体的 `MGSL_IOC*` 命令。你需要查找 `MGSL_IOC*` 宏定义对应的值（可以使用 `grep` 或在编译后的头文件中查找）。
7. **`onLeave`:**  在 `ioctl` 调用返回后执行的代码 (在本例中被注释掉)。

**使用步骤:**

1. 确保你的 Android 设备上运行了 Frida server。
2. 将上述 Python 代码保存为 `.py` 文件（例如 `hook_synclink.py`）。
3. 将 `com.example.myapp` 替换为你想要监控的 Android 应用的包名。
4. 运行 Python 脚本：`python hook_synclink.py`
5. 启动目标 Android 应用程序。
6. Frida 脚本会在控制台上打印出与 `synclink` 设备相关的 `ioctl` 调用信息。

这个 Frida 示例提供了一个基本的 hook 框架。你可以根据需要进一步解析 `ioctl` 的参数，以获取更详细的信息，例如传递给 `MGSL_IOCSPARAMS` 的 `MGSL_PARAMS` 结构体的内容。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/synclink.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_SYNCLINK_H_
#define _UAPI_SYNCLINK_H_
#define SYNCLINK_H_VERSION 3.6
#include <linux/types.h>
#define BIT0 0x0001
#define BIT1 0x0002
#define BIT2 0x0004
#define BIT3 0x0008
#define BIT4 0x0010
#define BIT5 0x0020
#define BIT6 0x0040
#define BIT7 0x0080
#define BIT8 0x0100
#define BIT9 0x0200
#define BIT10 0x0400
#define BIT11 0x0800
#define BIT12 0x1000
#define BIT13 0x2000
#define BIT14 0x4000
#define BIT15 0x8000
#define BIT16 0x00010000
#define BIT17 0x00020000
#define BIT18 0x00040000
#define BIT19 0x00080000
#define BIT20 0x00100000
#define BIT21 0x00200000
#define BIT22 0x00400000
#define BIT23 0x00800000
#define BIT24 0x01000000
#define BIT25 0x02000000
#define BIT26 0x04000000
#define BIT27 0x08000000
#define BIT28 0x10000000
#define BIT29 0x20000000
#define BIT30 0x40000000
#define BIT31 0x80000000
#define HDLC_MAX_FRAME_SIZE 65535
#define MAX_ASYNC_TRANSMIT 4096
#define MAX_ASYNC_BUFFER_SIZE 4096
#define ASYNC_PARITY_NONE 0
#define ASYNC_PARITY_EVEN 1
#define ASYNC_PARITY_ODD 2
#define ASYNC_PARITY_SPACE 3
#define HDLC_FLAG_UNDERRUN_ABORT7 0x0000
#define HDLC_FLAG_UNDERRUN_ABORT15 0x0001
#define HDLC_FLAG_UNDERRUN_FLAG 0x0002
#define HDLC_FLAG_UNDERRUN_CRC 0x0004
#define HDLC_FLAG_SHARE_ZERO 0x0010
#define HDLC_FLAG_AUTO_CTS 0x0020
#define HDLC_FLAG_AUTO_DCD 0x0040
#define HDLC_FLAG_AUTO_RTS 0x0080
#define HDLC_FLAG_RXC_DPLL 0x0100
#define HDLC_FLAG_RXC_BRG 0x0200
#define HDLC_FLAG_RXC_TXCPIN 0x8000
#define HDLC_FLAG_RXC_RXCPIN 0x0000
#define HDLC_FLAG_TXC_DPLL 0x0400
#define HDLC_FLAG_TXC_BRG 0x0800
#define HDLC_FLAG_TXC_TXCPIN 0x0000
#define HDLC_FLAG_TXC_RXCPIN 0x0008
#define HDLC_FLAG_DPLL_DIV8 0x1000
#define HDLC_FLAG_DPLL_DIV16 0x2000
#define HDLC_FLAG_DPLL_DIV32 0x0000
#define HDLC_FLAG_HDLC_LOOPMODE 0x4000
#define HDLC_CRC_NONE 0
#define HDLC_CRC_16_CCITT 1
#define HDLC_CRC_32_CCITT 2
#define HDLC_CRC_MASK 0x00ff
#define HDLC_CRC_RETURN_EX 0x8000
#define RX_OK 0
#define RX_CRC_ERROR 1
#define HDLC_TXIDLE_FLAGS 0
#define HDLC_TXIDLE_ALT_ZEROS_ONES 1
#define HDLC_TXIDLE_ZEROS 2
#define HDLC_TXIDLE_ONES 3
#define HDLC_TXIDLE_ALT_MARK_SPACE 4
#define HDLC_TXIDLE_SPACE 5
#define HDLC_TXIDLE_MARK 6
#define HDLC_TXIDLE_CUSTOM_8 0x10000000
#define HDLC_TXIDLE_CUSTOM_16 0x20000000
#define HDLC_ENCODING_NRZ 0
#define HDLC_ENCODING_NRZB 1
#define HDLC_ENCODING_NRZI_MARK 2
#define HDLC_ENCODING_NRZI_SPACE 3
#define HDLC_ENCODING_NRZI HDLC_ENCODING_NRZI_SPACE
#define HDLC_ENCODING_BIPHASE_MARK 4
#define HDLC_ENCODING_BIPHASE_SPACE 5
#define HDLC_ENCODING_BIPHASE_LEVEL 6
#define HDLC_ENCODING_DIFF_BIPHASE_LEVEL 7
#define HDLC_PREAMBLE_LENGTH_8BITS 0
#define HDLC_PREAMBLE_LENGTH_16BITS 1
#define HDLC_PREAMBLE_LENGTH_32BITS 2
#define HDLC_PREAMBLE_LENGTH_64BITS 3
#define HDLC_PREAMBLE_PATTERN_NONE 0
#define HDLC_PREAMBLE_PATTERN_ZEROS 1
#define HDLC_PREAMBLE_PATTERN_FLAGS 2
#define HDLC_PREAMBLE_PATTERN_10 3
#define HDLC_PREAMBLE_PATTERN_01 4
#define HDLC_PREAMBLE_PATTERN_ONES 5
#define MGSL_MODE_ASYNC 1
#define MGSL_MODE_HDLC 2
#define MGSL_MODE_MONOSYNC 3
#define MGSL_MODE_BISYNC 4
#define MGSL_MODE_RAW 6
#define MGSL_MODE_BASE_CLOCK 7
#define MGSL_MODE_XSYNC 8
#define MGSL_BUS_TYPE_ISA 1
#define MGSL_BUS_TYPE_EISA 2
#define MGSL_BUS_TYPE_PCI 5
#define MGSL_INTERFACE_MASK 0xf
#define MGSL_INTERFACE_DISABLE 0
#define MGSL_INTERFACE_RS232 1
#define MGSL_INTERFACE_V35 2
#define MGSL_INTERFACE_RS422 3
#define MGSL_INTERFACE_RTS_EN 0x10
#define MGSL_INTERFACE_LL 0x20
#define MGSL_INTERFACE_RL 0x40
#define MGSL_INTERFACE_MSB_FIRST 0x80
typedef struct _MGSL_PARAMS {
  unsigned long mode;
  unsigned char loopback;
  unsigned short flags;
  unsigned char encoding;
  unsigned long clock_speed;
  unsigned char addr_filter;
  unsigned short crc_type;
  unsigned char preamble_length;
  unsigned char preamble;
  unsigned long data_rate;
  unsigned char data_bits;
  unsigned char stop_bits;
  unsigned char parity;
} MGSL_PARAMS, * PMGSL_PARAMS;
#define MICROGATE_VENDOR_ID 0x13c0
#define SYNCLINK_DEVICE_ID 0x0010
#define MGSCC_DEVICE_ID 0x0020
#define SYNCLINK_SCA_DEVICE_ID 0x0030
#define SYNCLINK_GT_DEVICE_ID 0x0070
#define SYNCLINK_GT4_DEVICE_ID 0x0080
#define SYNCLINK_AC_DEVICE_ID 0x0090
#define SYNCLINK_GT2_DEVICE_ID 0x00A0
#define MGSL_MAX_SERIAL_NUMBER 30
#define DiagStatus_OK 0
#define DiagStatus_AddressFailure 1
#define DiagStatus_AddressConflict 2
#define DiagStatus_IrqFailure 3
#define DiagStatus_IrqConflict 4
#define DiagStatus_DmaFailure 5
#define DiagStatus_DmaConflict 6
#define DiagStatus_PciAdapterNotFound 7
#define DiagStatus_CantAssignPciResources 8
#define DiagStatus_CantAssignPciMemAddr 9
#define DiagStatus_CantAssignPciIoAddr 10
#define DiagStatus_CantAssignPciIrq 11
#define DiagStatus_MemoryError 12
#define SerialSignal_DCD 0x01
#define SerialSignal_TXD 0x02
#define SerialSignal_RI 0x04
#define SerialSignal_RXD 0x08
#define SerialSignal_CTS 0x10
#define SerialSignal_RTS 0x20
#define SerialSignal_DSR 0x40
#define SerialSignal_DTR 0x80
struct mgsl_icount {
  __u32 cts, dsr, rng, dcd, tx, rx;
  __u32 frame, parity, overrun, brk;
  __u32 buf_overrun;
  __u32 txok;
  __u32 txunder;
  __u32 txabort;
  __u32 txtimeout;
  __u32 rxshort;
  __u32 rxlong;
  __u32 rxabort;
  __u32 rxover;
  __u32 rxcrc;
  __u32 rxok;
  __u32 exithunt;
  __u32 rxidle;
};
struct gpio_desc {
  __u32 state;
  __u32 smask;
  __u32 dir;
  __u32 dmask;
};
#define DEBUG_LEVEL_DATA 1
#define DEBUG_LEVEL_ERROR 2
#define DEBUG_LEVEL_INFO 3
#define DEBUG_LEVEL_BH 4
#define DEBUG_LEVEL_ISR 5
#define MgslEvent_DsrActive 0x0001
#define MgslEvent_DsrInactive 0x0002
#define MgslEvent_Dsr 0x0003
#define MgslEvent_CtsActive 0x0004
#define MgslEvent_CtsInactive 0x0008
#define MgslEvent_Cts 0x000c
#define MgslEvent_DcdActive 0x0010
#define MgslEvent_DcdInactive 0x0020
#define MgslEvent_Dcd 0x0030
#define MgslEvent_RiActive 0x0040
#define MgslEvent_RiInactive 0x0080
#define MgslEvent_Ri 0x00c0
#define MgslEvent_ExitHuntMode 0x0100
#define MgslEvent_IdleReceived 0x0200
#define MGSL_MAGIC_IOC 'm'
#define MGSL_IOCSPARAMS _IOW(MGSL_MAGIC_IOC, 0, struct _MGSL_PARAMS)
#define MGSL_IOCGPARAMS _IOR(MGSL_MAGIC_IOC, 1, struct _MGSL_PARAMS)
#define MGSL_IOCSTXIDLE _IO(MGSL_MAGIC_IOC, 2)
#define MGSL_IOCGTXIDLE _IO(MGSL_MAGIC_IOC, 3)
#define MGSL_IOCTXENABLE _IO(MGSL_MAGIC_IOC, 4)
#define MGSL_IOCRXENABLE _IO(MGSL_MAGIC_IOC, 5)
#define MGSL_IOCTXABORT _IO(MGSL_MAGIC_IOC, 6)
#define MGSL_IOCGSTATS _IO(MGSL_MAGIC_IOC, 7)
#define MGSL_IOCWAITEVENT _IOWR(MGSL_MAGIC_IOC, 8, int)
#define MGSL_IOCCLRMODCOUNT _IO(MGSL_MAGIC_IOC, 15)
#define MGSL_IOCLOOPTXDONE _IO(MGSL_MAGIC_IOC, 9)
#define MGSL_IOCSIF _IO(MGSL_MAGIC_IOC, 10)
#define MGSL_IOCGIF _IO(MGSL_MAGIC_IOC, 11)
#define MGSL_IOCSGPIO _IOW(MGSL_MAGIC_IOC, 16, struct gpio_desc)
#define MGSL_IOCGGPIO _IOR(MGSL_MAGIC_IOC, 17, struct gpio_desc)
#define MGSL_IOCWAITGPIO _IOWR(MGSL_MAGIC_IOC, 18, struct gpio_desc)
#define MGSL_IOCSXSYNC _IO(MGSL_MAGIC_IOC, 19)
#define MGSL_IOCGXSYNC _IO(MGSL_MAGIC_IOC, 20)
#define MGSL_IOCSXCTRL _IO(MGSL_MAGIC_IOC, 21)
#define MGSL_IOCGXCTRL _IO(MGSL_MAGIC_IOC, 22)
#endif

"""

```