Response:
Let's break down the thought process for answering the request about `ptp_clock.h`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided C header file, focusing on its functionality, relationship to Android, implementation details (specifically for libc functions), dynamic linking aspects, usage errors, and how Android frameworks/NDK interact with it.

**2. Initial Scan and Identification of Key Elements:**

My first step is to quickly read through the header file and identify the major components:

* **Header Guards:** `#ifndef _PTP_CLOCK_H_`, `#define _PTP_CLOCK_H_`, `#endif`. These are standard C/C++ practices and don't directly represent functionality, but they are important for preventing multiple inclusions.
* **Includes:** `#include <linux/ioctl.h>`, `#include <linux/types.h>`. This immediately tells me it's interacting with the Linux kernel.
* **Macros:**  A large number of `#define` statements. These represent constants and bit flags used for configuring and controlling the PTP clock. I categorize these mentally into groups based on their prefixes (e.g., `PTP_ENABLE_`, `PTP_RISING_`, `PTP_PEROUT_`, etc.).
* **Structures:** Several `struct` definitions (`ptp_clock_time`, `ptp_clock_caps`, `ptp_extts_request`, etc.). These represent data structures used for interacting with the PTP clock through ioctl calls. I note the members of each struct.
* **ioctl Definitions:**  Macros starting with `PTP_CLOCK_GETCAPS`, `PTP_EXTTS_REQUEST`, etc. These are the primary interface for interacting with the PTP clock device driver in the kernel. The `_IOR`, `_IOW`, `_IOWR`, `_IO` macros are standard Linux ioctl definitions, indicating read, write, read-write, and no-data operations, respectively.
* **Enums:** The `enum ptp_pin_function`. This defines a set of possible functions for PTP clock pins.

**3. Deciphering the Functionality (Based on the Elements):**

Now I start to interpret what these elements mean:

* **PTP Clock:** The file is clearly about interacting with a Precise Time Protocol (PTP) clock. The structures and ioctls suggest the ability to get clock capabilities, request external timestamps, configure periodic outputs, get system offsets relative to the PTP clock, and manage pin functions.
* **ioctl Interface:** The heavy use of `ioctl` implies this is a low-level interface, directly interacting with a kernel driver.
* **Configuration Flags:** The numerous `#define` macros are for configuring specific aspects of the PTP clock, like enabling features, specifying edge triggers, setting output modes, etc.

**4. Connecting to Android:**

The prompt mentions `bionic`, Android's C library. This header file is within the `bionic/libc/kernel/uapi/linux` directory. This means Android exposes the PTP clock functionality from the Linux kernel to user-space applications. I need to think about *why* Android might use PTP. High-precision timing is crucial for:

* **Telecommunications:** Synchronizing cellular networks.
* **Automotive:**  Advanced driver-assistance systems (ADAS) often require precise time synchronization.
* **Industrial Automation:** Coordinating robots and machinery.
* **Audio/Video Synchronization:** Ensuring accurate timing in multimedia applications.

**5. Addressing Specific Questions:**

* **libc Function Implementation:**  This header file *defines* the interface but doesn't *implement* any libc functions. The actual implementation resides in the kernel driver. Therefore, my answer will focus on what the *structures and ioctls are for*, not how a C function in libc works. The interaction involves the `ioctl()` system call.
* **Dynamic Linker:** This header file is a *header file*. It's used during *compilation*. The dynamic linker (`linker64` or `linker`) comes into play when the compiled application (using these definitions) is *run*. I need to explain how the application would link against libc, and libc would then make the `ioctl` system calls. I'll provide a basic SO layout and the linking steps.
* **Logical Reasoning:** The "assumed input/output" relates to how the structures are used. For example, setting flags in `ptp_extts_request` and getting timestamp data back.
* **User Errors:** Common errors involve using incorrect flags, providing invalid indices, or not having the necessary permissions to access the PTP clock device.
* **Android Framework/NDK:**  I need to trace the path from a higher-level Android API down to the `ioctl` calls that would utilize these definitions. This involves thinking about potential frameworks that might require precise timing.

**6. Structuring the Answer:**

I decide to structure the answer with clear headings for each part of the request:

* 功能 (Functionality)
* 与Android的关系 (Relationship with Android)
* libc函数的功能实现 (Implementation of libc Functions) -  Crucially, I need to clarify that *this header doesn't implement libc functions* but defines the interface used by them.
* 动态链接器的功能 (Functionality of the Dynamic Linker)
* 逻辑推理 (Logical Reasoning)
* 用户或编程常见的使用错误 (Common User or Programming Errors)
* Android Framework/NDK如何到达这里 (How Android Framework/NDK Reaches Here)
* Frida Hook 示例 (Frida Hook Example)

**7. Crafting the Details:**

For each section, I elaborate on the points identified earlier, providing concrete examples and explanations.

* **Functionality:** List each major category of functionality (getting capabilities, timestamps, periodic output, etc.) and mention the relevant structures and ioctls.
* **Android:** Give specific examples of Android features that might rely on PTP.
* **libc:** Explain that `ioctl` is the system call used and how the structures are passed.
* **Dynamic Linker:** Explain the SO layout, linking process, and how the app links to libc.
* **Logical Reasoning:**  Provide a simple scenario with example input and expected output for one of the ioctls (e.g., getting an external timestamp).
* **User Errors:** List common mistakes and explain why they occur.
* **Android Framework/NDK:**  Describe a plausible path from a high-level API to the kernel driver. Focus on the system call boundary.
* **Frida Hook:** Provide a basic Frida script example to intercept the `ioctl` call and inspect the arguments.

**8. Review and Refinement:**

Finally, I review my answer to ensure accuracy, clarity, and completeness, double-checking that I've addressed all aspects of the original request. I pay attention to language and ensure it's understandable. I also make sure to highlight the distinction between the header file's *definitions* and the kernel's *implementation*.

This iterative process of understanding the request, identifying key elements, interpreting their meaning, connecting to the broader context, and structuring the answer allows me to create a comprehensive and informative response.
## bionic/libc/kernel/uapi/linux/ptp_clock.h 功能解析

这个头文件 `ptp_clock.h` 定义了用户空间程序与 Linux 内核中 PTP (Precision Time Protocol，精确时间协议) 时钟设备驱动程序进行交互的接口。它主要通过 `ioctl` 系统调用来控制和获取 PTP 时钟的相关信息。

**主要功能列举:**

1. **获取 PTP 时钟设备的性能参数:**
   -  `PTP_CLOCK_GETCAPS`: 获取 PTP 时钟设备的能力，例如支持的最大调整范围、告警数量、外部时间戳输入数量、周期性输出数量、PPS (Pulse Per Second) 支持、引脚数量、交叉时间戳支持、相位调整能力等。
   -  `PTP_CLOCK_GETCAPS2`:  可能是 `PTP_CLOCK_GETCAPS` 的新版本或扩展版本，提供更详细的性能参数。

2. **请求外部时间戳:**
   - `PTP_EXTTS_REQUEST`: 配置 PTP 时钟设备捕获外部事件的时间戳，可以指定捕获哪个引脚的上升沿或下降沿。
   - `PTP_EXTTS_REQUEST2`:  可能是 `PTP_EXTTS_REQUEST` 的新版本或扩展版本。

3. **配置周期性输出:**
   - `PTP_PEROUT_REQUEST`: 配置 PTP 时钟设备产生周期性的脉冲输出，可以设置起始时间、周期、占空比、相位等参数。
   - `PTP_PEROUT_REQUEST2`: 可能是 `PTP_PEROUT_REQUEST` 的新版本或扩展版本。

4. **使能/禁用 PPS 输出:**
   - `PTP_ENABLE_PPS`: 使能或禁用 PTP 时钟设备的 PPS (Pulse Per Second) 输出。
   - `PTP_ENABLE_PPS2`: 可能是 `PTP_ENABLE_PPS` 的新版本或扩展版本。

5. **获取系统与 PTP 时钟的偏移:**
   - `PTP_SYS_OFFSET`:  获取系统时间与 PTP 时钟时间的偏移量。
   - `PTP_SYS_OFFSET2`: 可能是 `PTP_SYS_OFFSET` 的新版本或扩展版本。
   - `PTP_SYS_OFFSET_PRECISE`: 获取更精确的系统时间 (realtime 和 monoraw) 与 PTP 时钟时间的偏移量。
   - `PTP_SYS_OFFSET_PRECISE2`: 可能是 `PTP_SYS_OFFSET_PRECISE` 的新版本或扩展版本。
   - `PTP_SYS_OFFSET_EXTENDED`: 获取扩展的系统时间与 PTP 时钟的偏移量信息，可能包含多个采样点和时钟源信息。
   - `PTP_SYS_OFFSET_EXTENDED2`: 可能是 `PTP_SYS_OFFSET_EXTENDED` 的新版本或扩展版本。

6. **管理 PTP 引脚功能:**
   - `PTP_PIN_GETFUNC`: 获取指定 PTP 引脚的当前功能配置。
   - `PTP_PIN_GETFUNC2`: 可能是 `PTP_PIN_GETFUNC` 的新版本或扩展版本。
   - `PTP_PIN_SETFUNC`: 设置指定 PTP 引脚的功能，例如配置为外部时间戳输入或周期性输出。
   - `PTP_PIN_SETFUNC2`: 可能是 `PTP_PIN_SETFUNC` 的新版本或扩展版本。

7. **清除所有掩码:**
   - `PTP_MASK_CLEAR_ALL`: 清除 PTP 时钟设备的所有中断掩码。

8. **使能单个掩码:**
   - `PTP_MASK_EN_SINGLE`: 使能 PTP 时钟设备的单个中断掩码。

**与 Android 功能的关系及举例说明:**

PTP 协议在需要高精度时间同步的 Android 应用场景中扮演着重要的角色。

* **电信和网络同步:** 在某些 Android 设备中，例如支持 5G 的设备，PTP 可以用于同步基站和设备的时钟，以实现更可靠的网络连接和更低的延迟。Android 框架可能会使用 PTP 来校准系统时钟，提高时间精度。
* **音视频同步:** 在专业的音频或视频应用中，精确的时间同步至关重要。例如，在进行多路音视频录制或播放时，PTP 可以帮助同步不同设备的时钟，保证音视频流的对齐。Android 的媒体框架可能在底层使用 PTP 来实现高精度的同步。
* **工业控制和自动化:**  在某些工业 Android 设备中，PTP 可以用于同步传感器、执行器和其他设备的时钟，实现精确的控制和协调。
* **车载系统:**  在车载娱乐系统或自动驾驶系统中，PTP 可以用于同步不同的 ECU (电子控制单元)，例如传感器、摄像头和处理器，以确保系统功能的正确运行。

**举例说明:**

假设一个 Android 应用需要高精度地记录外部事件发生的时间。它可以按照以下步骤使用 `ptp_clock.h` 中定义的接口：

1. **打开 PTP 时钟设备文件:**  通常位于 `/dev` 目录下，例如 `/dev/ptp0`。
2. **获取设备能力:** 使用 `ioctl` 调用 `PTP_CLOCK_GETCAPS` 获取设备的性能参数，例如支持的外部时间戳输入数量。
3. **配置外部时间戳请求:** 使用 `ioctl` 调用 `PTP_EXTTS_REQUEST`，指定要监听的引脚和触发沿 (上升沿或下降沿)。
4. **等待外部事件:**  应用可能需要使用 `poll` 或 `select` 等机制来等待 PTP 时钟设备的文件描述符变为可读。
5. **读取外部时间戳事件:** 当有外部事件发生时，内核会更新设备的状态。应用可以再次使用 `ioctl` 调用，可能通过一个特定的 `ioctl` 命令 (虽然在这个头文件中没有直接定义读取事件的 ioctl，但实际的驱动程序可能提供)，或者通过读取设备文件来获取包含时间戳信息的 `ptp_extts_event` 结构体。

**详细解释每一个 libc 函数的功能是如何实现的:**

`ptp_clock.h` 文件本身**并没有定义任何 libc 函数的实现**。它只是一个头文件，定义了与 PTP 时钟设备驱动程序交互所需的常量、数据结构和 `ioctl` 请求码。

用户空间程序需要使用标准 C 库中的 `ioctl` 函数来与内核驱动程序进行交互。`ioctl` 函数的功能如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

- `fd`:  要操作的设备文件的文件描述符。
- `request`:  指定要执行的操作的请求码，通常在头文件中定义为宏，例如 `PTP_CLOCK_GETCAPS`。
- `...`:  可选的参数，具体取决于请求码，通常是指向用于传递数据的结构体的指针。

**`ioctl` 函数的实现原理 (简述):**

1. 当用户空间程序调用 `ioctl` 函数时，系统会陷入内核态。
2. 内核根据传入的文件描述符 `fd` 找到对应的设备驱动程序。
3. 内核根据传入的请求码 `request` 调用驱动程序中相应的处理函数 (通常在驱动程序的 `ioctl` 方法中实现)。
4. 驱动程序执行相应的操作，例如读取硬件寄存器、设置硬件参数等。
5. 驱动程序将结果返回给内核。
6. 内核将结果返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`ptp_clock.h` 本身不涉及动态链接器的功能，因为它只是一个头文件。动态链接器 (`linker` 或 `linker64` 在 Android 上) 的作用是在程序运行时将程序依赖的共享库 (SO 文件) 加载到内存中，并解析符号引用。

**SO 布局样本 (假设一个使用了 PTP 功能的 Android 应用):**

```
/system/bin/my_ptp_app  (可执行文件)
/system/lib64/libc.so   (Android 的 C 库)
/vendor/lib64/hw/ptp.device.so (假设的 PTP 设备 HAL 库，实际路径可能不同)
```

**链接的处理过程:**

1. **编译时链接:**
   - 应用程序 `my_ptp_app` 的源代码会包含 `ptp_clock.h` 头文件，以便使用其中定义的常量和数据结构。
   - 在编译和链接阶段，链接器会将应用程序的代码与所需的系统库 (例如 `libc.so`) 进行链接。链接器会记录应用程序中对 `ioctl` 等符号的引用。

2. **运行时链接:**
   - 当 Android 系统启动 `my_ptp_app` 时，动态链接器会被调用。
   - 动态链接器会读取应用程序的 ELF 头信息，找到其依赖的共享库列表 (例如 `libc.so`)。
   - 动态链接器会将这些共享库加载到进程的内存空间中。
   - 动态链接器会解析应用程序中对共享库中符号的引用。例如，当应用程序调用 `ioctl` 时，动态链接器会将该调用指向 `libc.so` 中 `ioctl` 函数的实际地址。

**与 PTP 相关的动态链接可能涉及到:**

- **libc.so:** 应用程序通过 `libc.so` 中的 `ioctl` 函数与内核进行交互。
- **HAL (Hardware Abstraction Layer) 库:** Android 的 HAL 层可以提供更高级的接口来访问 PTP 功能。例如，可能会有一个专门的 HAL 库 (`ptp.device.so` 只是一个假设的名称) 封装了与 PTP 设备驱动程序的交互细节。应用程序可能会链接到这个 HAL 库，而不是直接使用 `ioctl`。

**逻辑推理 (假设输入与输出):**

**场景:** 应用程序尝试获取 PTP 时钟设备的性能参数。

**假设输入:**

- 打开 PTP 时钟设备的文件描述符 `fd`。
- 调用 `ioctl(fd, PTP_CLOCK_GETCAPS, &caps)`，其中 `caps` 是 `struct ptp_clock_caps` 类型的变量。

**预期输出:**

- `ioctl` 函数返回 0 表示成功。
- `caps` 结构体中的成员变量将被填充，包含 PTP 时钟设备的性能参数，例如：
  - `caps.max_adj`: 支持的最大调整范围。
  - `caps.n_alarm`: 支持的告警数量。
  - `caps.n_ext_ts`: 支持的外部时间戳输入数量。
  - ...

**场景:** 应用程序请求捕获外部时间戳。

**假设输入:**

- 打开 PTP 时钟设备的文件描述符 `fd`。
- 初始化 `struct ptp_extts_request req` 结构体，例如：
  - `req.index = 0;` (监听第一个外部时间戳输入引脚)
  - `req.flags = PTP_RISING_EDGE | PTP_ENABLE_FEATURE;` (捕获上升沿并使能)
- 调用 `ioctl(fd, PTP_EXTTS_REQUEST, &req)`。

**预期输出:**

- `ioctl` 函数返回 0 表示成功，内核开始监听指定的引脚的上升沿。
- 当指定引脚出现上升沿时，内核会记录时间戳。应用程序可能需要通过其他机制 (例如等待事件或读取设备文件) 来获取该时间戳。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **无效的文件描述符:**  尝试在未打开 PTP 时钟设备文件的情况下调用 `ioctl`，会导致错误。
   ```c
   int fd = -1; // 未打开设备
   struct ptp_clock_caps caps;
   if (ioctl(fd, PTP_CLOCK_GETCAPS, &caps) == -1) {
       perror("ioctl failed"); // 输出 "Bad file descriptor"
   }
   ```

2. **错误的请求码:**  使用了错误的 `ioctl` 请求码，或者将请求码用于了错误的设备文件，会导致 `ioctl` 调用失败。

3. **传递了不正确的参数结构体:**  例如，传递了一个未初始化的结构体，或者结构体中的某些成员变量设置了无效的值。
   ```c
   int fd = open("/dev/ptp0", O_RDWR);
   struct ptp_extts_request req; // 未初始化
   if (ioctl(fd, PTP_EXTTS_REQUEST, &req) == -1) {
       perror("ioctl failed"); // 可能会因为 flags 未设置而失败
   }
   close(fd);
   ```

4. **权限不足:**  用户可能没有足够的权限访问 PTP 时钟设备文件，导致 `open` 或 `ioctl` 调用失败。

5. **未检查 `ioctl` 的返回值:**  `ioctl` 函数在失败时会返回 -1，并设置 `errno`。程序员应该始终检查返回值并处理错误。

6. **使用了不支持的标志位组合:**  例如，某些标志位可能互斥，或者某些功能可能在特定的硬件上不受支持。查阅内核文档或设备驱动程序文档是必要的。

7. **竞态条件:**  在多线程或多进程环境中，如果没有适当的同步机制，可能会出现竞态条件，导致对 PTP 时钟设备的并发访问出现问题。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 `ptp_clock.h` 定义的是内核接口，Android Framework 或 NDK 应用通常不会直接调用这些 `ioctl` 命令。更常见的情况是，Android 提供更高级的 API 或服务来间接使用 PTP 功能。

**可能的路径:**

1. **Android Framework 服务:**  Android Framework 中可能存在一个系统服务，负责管理 PTP 时钟。这个服务可能会在底层使用 `ioctl` 调用来与内核驱动程序交互。
2. **HAL (Hardware Abstraction Layer):**  Android 的 HAL 层提供了一组标准接口，用于硬件抽象。可能存在一个 PTP 相关的 HAL 模块，封装了与 PTP 设备驱动程序的交互。Framework 服务可能会通过 HAL 接口来访问 PTP 功能。
3. **NDK API (较少见):**  虽然不太常见，但如果 Android 提供了直接访问 PTP 功能的 NDK API，开发者可以使用 NDK 来调用这些 API。这些 NDK API 在底层最终也会调用 `ioctl`。

**Frida Hook 示例:**

假设我们想 Hook 一个使用 `ioctl` 调用 `PTP_CLOCK_GETCAPS` 的进程。

```python
import frida
import sys

package_name = "com.example.ptp_app"  # 替换为目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        if (request === 0xc0103d01) { // PTP_CLOCK_GETCAPS 的值 (需要根据实际情况确定)
            send({
                type: "info",
                payload: "调用 ioctl PTP_CLOCK_GETCAPS",
                fd: fd,
                request: request,
                argp: argp
            });
            this.capsPtr = argp; // 保存参数指针
        }
    },
    onLeave: function(retval) {
        if (this.capsPtr) {
            const caps = Memory.readByteArray(this.capsPtr, 60); // 读取 ptp_clock_caps 结构体的内容 (根据结构体大小调整)
            send({
                type: "info",
                payload: "ioctl PTP_CLOCK_GETCAPS 返回",
                retval: retval.toInt32(),
                caps: caps
            });
            this.capsPtr = null; // 清空指针
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

1. **连接到目标进程:** 使用 `frida.attach` 连接到指定的 Android 应用进程。
2. **Hook `ioctl` 函数:** 使用 `Interceptor.attach` Hook `libc.so` 中的 `ioctl` 函数。
3. **检查请求码:** 在 `onEnter` 中，检查 `ioctl` 的第二个参数 (请求码) 是否等于 `PTP_CLOCK_GETCAPS` 的值 (需要根据实际编译环境或内核头文件确定)。
4. **保存参数指针:** 如果是 `PTP_CLOCK_GETCAPS`，则保存第三个参数 (指向 `ptp_clock_caps` 结构体的指针)。
5. **读取返回结果:** 在 `onLeave` 中，如果之前保存了参数指针，则读取该指针指向的内存区域，获取 `ptp_clock_caps` 结构体的内容。
6. **发送消息:** 使用 `send` 函数将 Hook 到的信息发送到 Frida 客户端。

**运行步骤:**

1. 确保你的 Android 设备已连接并通过 adb 可访问。
2. 确保目标 Android 应用正在运行。
3. 将上面的 Python 代码保存为 `ptp_hook.py`。
4. 运行 `python ptp_hook.py`。
5. 在目标应用中触发调用 PTP 相关功能的操作。
6. Frida 客户端会打印出 Hook 到的 `ioctl` 调用信息，包括请求码和参数内容。

**注意:**

- `PTP_CLOCK_GETCAPS` 的实际数值 (`0xc0103d01` 在这里只是一个例子) 需要根据目标 Android 系统的内核头文件或反编译相关代码来确定。
- 读取 `ptp_clock_caps` 结构体时，需要根据其定义的大小来调整 `Memory.readByteArray` 的第二个参数。
- 这个示例只是 Hook 了 `PTP_CLOCK_GETCAPS`，你可以根据需要修改代码来 Hook 其他的 `ioctl` 命令。

通过 Frida Hook，你可以动态地观察 Android 应用与内核 PTP 驱动程序的交互过程，帮助理解 Android Framework 或 NDK 如何使用 PTP 功能。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/ptp_clock.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _PTP_CLOCK_H_
#define _PTP_CLOCK_H_
#include <linux/ioctl.h>
#include <linux/types.h>
#define PTP_ENABLE_FEATURE (1 << 0)
#define PTP_RISING_EDGE (1 << 1)
#define PTP_FALLING_EDGE (1 << 2)
#define PTP_STRICT_FLAGS (1 << 3)
#define PTP_EXT_OFFSET (1 << 4)
#define PTP_EXTTS_EDGES (PTP_RISING_EDGE | PTP_FALLING_EDGE)
#define PTP_EXTTS_VALID_FLAGS (PTP_ENABLE_FEATURE | PTP_RISING_EDGE | PTP_FALLING_EDGE | PTP_STRICT_FLAGS | PTP_EXT_OFFSET)
#define PTP_EXTTS_V1_VALID_FLAGS (PTP_ENABLE_FEATURE | PTP_RISING_EDGE | PTP_FALLING_EDGE)
#define PTP_EXTTS_EVENT_VALID (PTP_ENABLE_FEATURE)
#define PTP_PEROUT_ONE_SHOT (1 << 0)
#define PTP_PEROUT_DUTY_CYCLE (1 << 1)
#define PTP_PEROUT_PHASE (1 << 2)
#define PTP_PEROUT_VALID_FLAGS (PTP_PEROUT_ONE_SHOT | PTP_PEROUT_DUTY_CYCLE | PTP_PEROUT_PHASE)
#define PTP_PEROUT_V1_VALID_FLAGS (0)
struct ptp_clock_time {
  __s64 sec;
  __u32 nsec;
  __u32 reserved;
};
struct ptp_clock_caps {
  int max_adj;
  int n_alarm;
  int n_ext_ts;
  int n_per_out;
  int pps;
  int n_pins;
  int cross_timestamping;
  int adjust_phase;
  int max_phase_adj;
  int rsv[11];
};
struct ptp_extts_request {
  unsigned int index;
  unsigned int flags;
  unsigned int rsv[2];
};
struct ptp_perout_request {
  union {
    struct ptp_clock_time start;
    struct ptp_clock_time phase;
  };
  struct ptp_clock_time period;
  unsigned int index;
  unsigned int flags;
  union {
    struct ptp_clock_time on;
    unsigned int rsv[4];
  };
};
#define PTP_MAX_SAMPLES 25
struct ptp_sys_offset {
  unsigned int n_samples;
  unsigned int rsv[3];
  struct ptp_clock_time ts[2 * PTP_MAX_SAMPLES + 1];
};
struct ptp_sys_offset_extended {
  unsigned int n_samples;
  __kernel_clockid_t clockid;
  unsigned int rsv[2];
  struct ptp_clock_time ts[PTP_MAX_SAMPLES][3];
};
struct ptp_sys_offset_precise {
  struct ptp_clock_time device;
  struct ptp_clock_time sys_realtime;
  struct ptp_clock_time sys_monoraw;
  unsigned int rsv[4];
};
enum ptp_pin_function {
  PTP_PF_NONE,
  PTP_PF_EXTTS,
  PTP_PF_PEROUT,
  PTP_PF_PHYSYNC,
};
struct ptp_pin_desc {
  char name[64];
  unsigned int index;
  unsigned int func;
  unsigned int chan;
  unsigned int rsv[5];
};
#define PTP_CLK_MAGIC '='
#define PTP_CLOCK_GETCAPS _IOR(PTP_CLK_MAGIC, 1, struct ptp_clock_caps)
#define PTP_EXTTS_REQUEST _IOW(PTP_CLK_MAGIC, 2, struct ptp_extts_request)
#define PTP_PEROUT_REQUEST _IOW(PTP_CLK_MAGIC, 3, struct ptp_perout_request)
#define PTP_ENABLE_PPS _IOW(PTP_CLK_MAGIC, 4, int)
#define PTP_SYS_OFFSET _IOW(PTP_CLK_MAGIC, 5, struct ptp_sys_offset)
#define PTP_PIN_GETFUNC _IOWR(PTP_CLK_MAGIC, 6, struct ptp_pin_desc)
#define PTP_PIN_SETFUNC _IOW(PTP_CLK_MAGIC, 7, struct ptp_pin_desc)
#define PTP_SYS_OFFSET_PRECISE _IOWR(PTP_CLK_MAGIC, 8, struct ptp_sys_offset_precise)
#define PTP_SYS_OFFSET_EXTENDED _IOWR(PTP_CLK_MAGIC, 9, struct ptp_sys_offset_extended)
#define PTP_CLOCK_GETCAPS2 _IOR(PTP_CLK_MAGIC, 10, struct ptp_clock_caps)
#define PTP_EXTTS_REQUEST2 _IOW(PTP_CLK_MAGIC, 11, struct ptp_extts_request)
#define PTP_PEROUT_REQUEST2 _IOW(PTP_CLK_MAGIC, 12, struct ptp_perout_request)
#define PTP_ENABLE_PPS2 _IOW(PTP_CLK_MAGIC, 13, int)
#define PTP_SYS_OFFSET2 _IOW(PTP_CLK_MAGIC, 14, struct ptp_sys_offset)
#define PTP_PIN_GETFUNC2 _IOWR(PTP_CLK_MAGIC, 15, struct ptp_pin_desc)
#define PTP_PIN_SETFUNC2 _IOW(PTP_CLK_MAGIC, 16, struct ptp_pin_desc)
#define PTP_SYS_OFFSET_PRECISE2 _IOWR(PTP_CLK_MAGIC, 17, struct ptp_sys_offset_precise)
#define PTP_SYS_OFFSET_EXTENDED2 _IOWR(PTP_CLK_MAGIC, 18, struct ptp_sys_offset_extended)
#define PTP_MASK_CLEAR_ALL _IO(PTP_CLK_MAGIC, 19)
#define PTP_MASK_EN_SINGLE _IOW(PTP_CLK_MAGIC, 20, unsigned int)
struct ptp_extts_event {
  struct ptp_clock_time t;
  unsigned int index;
  unsigned int flags;
  unsigned int rsv[2];
};
#endif
```