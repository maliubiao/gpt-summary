Response:
Let's break down the thought process for analyzing this header file and generating the comprehensive response.

1. **Understand the Context:** The prompt clearly states this is a UAPI (Userspace API) header file for GPIO (General Purpose Input/Output) within the Android Bionic library. This immediately tells us:
    * It defines structures and constants for interacting with the kernel's GPIO subsystem from user-space applications.
    * It's not the implementation of GPIO itself, but rather the interface to it.
    * Bionic is the foundation of Android's userspace, so this is crucial for hardware interaction.

2. **Initial Scan and Categorization:**  Quickly read through the file, noting the major sections and keywords. I see:
    * `#ifndef`, `#define`: Standard header guard.
    * `#include`: Includes for standard Linux types and ioctl definitions.
    * `struct gpiochip_info`: Information about a GPIO chip.
    * `enum gpio_v2_line_flag`, `struct gpio_v2_line_values`, etc.: A set of structures and enums related to a "V2" GPIO interface.
    * `struct gpioline_info`, `struct gpiohandle_request`, etc.: Another set of structures, likely an older or different GPIO interface.
    * `#define GPIO_GET_CHIPINFO_IOCTL`, etc.: Definitions for ioctl commands.

    This suggests two primary interfaces for GPIO: an older one and a newer "V2" one.

3. **Focus on Functionality (Based on Structures):** Now, examine the structures and enums more closely to understand their purpose:

    * **`gpiochip_info`:** Clearly describes a GPIO controller chip (name, label, number of lines).
    * **`gpio_v2_line_*`:**  This "V2" set appears more feature-rich:
        * Flags for line characteristics (input/output, active low, pull-up/down, edge triggering).
        * Ways to get and set line values (`gpio_v2_line_values`).
        * Attributes for configuration (flags, output values, debounce).
        * Structures for requesting lines (`gpio_v2_line_request`), getting info (`gpio_v2_line_info`), and handling events (`gpio_v2_line_event`).
    * **`gpioline_*` and `gpiohandle_*`:** Seem to be a simpler interface:
        * Basic line info (`gpioline_info`).
        * Requests for handles (groups of GPIOs) with input/output direction and initial values (`gpiohandle_request`).
        * Getting and setting values of a handle (`gpiohandle_data`).
        * Requesting events on a single line (`gpioevent_request`, `gpioevent_data`).

4. **Identify Key Concepts:**  Several core GPIO concepts emerge:
    * **Chips:** Physical GPIO controllers.
    * **Lines (or Pins):** Individual GPIO signals on a chip.
    * **Handles:**  A way to group and control multiple GPIO lines together.
    * **Configuration:** Setting the direction, pull-up/down, active level, etc. of a GPIO line.
    * **Value:** The current logical state (high or low) of a GPIO line.
    * **Events:** Detecting changes in the state of a GPIO line.

5. **Relate to Android:** How does this fit into Android?  Think about common Android hardware functionalities:
    * **Touchscreens:** Often use GPIOs for interrupt signals.
    * **Buttons:**  Simple input via GPIO.
    * **LEDs:** Output control using GPIO.
    * **Sensors:**  Might use GPIO for data ready signals or I2C/SPI communication (though this header is about direct GPIO control).
    * **Peripherals:**  Many external devices interact with the Android system through GPIO.

6. **Explain Libc Functions (ioctl):** The key libc function here is `ioctl`. Explain its general purpose (device-specific control) and how these `#define`d constants are used to specify the operation and data structures for the GPIO subsystem. Emphasize that the *implementation* is in the kernel, not in this header.

7. **Dynamic Linker (SO Layout and Linking):** This header itself *doesn't* directly involve dynamic linking. It defines *data structures*. However, to interact with the kernel using these structures, applications will likely use functions from libraries (like `libc`) that make the `ioctl` calls. Therefore:
    * Create a simple SO layout example of an application using a hypothetical `libgpio.so`.
    * Explain the linking process (symbol resolution).
    * Emphasize that the kernel interface itself doesn't involve dynamic linking in the same way as userspace libraries.

8. **Logic and Assumptions:**  For things like event handling, imagine a scenario:
    * **Input:** Request an interrupt on a button press.
    * **Output:**  Kernel sends an event notification to the application.

9. **Common Mistakes:** Think about typical errors developers make when dealing with hardware:
    * Incorrectly configuring direction (input vs. output).
    * Not handling active-low signals correctly.
    * Race conditions when multiple threads access GPIOs.
    * Permission issues.

10. **Android Framework/NDK Path and Frida:** Trace the path from a high-level Android concept down to this header:
    * Android Framework (Java APIs like `Gpio`).
    * Native code (NDK) using C/C++.
    * System calls (via `ioctl`) using the structures defined here.
    * Kernel GPIO driver handling the actual hardware.

    Show a simple Frida hook example targeting `ioctl` to intercept GPIO calls.

11. **Structure and Language:** Organize the information logically using headings and bullet points. Use clear and concise Chinese. Explain technical terms.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Should I explain the kernel GPIO driver implementation? **Correction:** No, the prompt is about the *header file*. Focus on the user-space API.
* **Realization:** The header has two distinct sets of GPIO structures. **Action:**  Explain both and highlight the "V2" as likely newer.
* **Consideration:** How much detail about `ioctl` is necessary? **Decision:**  Explain the core concept and how the macros work but avoid getting bogged down in the low-level details of system calls.
* **Important point:**  The dynamic linker is not directly involved with *this* file, but it's relevant to how applications use the functionality defined here. **Clarification:** Emphasize the role of libraries like `libc` in making the system calls.

By following this structured thought process, combining domain knowledge with careful analysis of the provided code, and iterating on the explanations, I can generate a comprehensive and accurate response to the user's request.
这是一个定义了 Linux GPIO (General Purpose Input/Output) 子系统的用户空间 API 的头文件。它不是 Bionic C 库或动态链接器的实现代码，而是定义了用户空间程序如何与内核中的 GPIO 驱动程序交互的接口。

**它的功能：**

这个头文件定义了用于与 Linux 内核中的 GPIO 子系统交互的数据结构和 ioctl 命令。其主要功能是提供了一种标准的方式，让用户空间程序能够：

1. **查询 GPIO 芯片信息：** 获取系统中存在的 GPIO 控制器芯片的信息，例如芯片名称、标签和拥有的 GPIO 线数量。
2. **查询 GPIO 线信息：** 获取特定 GPIO 线的信息，例如线偏移、标志（输入/输出、高/低电平有效等）、名称和使用者。
3. **请求和释放 GPIO 线：**  让用户空间程序能够请求使用一个或多个 GPIO 线。在请求时，可以配置线的方向（输入或输出）、初始值（如果作为输出）、边沿触发类型（用于中断）等。
4. **设置和获取 GPIO 线的值：**  允许程序读取输入 GPIO 线的当前状态，或者设置输出 GPIO 线的状态（高电平或低电平）。
5. **监听 GPIO 线事件：**  使程序能够等待 GPIO 线上发生的特定事件，例如上升沿或下降沿。

**与 Android 功能的关系及举例说明：**

GPIO 在 Android 系统中扮演着至关重要的角色，因为它允许软件与硬件进行交互。 几乎所有的 Android 设备都依赖 GPIO 来控制各种硬件组件，例如：

* **屏幕背光控制：**  使用 GPIO 控制背光的开启和关闭，以及调节亮度。
    * **例子：**  Android 系统可能会使用一个 GPIO 线来控制背光模组的使能引脚。当用户调整屏幕亮度时，Framework 层会调用 Native 层，最终通过 `ioctl` 和这个头文件中定义的结构来设置 GPIO 线的状态，从而控制背光的亮度。
* **按键和开关：**  物理按键（音量键、电源键等）的状态通常通过连接到 GPIO 输入线来检测。
    * **例子：** 当用户按下电源键时，连接到该按键的 GPIO 输入线电平发生变化。内核的 GPIO 驱动程序检测到这个变化，并通过事件或其他机制通知用户空间。Android 的 SystemServer 进程会监听这些事件并采取相应的操作，例如弹出电源菜单。
* **LED 指示灯：**  控制 LED 灯的亮灭。
    * **例子：** 充电指示灯、通知指示灯等都可能通过 GPIO 输出线进行控制。当需要点亮 LED 时，Android 系统会设置相应的 GPIO 输出线为高电平（或低电平，取决于硬件设计）。
* **传感器：**  某些传感器可能使用 GPIO 线作为数据就绪信号或中断信号。
    * **例子：** 一个加速度传感器可能使用一个 GPIO 输出线来通知 Android 系统有新的加速度数据可用。
* **外围设备控制：**  控制各种外围设备，例如蜂鸣器、振动器等。
    * **例子：** 当 Android 设备需要振动时，系统会设置控制振动器的 GPIO 输出线为高电平或低电平，从而驱动振动马达。

**libc 函数的功能实现：**

这个头文件本身 **不包含任何 libc 函数的实现**。它仅仅定义了数据结构和常量。真正实现与 GPIO 交互功能的代码位于 Android 的 C 库 (Bionic) 和内核中。

用户空间程序通常使用 `ioctl` 系统调用来与设备驱动程序进行通信，包括 GPIO 驱动程序。  `ioctl` 的功能是向设备发送控制命令并传递数据。

在这个头文件中定义的 `#define` 宏，例如 `GPIO_GET_CHIPINFO_IOCTL`、`GPIO_GET_LINEHANDLE_IOCTL` 等，就是用于 `ioctl` 调用的命令码。  当用户空间程序调用 `ioctl` 时，它会传递以下信息：

1. **文件描述符 (fd):**  指向代表 GPIO 字符设备的打开文件的描述符（通常是 `/dev/gpiochipX`）。
2. **请求码 (request):**  即上面提到的 `GPIO_*_IOCTL` 宏之一，指示要执行的操作。
3. **参数 (argp):**  一个指向数据结构的指针，该结构包含要发送给驱动程序的数据或用于接收驱动程序返回的数据。这些数据结构就是这个头文件中定义的结构体，例如 `gpiochip_info`、`gpiohandle_request` 等。

**例如，获取 GPIO 芯片信息的流程可能是这样的：**

1. 用户空间程序打开 GPIO 字符设备文件，例如 `/dev/gpiochip0`，获得文件描述符 `fd`。
2. 程序声明一个 `gpiochip_info` 结构体变量 `info`。
3. 程序调用 `ioctl(fd, GPIO_GET_CHIPINFO_IOCTL, &info)`。
4. 内核中的 GPIO 驱动程序接收到 `ioctl` 调用，根据 `GPIO_GET_CHIPINFO_IOCTL` 命令，读取 GPIO 芯片的硬件信息，并将信息填充到用户空间传递进来的 `info` 结构体中。
5. `ioctl` 调用返回，`info` 结构体现在包含了 GPIO 芯片的信息，例如名称和线数量。

**涉及 dynamic linker 的功能：**

这个头文件本身 **不涉及 dynamic linker 的功能**。它定义的是内核接口。Dynamic linker (如 Android 的 `linker64` 或 `linker`) 的作用是在程序启动时加载和链接共享库 (.so 文件)。

然而，为了使用这个头文件中定义的 GPIO 接口，用户空间程序通常会链接到 C 库 (libc.so)。libc.so 中包含了 `open`, `close`, `ioctl` 等系统调用封装函数。

**SO 布局样本：**

假设我们有一个应用程序 `my_gpio_app` 需要使用 GPIO 功能，它可能会链接到 `libc.so`。一个可能的 SO 布局如下：

```
/system/bin/my_gpio_app  (可执行文件)
/system/lib64/libc.so   (Bionic C 库)
```

**链接的处理过程：**

1. 当 `my_gpio_app` 启动时，操作系统的加载器会加载可执行文件到内存。
2. Dynamic linker 会被调用，并读取 `my_gpio_app` 的 ELF 头中的动态链接信息。
3. Dynamic linker 会解析 `my_gpio_app` 依赖的共享库，在本例中是 `libc.so`。
4. Dynamic linker 会加载 `libc.so` 到内存中。
5. Dynamic linker 会进行符号解析，将 `my_gpio_app` 中对 `open`, `close`, `ioctl` 等函数的调用重定向到 `libc.so` 中对应的函数实现。

**涉及 dynamic linker 但与此头文件不直接相关的例子：**

如果 Android 提供了一个专门用于 GPIO 操作的共享库（虽然通常直接使用 libc 中的系统调用），例如 `libgpio.so`，那么链接过程会更明显：

```
/system/bin/my_gpio_app
/system/lib64/libc.so
/system/lib64/libgpio.so
```

在这种情况下，`my_gpio_app` 会链接到 `libgpio.so`，`libgpio.so` 可能会封装对 `ioctl` 的调用，并提供更方便的 API。 Dynamic linker 会加载 `libgpio.so`，并解析 `my_gpio_app` 中对 `libgpio.so` 中函数的调用。

**逻辑推理（假设输入与输出）：**

假设我们想读取一个连接到 GPIO 线 5 的按键的状态。

**假设输入：**

* GPIO 芯片设备文件描述符：`fd` (假设已成功打开 `/dev/gpiochip0`)
* 要读取的 GPIO 线偏移：`line_offset = 5`

**处理过程：**

1. 构建 `gpiohandle_request` 结构体，指定要请求的线偏移为 5，方向为输入。
2. 使用 `ioctl(fd, GPIO_GET_LINEHANDLE_IOCTL, &request)` 请求 GPIO 线。
3. 如果请求成功，会得到一个新的文件描述符 `handle_fd`，用于操作该 GPIO 线。
4. 构建 `gpiohandle_data` 结构体用于接收数据。
5. 使用 `ioctl(handle_fd, GPIOHANDLE_GET_LINE_VALUES_IOCTL, &data)` 读取 GPIO 线的值。

**假设输出：**

* 如果按键被按下（假设是低电平有效），`data.values[0]` 可能为 0。
* 如果按键未按下，`data.values[0]` 可能为 1。

**用户或编程常见的使用错误：**

1. **权限错误：** 尝试访问 GPIO 设备文件时没有足够的权限。需要确保应用程序以具有相应权限的用户或组运行。
2. **错误的 GPIO 线偏移：** 使用了不存在或不正确的 GPIO 线编号。需要查阅硬件文档来确定正确的线偏移。
3. **方向配置错误：** 将输入线配置为输出，或将输出线配置为输入，会导致功能异常。
4. **竞争条件：** 多个进程或线程同时尝试访问和控制同一个 GPIO 线，可能导致状态不一致。需要使用适当的同步机制（如互斥锁）来保护对 GPIO 的访问。
5. **忘记释放 GPIO 线：** 在使用完 GPIO 线后没有调用相应的释放操作，可能导致资源泄漏，其他应用程序可能无法使用这些线。
6. **没有处理边沿触发事件：** 如果配置了边沿触发中断，但应用程序没有正确地等待和处理中断事件，会导致事件丢失或程序挂起。
7. **混淆高电平有效和低电平有效：** 有些 GPIO 线是高电平有效，有些是低电平有效。如果在代码中没有正确处理，会导致逻辑反转。

**Android Framework 或 NDK 如何一步步到达这里：**

1. **Android Framework (Java 层):**  Android Framework 中通常会提供一些 Java API 来访问硬件功能，包括 GPIO。例如，可能会有与硬件相关的服务（HAL - Hardware Abstraction Layer）提供访问 GPIO 的接口。
2. **Native 代码 (NDK):**  Framework 的 Java 代码最终会通过 JNI (Java Native Interface) 调用 Native 代码（C/C++）。这些 Native 代码通常位于硬件抽象层 (HAL) 或系统服务中。
3. **HAL (Hardware Abstraction Layer):** HAL 的职责是封装硬件细节，向上层提供统一的接口。对于 GPIO，HAL 可能会提供一些函数，例如 `gpio_request()`, `gpio_direction_input()`, `gpio_set_value()` 等。
4. **系统调用 (ioctl):** HAL 的实现最终会调用底层的系统调用，例如 `open()`, `close()`, `ioctl()`。在 GPIO 的情况下，HAL 会打开 `/dev/gpiochipX` 设备文件，并使用 `ioctl()` 系统调用，并使用这个头文件中定义的结构体和 ioctl 命令码与内核的 GPIO 驱动程序进行通信。

**Frida Hook 示例调试这些步骤：**

可以使用 Frida 来 hook 相关的函数调用，观察参数和返回值，从而调试 GPIO 的交互过程。

**Frida Hook 示例 (Hook `ioctl` 系统调用):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['api'], message['payload']['args']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(sys.argv[0]))
        sys.exit(1)

    target = sys.argv[1]
    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();
            const argp = args[2];

            let api_name = "unknown_ioctl";
            let api_args = [];

            // 这里可以根据 request 的值来判断是哪个 GPIO ioctl，并解析 argp 参数
            if (request === 0xb401) { // GPIO_GET_CHIPINFO_IOCTL
                api_name = "GPIO_GET_CHIPINFO_IOCTL";
                const infoPtr = ptr(argp);
                api_args.push(Memory.readUtf8String(infoPtr.add(0))); // name
                api_args.push(Memory.readUtf8String(infoPtr.add(32))); // label
                api_args.push(Memory.readU32(infoPtr.add(64))); // lines
            } else if (request === 0xb403) { // GPIO_GET_LINEHANDLE_IOCTL
                api_name = "GPIO_GET_LINEHANDLE_IOCTL";
                // ... 解析 gpiohandle_request 结构体 ...
            }
            // ... 添加其他 GPIO ioctl 的解析 ...

            send({ 'api': api_name, 'args': api_args });
        },
        onLeave: function(retval) {
            // console.log("Return value:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Waiting for messages...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法：**

1. 将上述 Python 代码保存为 `gpio_hook.py`。
2. 运行 Frida 服务。
3. 找到你想要调试的进程的名称或 PID（例如，一个使用 GPIO 的应用程序的进程）。
4. 运行 `python gpio_hook.py <进程名称或PID>`。

这个 Frida 脚本会 hook `ioctl` 系统调用。当目标进程调用 `ioctl` 时，脚本会尝试识别是否是 GPIO 相关的 ioctl，并打印出 ioctl 的名称和参数。你需要根据具体的 `request` 值来解析 `argp` 指向的数据结构，才能看到更详细的 GPIO 操作信息。

通过这种方式，你可以观察 Android Framework 或 NDK 代码如何通过 `ioctl` 与内核的 GPIO 驱动程序进行交互，从而理解数据结构的使用和交互流程。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/gpio.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_GPIO_H_
#define _UAPI_GPIO_H_
#include <linux/const.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#define GPIO_MAX_NAME_SIZE 32
struct gpiochip_info {
  char name[GPIO_MAX_NAME_SIZE];
  char label[GPIO_MAX_NAME_SIZE];
  __u32 lines;
};
#define GPIO_V2_LINES_MAX 64
#define GPIO_V2_LINE_NUM_ATTRS_MAX 10
enum gpio_v2_line_flag {
  GPIO_V2_LINE_FLAG_USED = _BITULL(0),
  GPIO_V2_LINE_FLAG_ACTIVE_LOW = _BITULL(1),
  GPIO_V2_LINE_FLAG_INPUT = _BITULL(2),
  GPIO_V2_LINE_FLAG_OUTPUT = _BITULL(3),
  GPIO_V2_LINE_FLAG_EDGE_RISING = _BITULL(4),
  GPIO_V2_LINE_FLAG_EDGE_FALLING = _BITULL(5),
  GPIO_V2_LINE_FLAG_OPEN_DRAIN = _BITULL(6),
  GPIO_V2_LINE_FLAG_OPEN_SOURCE = _BITULL(7),
  GPIO_V2_LINE_FLAG_BIAS_PULL_UP = _BITULL(8),
  GPIO_V2_LINE_FLAG_BIAS_PULL_DOWN = _BITULL(9),
  GPIO_V2_LINE_FLAG_BIAS_DISABLED = _BITULL(10),
  GPIO_V2_LINE_FLAG_EVENT_CLOCK_REALTIME = _BITULL(11),
  GPIO_V2_LINE_FLAG_EVENT_CLOCK_HTE = _BITULL(12),
};
struct gpio_v2_line_values {
  __aligned_u64 bits;
  __aligned_u64 mask;
};
enum gpio_v2_line_attr_id {
  GPIO_V2_LINE_ATTR_ID_FLAGS = 1,
  GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES = 2,
  GPIO_V2_LINE_ATTR_ID_DEBOUNCE = 3,
};
struct gpio_v2_line_attribute {
  __u32 id;
  __u32 padding;
  union {
    __aligned_u64 flags;
    __aligned_u64 values;
    __u32 debounce_period_us;
  };
};
struct gpio_v2_line_config_attribute {
  struct gpio_v2_line_attribute attr;
  __aligned_u64 mask;
};
struct gpio_v2_line_config {
  __aligned_u64 flags;
  __u32 num_attrs;
  __u32 padding[5];
  struct gpio_v2_line_config_attribute attrs[GPIO_V2_LINE_NUM_ATTRS_MAX];
};
struct gpio_v2_line_request {
  __u32 offsets[GPIO_V2_LINES_MAX];
  char consumer[GPIO_MAX_NAME_SIZE];
  struct gpio_v2_line_config config;
  __u32 num_lines;
  __u32 event_buffer_size;
  __u32 padding[5];
  __s32 fd;
};
struct gpio_v2_line_info {
  char name[GPIO_MAX_NAME_SIZE];
  char consumer[GPIO_MAX_NAME_SIZE];
  __u32 offset;
  __u32 num_attrs;
  __aligned_u64 flags;
  struct gpio_v2_line_attribute attrs[GPIO_V2_LINE_NUM_ATTRS_MAX];
  __u32 padding[4];
};
enum gpio_v2_line_changed_type {
  GPIO_V2_LINE_CHANGED_REQUESTED = 1,
  GPIO_V2_LINE_CHANGED_RELEASED = 2,
  GPIO_V2_LINE_CHANGED_CONFIG = 3,
};
struct gpio_v2_line_info_changed {
  struct gpio_v2_line_info info;
  __aligned_u64 timestamp_ns;
  __u32 event_type;
  __u32 padding[5];
};
enum gpio_v2_line_event_id {
  GPIO_V2_LINE_EVENT_RISING_EDGE = 1,
  GPIO_V2_LINE_EVENT_FALLING_EDGE = 2,
};
struct gpio_v2_line_event {
  __aligned_u64 timestamp_ns;
  __u32 id;
  __u32 offset;
  __u32 seqno;
  __u32 line_seqno;
  __u32 padding[6];
};
#define GPIOLINE_FLAG_KERNEL (1UL << 0)
#define GPIOLINE_FLAG_IS_OUT (1UL << 1)
#define GPIOLINE_FLAG_ACTIVE_LOW (1UL << 2)
#define GPIOLINE_FLAG_OPEN_DRAIN (1UL << 3)
#define GPIOLINE_FLAG_OPEN_SOURCE (1UL << 4)
#define GPIOLINE_FLAG_BIAS_PULL_UP (1UL << 5)
#define GPIOLINE_FLAG_BIAS_PULL_DOWN (1UL << 6)
#define GPIOLINE_FLAG_BIAS_DISABLE (1UL << 7)
struct gpioline_info {
  __u32 line_offset;
  __u32 flags;
  char name[GPIO_MAX_NAME_SIZE];
  char consumer[GPIO_MAX_NAME_SIZE];
};
#define GPIOHANDLES_MAX 64
enum {
  GPIOLINE_CHANGED_REQUESTED = 1,
  GPIOLINE_CHANGED_RELEASED,
  GPIOLINE_CHANGED_CONFIG,
};
struct gpioline_info_changed {
  struct gpioline_info info;
  __u64 timestamp;
  __u32 event_type;
  __u32 padding[5];
};
#define GPIOHANDLE_REQUEST_INPUT (1UL << 0)
#define GPIOHANDLE_REQUEST_OUTPUT (1UL << 1)
#define GPIOHANDLE_REQUEST_ACTIVE_LOW (1UL << 2)
#define GPIOHANDLE_REQUEST_OPEN_DRAIN (1UL << 3)
#define GPIOHANDLE_REQUEST_OPEN_SOURCE (1UL << 4)
#define GPIOHANDLE_REQUEST_BIAS_PULL_UP (1UL << 5)
#define GPIOHANDLE_REQUEST_BIAS_PULL_DOWN (1UL << 6)
#define GPIOHANDLE_REQUEST_BIAS_DISABLE (1UL << 7)
struct gpiohandle_request {
  __u32 lineoffsets[GPIOHANDLES_MAX];
  __u32 flags;
  __u8 default_values[GPIOHANDLES_MAX];
  char consumer_label[GPIO_MAX_NAME_SIZE];
  __u32 lines;
  int fd;
};
struct gpiohandle_config {
  __u32 flags;
  __u8 default_values[GPIOHANDLES_MAX];
  __u32 padding[4];
};
struct gpiohandle_data {
  __u8 values[GPIOHANDLES_MAX];
};
#define GPIOEVENT_REQUEST_RISING_EDGE (1UL << 0)
#define GPIOEVENT_REQUEST_FALLING_EDGE (1UL << 1)
#define GPIOEVENT_REQUEST_BOTH_EDGES ((1UL << 0) | (1UL << 1))
struct gpioevent_request {
  __u32 lineoffset;
  __u32 handleflags;
  __u32 eventflags;
  char consumer_label[GPIO_MAX_NAME_SIZE];
  int fd;
};
#define GPIOEVENT_EVENT_RISING_EDGE 0x01
#define GPIOEVENT_EVENT_FALLING_EDGE 0x02
struct gpioevent_data {
  __u64 timestamp;
  __u32 id;
};
#define GPIO_GET_CHIPINFO_IOCTL _IOR(0xB4, 0x01, struct gpiochip_info)
#define GPIO_GET_LINEINFO_UNWATCH_IOCTL _IOWR(0xB4, 0x0C, __u32)
#define GPIO_V2_GET_LINEINFO_IOCTL _IOWR(0xB4, 0x05, struct gpio_v2_line_info)
#define GPIO_V2_GET_LINEINFO_WATCH_IOCTL _IOWR(0xB4, 0x06, struct gpio_v2_line_info)
#define GPIO_V2_GET_LINE_IOCTL _IOWR(0xB4, 0x07, struct gpio_v2_line_request)
#define GPIO_V2_LINE_SET_CONFIG_IOCTL _IOWR(0xB4, 0x0D, struct gpio_v2_line_config)
#define GPIO_V2_LINE_GET_VALUES_IOCTL _IOWR(0xB4, 0x0E, struct gpio_v2_line_values)
#define GPIO_V2_LINE_SET_VALUES_IOCTL _IOWR(0xB4, 0x0F, struct gpio_v2_line_values)
#define GPIO_GET_LINEINFO_IOCTL _IOWR(0xB4, 0x02, struct gpioline_info)
#define GPIO_GET_LINEHANDLE_IOCTL _IOWR(0xB4, 0x03, struct gpiohandle_request)
#define GPIO_GET_LINEEVENT_IOCTL _IOWR(0xB4, 0x04, struct gpioevent_request)
#define GPIOHANDLE_GET_LINE_VALUES_IOCTL _IOWR(0xB4, 0x08, struct gpiohandle_data)
#define GPIOHANDLE_SET_LINE_VALUES_IOCTL _IOWR(0xB4, 0x09, struct gpiohandle_data)
#define GPIOHANDLE_SET_CONFIG_IOCTL _IOWR(0xB4, 0x0A, struct gpiohandle_config)
#define GPIO_GET_LINEINFO_WATCH_IOCTL _IOWR(0xB4, 0x0B, struct gpioline_info)
#endif

"""

```