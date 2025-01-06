Response:
Let's break down the thought process for analyzing this `uhid.h` header file.

**1. Initial Understanding and Goal Identification:**

The first step is to recognize the context:  "bionic/libc/kernel/uapi/linux/uhid.handroid". This immediately signals that this is a header file defining the *userspace API* to interact with a kernel driver. The "uapi" signifies user-space API. "uhid" strongly suggests "USB HID" (Human Interface Device), and "handroid" indicates Android-specific modifications or usage.

The request asks for several things:

* **Functionality:** What does this code *do*?
* **Android Relevance:** How is it used in Android?
* **libc Implementation Details:**  (This is a bit of a misdirection, as this header *defines* interfaces, not implements them within libc).
* **Dynamic Linker:** How does this relate to dynamic linking?
* **Logic/Assumptions:**  Any inferred behavior.
* **Common Errors:**  Pitfalls for developers.
* **Framework/NDK Path:** How does data get here from higher levels?
* **Frida Hook Example:** How to observe this in action.

**2. Core Functionality Deduction (Based on Structures and Enums):**

The most direct way to understand the functionality is to examine the defined structures and enumerations.

* **`enum uhid_event_type`:** This is the central point. It lists all the possible commands/events that can be sent to or received from the `uhid` driver. Keywords like `CREATE`, `DESTROY`, `START`, `STOP`, `OPEN`, `CLOSE`, `INPUT`, `OUTPUT`, `GET_REPORT`, `SET_REPORT` strongly suggest the lifecycle and data transfer mechanisms of a virtual HID device.

* **Structures (`uhid_create2_req`, `uhid_start_req`, etc.):**  These structures define the data payloads associated with each event type. Analyzing the members of these structures provides details on what information is required or provided for each operation. For instance, `uhid_create2_req` contains fields like `name`, `phys`, `uniq`, `rd_size`, and `rd_data`, pointing to the creation and descriptor setup of the virtual HID device. `uhid_input2_req` and `uhid_output_req` handle data transfer.

* **Macros (`UHID_DATA_MAX`):** These define constants relevant to the communication.

* **`union uhid_event`:** This structure encapsulates all possible event data, with the `type` field determining which member of the union is valid. This is a common pattern for event-driven interfaces.

**3. Android Relevance and Examples:**

Knowing this is for virtual HID devices within Android, the next step is to think about *why* Android needs this. Virtual input devices are crucial for:

* **Emulators:** Simulating keyboards, mice, touchscreens.
* **Accessibility Services:**  Allowing assistive technologies to provide input.
* **Testing Frameworks:** Programmatically injecting input events for testing purposes.
* **Custom Input Solutions:**  Developers might create their own virtual input devices for specialized applications.

Concrete examples are key here:  Think of an accessibility service that maps voice commands to keyboard presses. Or a testing framework that sends a sequence of touch events to an application.

**4. Addressing Misconceptions (libc Implementation):**

The request asks about libc function implementation. This header file *defines* the API. The actual implementation of *sending* these events to the kernel happens via system calls (like `ioctl` or `write` to a file descriptor associated with the `uhid` device). It's important to clarify this distinction.

**5. Dynamic Linker Aspects:**

This header file itself doesn't directly involve the dynamic linker. However, *using* this API in an Android application *does*. The application would link against libc, which provides the necessary system call wrappers.

The thought process here involves visualizing the `.so` files involved. The application would link against `libc.so`. The `uhid` driver is part of the kernel, so there's no direct `.so` for it in userspace. The dynamic linker resolves the `libc` dependency.

**6. Logic and Assumptions:**

Here, you make informed guesses about the behavior. For example:

* The `CREATE` event likely creates a virtual device node.
* `START` might make the device visible to the system.
* `INPUT` sends data *to* the host, while `OUTPUT` receives data *from* the host (or another system component acting as the host for this virtual device).
* The `rd_data` in the `CREATE` request is likely the HID Report Descriptor, which defines the structure of the data exchanged.

**7. Common Errors:**

Think about the practical problems developers might face:

* **Incorrect Report Descriptors:**  Crucial for the host system to understand the device.
* **Incorrect Data Sizes:**  Mismatches between the declared and actual data sizes.
* **Race Conditions:**  If multiple processes try to control the same virtual device.
* **Permissions:**  Not having the necessary permissions to access the `uhid` device node.

**8. Framework/NDK Path:**

Trace the flow of control from the higher levels of Android:

* **Framework (Java):**  Look for Android APIs that deal with input or virtual devices. `InputManager`, `InputDevice`, and related classes are good starting points. The implementation likely involves native code.
* **NDK (C++):**  Show how an NDK developer would use standard file operations (`open`, `ioctl`, `write`) to interact with the `uhid` device node.

**9. Frida Hooking:**

Think about which points in the interaction would be interesting to observe:

* **Opening the `uhid` device node:** Hooking the `open` system call.
* **Sending events:** Hooking the `write` system call, focusing on writes to the `uhid` file descriptor.
* **Potentially `ioctl`:** If that's used for specific commands.

The Frida example should demonstrate how to intercept these calls and inspect the data being passed, particularly the `uhid_event` structure.

**Self-Correction/Refinement:**

During the process, I might realize:

* **Initial Misunderstanding:**  If I initially thought this header defined libc functions, I'd correct myself and focus on the API definition aspect.
* **Missing Details:**  I might initially forget to mention the HID Report Descriptor and then add that in.
* **Clarity:** I'd review my explanations to ensure they are clear and easy to understand, using precise terminology.

By following this structured approach, combining code analysis with knowledge of Android internals and common development practices, we can provide a comprehensive and accurate answer to the request.
这个头文件 `uhid.h` 定义了用户空间程序与 Linux 内核中的 `uhid` (Userspace HID) 驱动进行交互的接口。`uhid` 驱动允许用户空间程序创建和管理虚拟的 HID (Human Interface Device) 设备。这使得用户空间的应用程序可以模拟键盘、鼠标、触摸屏等输入设备，并将输入事件注入到系统中。

由于它位于 `bionic/libc/kernel/uapi/linux/` 目录下，这意味着它定义了用户空间可见的内核接口。`bionic` 是 Android 的 C 库，但这个文件本身是 Linux 内核头文件的拷贝，供 `bionic` 使用，以便用户空间程序能够与内核的 `uhid` 驱动进行交互。

**文件功能总结:**

1. **定义 `uhid` 事件类型 (`enum uhid_event_type`):**  列出了所有可以发送给 `uhid` 驱动的命令，以及从驱动接收到的事件类型，例如创建设备、销毁设备、发送输入事件等。
2. **定义数据结构 (`struct uhid_create2_req`, `struct uhid_input2_req` 等):**  描述了与不同 `uhid` 事件关联的数据结构，例如创建设备时需要的设备名称、物理地址、报告描述符等，以及发送输入/输出报告时的数据格式。
3. **定义设备标志 (`enum uhid_dev_flag`):**  定义了虚拟 HID 设备的特性标志，例如是否使用编号的 Feature、Output 或 Input 报告。
4. **定义报告类型 (`enum uhid_report_type`):**  定义了 HID 报告的类型，如 Feature Report、Output Report 和 Input Report。
5. **定义遗留事件类型 (`enum uhid_legacy_event_type`):**  为旧版本的 `uhid` 接口提供兼容性。
6. **定义统一的事件结构 (`struct uhid_event`):**  使用联合体 `union` 来包含所有可能的事件数据，并通过 `type` 字段来区分不同的事件类型。

**与 Android 功能的关系及举例说明:**

`uhid` 在 Android 中扮演着重要的角色，因为它允许在用户空间模拟硬件输入设备。这在以下场景中非常有用：

* **模拟器 (Emulator):** Android 模拟器需要模拟键盘、鼠标和触摸屏等输入设备，以便用户可以在 PC 上操作模拟的 Android 系统。`uhid` 驱动允许模拟器在用户空间创建这些虚拟设备，并将用户的操作转换为 Android 系统可以理解的输入事件。
    * **例子:** 当你在 Android 模拟器中点击鼠标左键时，模拟器程序会通过 `uhid` 驱动发送一个相应的鼠标按键事件到模拟的 Android 系统。
* **辅助功能 (Accessibility Services):**  一些辅助功能服务可能需要模拟输入事件来与应用程序进行交互。例如，一个语音控制应用可能需要将语音指令转换为屏幕点击或键盘输入。
    * **例子:** 一个辅助功能服务接收到 "向上滚动" 的语音指令后，可以使用 `uhid` 驱动发送一个模拟的向上滚动事件。
* **自动化测试 (Automation Testing):**  自动化测试框架可以使用 `uhid` 驱动来模拟用户与应用程序的交互，例如点击按钮、输入文本等，从而实现 UI 自动化测试。
    * **例子:** 一个 UI 测试脚本可以使用 `uhid` 驱动模拟一系列的触摸事件来测试应用的特定功能。
* **虚拟输入设备 (Virtual Input Devices):**  开发者可以创建自定义的虚拟输入设备，用于特定的应用程序或场景。
    * **例子:**  一个游戏手柄模拟器可以使用 `uhid` 驱动来创建一个虚拟的游戏手柄设备，让不支持物理手柄的游戏也能通过模拟器进行操作。

**libc 函数的功能实现:**

这个头文件本身 **并没有实现任何 libc 函数**。它只是定义了与内核 `uhid` 驱动交互所需的数据结构和枚举类型。

用户空间的程序需要使用 **系统调用** 来与 `/dev/uhid` 设备节点进行通信，从而使用 `uhid` 驱动的功能。常见的系统调用包括：

* **`open()`:** 打开 `/dev/uhid` 设备节点。
* **`write()`:** 将 `uhid_event` 结构体的数据写入 `/dev/uhid` 文件描述符，从而向内核 `uhid` 驱动发送命令。
* **`read()`:** 从 `/dev/uhid` 文件描述符读取数据，接收来自内核 `uhid` 驱动的事件。
* **`close()`:** 关闭 `/dev/uhid` 设备节点。
* **`ioctl()`:**  虽然 `uhid` 的主要交互是通过 `read` 和 `write` 进行，但在某些情况下，也可能使用 `ioctl` 进行特定的控制操作（尽管在 `uhid` 中不常见）。

`bionic` 的 libc 提供了这些系统调用的封装函数，例如 `open`, `write`, `read`, `close` 等。开发者可以使用这些 libc 函数来与 `uhid` 驱动进行交互。

**涉及 dynamic linker 的功能:**

这个头文件本身并不直接涉及 dynamic linker 的功能。Dynamic linker (例如 Android 中的 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 并解析符号依赖关系。

当一个使用了 `uhid` 功能的应用程序运行时，它会链接到 `bionic` 的 libc (`libc.so`)。libc 提供了与内核进行交互所需的系统调用封装。Dynamic linker 负责在应用程序启动时加载 `libc.so`，并解析应用程序对 libc 函数的调用。

**so 布局样本和链接处理过程:**

假设有一个名为 `my_uhid_app` 的应用程序使用了 `uhid` 功能：

**so 布局样本:**

```
/system/bin/my_uhid_app  (可执行文件)
/system/lib64/libc.so   (bionic 的 C 库)
```

**链接处理过程:**

1. **编译时链接:**  在编译 `my_uhid_app` 时，链接器会将应用程序与 libc 链接起来。这意味着应用程序的可执行文件中会记录它需要使用 `libc.so` 中的哪些函数（例如 `open`, `write`）。
2. **运行时链接:** 当 Android 系统启动 `my_uhid_app` 时，`linker64` (或 `linker` 在 32 位系统上) 会执行以下步骤：
   a. 加载 `my_uhid_app` 到内存中。
   b. 读取 `my_uhid_app` 的动态链接信息，识别出它依赖于 `libc.so`。
   c. 在预定义的路径中查找 `libc.so` (通常是 `/system/lib64` 或 `/system/lib`)。
   d. 将 `libc.so` 加载到内存中。
   e. **符号解析:** 将 `my_uhid_app` 中对 libc 函数的调用地址，替换为 `libc.so` 中对应函数的实际内存地址。这个过程就是链接。
   f. 完成链接后，`my_uhid_app` 就可以调用 `libc.so` 中提供的系统调用封装函数，例如 `open("/dev/uhid", ...)`。

**逻辑推理、假设输入与输出:**

假设一个应用程序想要创建一个虚拟键盘设备并发送一个 'A' 键的按下事件。

**假设输入:**

1. **创建设备请求 (UHID_CREATE2):** 应用程序会构造一个 `uhid_event` 结构体，其 `type` 字段设置为 `UHID_CREATE2`，并填充 `u.create2` 字段，包括：
   * `name`: "Virtual Keyboard"
   * `phys`: "virt/keyboard0"
   * `uniq`: "my-unique-id"
   * `rd_size`: 报告描述符的大小
   * `rd_data`:  键盘的 HID 报告描述符 (定义了键盘的按键布局和报告格式)
   * 其他字段，如 `bus`, `vendor`, `product`, `version`, `country`。

2. **启动设备请求 (UHID_START):** 创建成功后，应用程序会发送一个 `UHID_START` 事件，使设备生效。

3. **输入事件请求 (UHID_INPUT2):**  要发送 'A' 键的按下事件，应用程序会构造一个 `uhid_event` 结构体，其 `type` 字段设置为 `UHID_INPUT2`，并填充 `u.input2` 字段：
   * `size`: 输入报告数据的大小
   * `data`:  包含 'A' 键按下信息的输入报告数据，这会根据键盘的报告描述符进行编码。

**预期输出:**

* **创建设备:** 内核 `uhid` 驱动会创建一个新的虚拟 HID 设备节点，通常在 `/dev/input/eventX` (X 是一个数字)。
* **启动设备:** 该虚拟设备会出现在系统中，并可以被其他应用程序识别为键盘设备。
* **输入事件:**  当应用程序发送 'A' 键的 `UHID_INPUT2` 事件后，系统会接收到一个键盘按下事件，就像用户按下了真实的 'A' 键一样。当前获得焦点的应用程序会接收到这个输入事件。

**用户或编程常见的使用错误:**

1. **错误的报告描述符 (Report Descriptor):**  HID 设备的报告描述符定义了设备的功能和数据格式。如果提供的报告描述符不正确或不完整，系统可能无法正确识别和使用该虚拟设备。
    * **例子:**  描述符中没有定义键盘按键的输入报告，导致发送按键事件时系统无法识别。
2. **数据大小不匹配:**  发送 `UHID_INPUT2` 或 `UHID_OUTPUT` 事件时，`size` 字段必须与 `data` 字段的实际大小匹配。不匹配可能导致数据截断或读取错误。
    * **例子:**  `size` 设置为 10，但 `data` 中只包含了 5 个字节的数据。
3. **未正确打开和关闭设备:**  在使用 `uhid` 驱动之前，需要先打开 `/dev/uhid` 设备节点。使用完毕后，应正确关闭该文件描述符，释放资源。
    * **例子:**  程序打开 `/dev/uhid` 后忘记关闭，可能导致资源泄漏。
4. **权限问题:**  访问 `/dev/uhid` 设备节点可能需要特定的权限。用户运行的程序可能没有足够的权限来创建或操作虚拟 HID 设备。
    * **例子:**  一个普通应用尝试创建虚拟键盘，但由于 SELinux 策略限制而失败。
5. **并发访问冲突:**  多个进程同时尝试操作同一个虚拟 HID 设备可能会导致冲突和不可预测的行为。
    * **例子:**  两个程序同时尝试向同一个虚拟键盘发送输入事件，导致事件混乱。

**Android Framework 或 NDK 如何一步步到达这里:**

**Android Framework (Java):**

1. **InputManagerService:** Android Framework 中负责管理输入设备的组件是 `InputManagerService`。
2. **Virtual Input Device Creation:**  Framework 中可能存在 API (例如，在 `InputManager` 或相关的隐藏 API 中) 允许系统服务或具有特定权限的应用程序创建虚拟输入设备。这些 API 的底层实现会调用 Native 代码。
3. **Native Code (C++):**  Framework 的 Native 层代码会使用 NDK 提供的接口与内核进行交互。这通常涉及到：
   * 使用 `open()` 系统调用打开 `/dev/uhid`。
   * 构建 `uhid_event` 结构体，根据要创建的虚拟设备的类型和功能填充相应的数据。
   * 使用 `write()` 系统调用将 `uhid_event` 发送给内核 `uhid` 驱动。
   * 处理来自 `uhid` 驱动的响应 (如果有)。

**NDK (C/C++):**

1. **直接访问 `/dev/uhid`:**  使用 NDK 开发的应用程序可以直接通过标准 C 库函数与 `/dev/uhid` 进行交互。
2. **打开设备:** 使用 `open("/dev/uhid", O_RDWR | O_CLOEXEC)` 打开设备节点。
3. **构建事件:**  手动构建 `uhid_event` 结构体，填充必要的字段。
4. **发送事件:** 使用 `write(fd, &event, sizeof(event))` 将事件发送到内核。
5. **接收事件 (如果需要):** 使用 `read(fd, &event, sizeof(event))` 从内核接收事件。
6. **关闭设备:** 使用 `close(fd)` 关闭设备节点。

**Frida Hook 示例调试步骤:**

假设你想观察一个应用程序如何创建一个虚拟键盘设备。你可以使用 Frida Hook 来拦截对 `/dev/uhid` 的 `open` 和 `write` 调用。

**Frida Hook 示例 (Python):**

```python
import frida
import sys

package_name = "your.target.package"  # 替换为目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process with package name '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        const path = Memory.readUtf8String(args[0]);
        if (path.includes("/dev/uhid")) {
            console.log("[*] open() called with path:", path);
            this.is_uhid = true;
        } else {
            this.is_uhid = false;
        }
    },
    onLeave: function(retval) {
        if (this.is_uhid) {
            console.log("[*] open() returned fd:", retval);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "write"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        if (this.is_uhid_fd && fd === this.uhid_fd) {
            const size = args[2].toInt32();
            const buffer = Memory.readByteArray(args[1], size);
            console.log("[*] write() called on uhid fd:", fd, "size:", size);
            // 可以进一步解析 buffer 中的 uhid_event 结构体
            // const event_type = Memory.readU32(args[1]);
            // console.log("[*] UHID Event Type:", event_type);
        }
    },
    onLeave: function(retval) {
    }
});

// 监听 open 返回值，以便在 write hook 中判断是否是 uhid 的 fd
Process.setExceptionHandler(function(details) {
  console.log("Exception caught: " + details.error);
  return true; // Continue execution
});

// 监听 open 返回值，保存 uhid 的 fd
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        this.path = Memory.readUtf8String(args[0]);
    },
    onLeave: function(retval) {
        if (this.path.includes("/dev/uhid")) {
            this.uhid_fd = retval.toInt32();
            this.is_uhid_fd = true;
            console.log("[*] Detected uhid fd:", this.uhid_fd);
        }
    }
});

""",

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并安装了 Frida 服务。
2. **找到目标应用:** 确定你想要分析的应用程序的包名。
3. **运行 Frida 脚本:** 运行上面的 Python Frida 脚本，将 `your.target.package` 替换为目标应用的包名。
4. **操作目标应用:** 在 Android 设备上操作目标应用程序，触发其创建虚拟键盘的动作。
5. **观察 Frida 输出:** Frida 脚本会拦截 `open` 和 `write` 系统调用。
   * 当应用程序打开 `/dev/uhid` 时，你会看到 `open()` 调用的路径和返回的文件描述符。
   * 当应用程序向 `/dev/uhid` 写入数据时，你会看到 `write()` 调用的文件描述符、写入的大小以及写入的数据内容 (可以进一步解析为 `uhid_event` 结构体，查看事件类型和数据)。

通过 Frida Hook，你可以详细观察应用程序与 `uhid` 驱动的交互过程，例如创建设备的请求、发送的输入事件等，从而理解其工作原理。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/uhid.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __UHID_H_
#define __UHID_H_
#include <linux/input.h>
#include <linux/types.h>
#include <linux/hid.h>
enum uhid_event_type {
  __UHID_LEGACY_CREATE,
  UHID_DESTROY,
  UHID_START,
  UHID_STOP,
  UHID_OPEN,
  UHID_CLOSE,
  UHID_OUTPUT,
  __UHID_LEGACY_OUTPUT_EV,
  __UHID_LEGACY_INPUT,
  UHID_GET_REPORT,
  UHID_GET_REPORT_REPLY,
  UHID_CREATE2,
  UHID_INPUT2,
  UHID_SET_REPORT,
  UHID_SET_REPORT_REPLY,
};
struct uhid_create2_req {
  __u8 name[128];
  __u8 phys[64];
  __u8 uniq[64];
  __u16 rd_size;
  __u16 bus;
  __u32 vendor;
  __u32 product;
  __u32 version;
  __u32 country;
  __u8 rd_data[HID_MAX_DESCRIPTOR_SIZE];
} __attribute__((__packed__));
enum uhid_dev_flag {
  UHID_DEV_NUMBERED_FEATURE_REPORTS = (1ULL << 0),
  UHID_DEV_NUMBERED_OUTPUT_REPORTS = (1ULL << 1),
  UHID_DEV_NUMBERED_INPUT_REPORTS = (1ULL << 2),
};
struct uhid_start_req {
  __u64 dev_flags;
};
#define UHID_DATA_MAX 4096
enum uhid_report_type {
  UHID_FEATURE_REPORT,
  UHID_OUTPUT_REPORT,
  UHID_INPUT_REPORT,
};
struct uhid_input2_req {
  __u16 size;
  __u8 data[UHID_DATA_MAX];
} __attribute__((__packed__));
struct uhid_output_req {
  __u8 data[UHID_DATA_MAX];
  __u16 size;
  __u8 rtype;
} __attribute__((__packed__));
struct uhid_get_report_req {
  __u32 id;
  __u8 rnum;
  __u8 rtype;
} __attribute__((__packed__));
struct uhid_get_report_reply_req {
  __u32 id;
  __u16 err;
  __u16 size;
  __u8 data[UHID_DATA_MAX];
} __attribute__((__packed__));
struct uhid_set_report_req {
  __u32 id;
  __u8 rnum;
  __u8 rtype;
  __u16 size;
  __u8 data[UHID_DATA_MAX];
} __attribute__((__packed__));
struct uhid_set_report_reply_req {
  __u32 id;
  __u16 err;
} __attribute__((__packed__));
enum uhid_legacy_event_type {
  UHID_CREATE = __UHID_LEGACY_CREATE,
  UHID_OUTPUT_EV = __UHID_LEGACY_OUTPUT_EV,
  UHID_INPUT = __UHID_LEGACY_INPUT,
  UHID_FEATURE = UHID_GET_REPORT,
  UHID_FEATURE_ANSWER = UHID_GET_REPORT_REPLY,
};
struct uhid_create_req {
  __u8 name[128];
  __u8 phys[64];
  __u8 uniq[64];
  __u8  * rd_data;
  __u16 rd_size;
  __u16 bus;
  __u32 vendor;
  __u32 product;
  __u32 version;
  __u32 country;
} __attribute__((__packed__));
struct uhid_input_req {
  __u8 data[UHID_DATA_MAX];
  __u16 size;
} __attribute__((__packed__));
struct uhid_output_ev_req {
  __u16 type;
  __u16 code;
  __s32 value;
} __attribute__((__packed__));
struct uhid_feature_req {
  __u32 id;
  __u8 rnum;
  __u8 rtype;
} __attribute__((__packed__));
struct uhid_feature_answer_req {
  __u32 id;
  __u16 err;
  __u16 size;
  __u8 data[UHID_DATA_MAX];
} __attribute__((__packed__));
struct uhid_event {
  __u32 type;
  union {
    struct uhid_create_req create;
    struct uhid_input_req input;
    struct uhid_output_req output;
    struct uhid_output_ev_req output_ev;
    struct uhid_feature_req feature;
    struct uhid_get_report_req get_report;
    struct uhid_feature_answer_req feature_answer;
    struct uhid_get_report_reply_req get_report_reply;
    struct uhid_create2_req create2;
    struct uhid_input2_req input2;
    struct uhid_set_report_req set_report;
    struct uhid_set_report_reply_req set_report_reply;
    struct uhid_start_req start;
  } u;
} __attribute__((__packed__));
#endif

"""

```