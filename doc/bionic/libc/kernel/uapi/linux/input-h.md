Response:
Let's break down the thought process for generating the detailed explanation of the `input.h` file.

**1. Understanding the Request:**

The core request is to analyze the provided C header file (`input.h`) and explain its functionality, especially in the context of Android. Key aspects to cover include:

* **Functionality:** What does this file define?
* **Android Relevance:** How is it used in Android?
* **libc Functions:** Explain the implementation (though this is tricky for a header file).
* **Dynamic Linker:** Identify relevant parts and explain linking.
* **Logic/Assumptions:**  Illustrate with examples.
* **Common Errors:** Point out potential pitfalls.
* **Android Framework/NDK Path:**  Trace the usage.
* **Frida Hooking:** Provide a debugging example.

**2. Initial Scan and Identification of Key Components:**

The first step is to quickly scan the file and identify the major elements:

* **Includes:** `<sys/time.h>`, `<sys/ioctl.h>`, `<sys/types.h>`, `<linux/types.h>`, `"input-event-codes.h"`. This immediately signals system-level interaction, especially with ioctl.
* **`struct input_event`:**  This appears to be the central data structure, likely representing an input event. The `time`, `type`, `code`, and `value` members are strong indicators.
* **`struct input_id`:**  Information about the input device itself.
* **`struct input_absinfo`:**  Details about absolute axis input (like touch or joysticks).
* **`struct input_keymap_entry`:**  Related to key mapping.
* **`struct input_mask`:**  Likely used for filtering or selecting input events.
* **`#define EVIOC...`:** A large set of macros starting with `EVIOC`. The `_IOR`, `_IOW`, and `_IOC` suggest they are `ioctl` commands. This is a crucial finding.
* **`#define BUS_...`:** Defines for different bus types.
* **`#define MT_TOOL_...`:** Defines for multi-touch tools.
* **`struct ff_...` and `#define FF_...`:**  Structures and defines related to force feedback.

**3. Categorizing and Explaining Functionality:**

Based on the identified components, start grouping and explaining:

* **Core Data Structures:**  Explain the purpose of `input_event`, `input_id`, `input_absinfo`, etc. Emphasize what kind of information each holds.
* **`ioctl` Commands:**  Recognize the `EVIOC` macros as `ioctl` requests. Explain the general purpose of `ioctl` for device-specific control. Group the commands by their function (getting information, setting parameters, etc.).
* **Constants:** Describe the purpose of the `BUS_`, `MT_TOOL_`, and `FF_` constants, linking them to the corresponding structures or commands.

**4. Connecting to Android:**

This requires understanding how Android handles input. Key connections include:

* **Input System:** Recognize that this header is fundamental to Android's input handling.
* **Hardware Abstraction Layer (HAL):**  Explain how the `ioctl` commands interact with the kernel driver through the HAL.
* **Android Framework:**  Briefly describe how touch events, key presses, etc., propagate from the kernel up to applications.
* **NDK:** Mention that NDK developers can directly interact with input devices.

**5. Addressing Specific Requirements:**

* **libc Functions:**  Acknowledge that this is a header file and doesn't contain libc *function implementations*. The included headers (`sys/time.h`, `sys/ioctl.h`, etc.) define functions, but the current file defines *data structures and constants* used with those functions.
* **Dynamic Linker:**  Focus on the inclusion of other headers. Explain that the *use* of these structures in libraries would involve linking. Provide a simplified example of a library using `input_event`.
* **Logic/Assumptions:** Create simple examples illustrating how the structures are used to represent input events (e.g., a key press).
* **Common Errors:**  Think about typical mistakes when dealing with input devices: incorrect `ioctl` calls, wrong event types, buffer overflows (though less likely with these structures directly).
* **Android Framework/NDK Path:** Outline the typical flow of an input event, starting from hardware and going up to the application.
* **Frida Hooking:** Provide a basic Frida example focusing on hooking the `read` system call when interacting with an input device file.

**6. Structuring the Output:**

Organize the information logically using headings and bullet points. Start with a high-level overview and then delve into specifics.

**7. Refinement and Language:**

Ensure the language is clear, concise, and in Mandarin Chinese as requested. Double-check for any technical inaccuracies. Use appropriate terminology (e.g., "文件描述符" for file descriptor).

**Self-Correction/Improvements during the process:**

* **Initial thought:** Maybe try to explain the implementation of `ioctl`.
* **Correction:** Realize that `ioctl` is a system call handled by the kernel. This header file only defines the *requests* for `ioctl`. Shift focus to how these requests are used.
* **Initial thought:** Focus too much on the `struct` definitions in isolation.
* **Correction:** Emphasize the *relationship* between the structures and the `ioctl` commands. The structures are the data passed to and from the kernel via `ioctl`.
* **Initial thought:**  Provide extremely detailed code examples within the Frida section.
* **Correction:**  Keep the Frida example focused on demonstrating the general concept of hooking the interaction with input devices. Avoid overly complex code.

By following this structured approach, the comprehensive and accurate explanation of the `input.h` file can be generated. The key is to break down the file into its components, understand their purpose, and then connect them to the broader context of Android's input handling system.
这是一个定义 Linux 用户空间 API 中用于处理输入事件的头文件 (`input.h`)。它位于 Android Bionic 库的内核头文件目录中，这意味着 Android 的 C 库需要与 Linux 内核的输入子系统进行交互。

**它的功能：**

这个头文件定义了与 Linux 输入子系统交互所需的各种数据结构、常量和 ioctl 命令。其主要功能包括：

1. **定义输入事件结构体 `input_event`:**  这是表示一个输入事件（例如按键按下、鼠标移动、触摸屏操作等）的核心数据结构。它包含了事件发生的时间、事件类型、事件代码和事件值。
2. **定义输入设备标识结构体 `input_id`:** 用于描述输入设备的类型、制造商、产品 ID 和版本信息。
3. **定义绝对轴信息结构体 `input_absinfo`:** 用于描述绝对轴输入设备（如触摸屏、摇杆）的当前值、最小值、最大值、模糊值、平坦值和分辨率。
4. **定义按键映射相关结构体 `input_keymap_entry`:** 用于处理按键码和扫描码之间的映射关系。
5. **定义输入掩码结构体 `input_mask`:** 用于指定感兴趣的事件类型和代码，可能用于过滤输入事件。
6. **定义 `ioctl` 命令宏:**  定义了一系列 `EVIOC` 开头的宏，这些宏用于向输入设备文件描述符发送 `ioctl` 命令，以获取设备信息、设置参数或执行特定操作。 例如：
    * `EVIOCGVERSION`: 获取输入子系统的版本。
    * `EVIOCGID`: 获取输入设备的 `input_id` 信息。
    * `EVIOCGKEY`: 获取按键状态。
    * `EVIOCGABS`: 获取绝对轴的当前信息。
    * `EVIOCSFF`: 发送力反馈效果。
7. **定义常量:**  定义了各种常量，例如：
    * `EV_VERSION`: 输入子系统的版本号。
    * `BUS_...`:  定义了不同的总线类型（USB, Bluetooth 等）。
    * `MT_TOOL_...`: 定义了多点触摸工具类型（手指，笔等）。
    * `FF_...`: 定义了力反馈相关的常量（效果类型、波形等）。

**它与 Android 功能的关系以及举例说明：**

这个头文件是 Android 输入系统的重要组成部分。Android 设备的各种输入操作，如触摸屏操作、按键按下、传感器数据等，最终都会通过 Linux 内核的输入子系统传递到用户空间。Android Framework 或 NDK 通过与 `/dev/input/event*` 等输入设备文件进行交互，来获取这些输入事件。

**举例说明：**

* **触摸屏事件:** 当用户触摸 Android 设备的屏幕时，触摸屏驱动程序会将触摸事件信息封装成 `input_event` 结构体，并通过内核输入子系统传递。Android Framework 会读取这些事件，解析触摸点的坐标、压力等信息，并将其转换为 Android 的触摸事件 (MotionEvent)，最终传递给应用程序。
* **按键事件:**  当用户按下 Android 设备的物理按键或虚拟按键时，按键驱动程序也会生成 `input_event` 结构体，包含按键的类型 (EV_KEY)、按键代码 (例如 `KEY_BACK`) 和值 (按下或释放)。Android Framework 会捕获这些事件，并根据按键代码执行相应的操作，例如返回上一页。
* **传感器事件:** 虽然这个头文件主要关注用户输入设备，但某些传感器（如加速计、陀螺仪）的数据也可能通过 input 子系统传递，并使用类似的机制在用户空间被访问。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了数据结构和宏。  实际与输入设备交互的 libc 函数通常是 `open`, `read`, `ioctl`, `close` 等。

* **`open()`:**  用于打开输入设备文件 (例如 `/dev/input/event0`)，返回一个文件描述符，后续的操作都基于这个文件描述符。
* **`read()`:**  用于从输入设备文件描述符读取数据。读取的数据通常是一个或多个 `input_event` 结构体。内核会将发生的输入事件写入到这些文件中，用户空间的程序通过 `read()` 获取这些事件。
* **`ioctl()`:**  这是一个通用的设备控制系统调用。在这个上下文中，`ioctl()` 被用来向输入设备发送特定的命令，例如获取设备信息 (`EVIOCGID`)，设置重复率 (`EVIOCSREP`)，或抓取设备以独占访问 (`EVIOCGRAB`)。  `ioctl` 的实现是在内核驱动程序中。当用户空间程序调用 `ioctl` 时，内核会根据传入的命令码和参数，调用相应的驱动程序函数来处理请求。
* **`close()`:** 用于关闭打开的输入设备文件描述符，释放相关资源。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身不直接涉及 dynamic linker。Dynamic linker 的作用是在程序启动时将程序依赖的共享库加载到内存中，并解析符号引用。

然而，当 Android Framework 或 NDK 中的库 (例如 `libinput.so`) 使用到这个头文件中定义的结构体和宏时，就会涉及到 dynamic linker。

**so 布局样本 (假设 `libinput.so` 使用了 `input.h`)：**

```
libinput.so:
    .text          # 代码段
        ... 使用 input_event 等结构体的代码 ...
        ... 调用 open, read, ioctl 等 libc 函数的代码 ...
    .data          # 数据段
        ...
    .bss           # 未初始化数据段
        ...
    .rodata        # 只读数据段
        ...
    .dynamic       # 动态链接信息
        NEEDED libc.so  # 依赖 libc.so
        ...
    .symtab        # 符号表 (包含 input_event 等符号)
        ... input_event ...
        ... EVIOCGVERSION ...
        ...
    .strtab        # 字符串表
        ... input_event ...
        ... EVIOCGVERSION ...
        ...
```

**链接的处理过程：**

1. **编译时：** 当编译 `libinput.so` 的源代码时，编译器会遇到 `input.h` 中定义的结构体和宏。这些符号会被记录在 `libinput.so` 的符号表 (`.symtab`) 中。
2. **链接时：**  链接器会处理 `libinput.so` 的依赖关系。它会注意到 `libinput.so` 中使用了 `libc.so` 中的函数 (如 `open`, `read`, `ioctl`)，并将这些依赖关系记录在 `.dynamic` 段的 `NEEDED` 条目中。  `input.h` 中定义的符号通常不会直接链接到 `libc.so`，因为它们是数据结构和宏，而不是函数。
3. **运行时：** 当一个使用了 `libinput.so` 的应用程序启动时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会执行以下操作：
    * 加载可执行文件到内存。
    * 解析可执行文件的 `.dynamic` 段，找到依赖的共享库 `libc.so` 和 `libinput.so`。
    * 加载 `libc.so` 和 `libinput.so` 到内存中的合适位置。
    * **符号解析 (Symbol Resolution):**  遍历 `libinput.so` 的重定位表，找到所有未定义的符号 (例如，对 `input_event` 的引用)。然后在 `libc.so` 和 `libinput.so` 自身以及其他已加载的库的符号表中查找这些符号的定义。
    * 由于 `input_event` 等结构体定义在 `input.h` 中，而 `input.h` 通常是系统头文件，它们会被编译到 `libinput.so` 中。因此，对 `input_event` 的引用会在 `libinput.so` 内部被解析。对于 `open`, `read`, `ioctl` 等 libc 函数的调用，则会在 `libc.so` 中找到相应的实现。
    * 完成符号解析后，dynamic linker 会修改内存中的代码，将未定义的符号引用替换为实际的函数地址或数据地址。

**如果做了逻辑推理，请给出假设输入与输出：**

假设用户触摸了 Android 设备的屏幕。

**假设输入:**

* 设备文件: `/dev/input/event0` (假设这是触摸屏设备的事件文件)
* 读取操作:  应用程序调用 `read(fd, &event, sizeof(event))` 从文件描述符 `fd` 读取数据，其中 `event` 是 `struct input_event` 类型的变量。
* 内核驱动程序生成以下 `input_event` 结构体：
    ```c
    struct input_event event = {
        .time = { .tv_sec = 1678886400, .tv_usec = 123456 }, // 假设的时间戳
        .type = EV_ABS,          // 绝对轴事件
        .code = ABS_MT_POSITION_X, // X 轴坐标
        .value = 500             // 触摸点的 X 坐标
    };
    ```
    接下来可能还会有一个类似的事件表示 Y 轴坐标：
    ```c
    struct input_event event_y = {
        .time = { .tv_sec = 1678886400, .tv_usec = 123456 },
        .type = EV_ABS,
        .code = ABS_MT_POSITION_Y,
        .value = 800
    };
    ```
    最后，可能还有一个同步事件表示一个完整的触摸事件结束：
    ```c
    struct input_event sync_event = {
        .time = { .tv_sec = 1678886400, .tv_usec = 123456 },
        .type = EV_SYN,
        .code = SYN_REPORT,
        .value = 0
    };
    ```

**假设输出:**

* `read()` 函数成功读取到数据，返回读取的字节数 (通常是 `sizeof(struct input_event)` 或其倍数)。
* `event` 变量的内容将被填充为内核驱动程序生成的数据，如上面的示例所示。应用程序可以访问 `event.type`, `event.code`, `event.value` 来获取触摸事件的信息。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **忘记打开设备文件:**  在尝试读取或发送 ioctl 命令之前，必须先使用 `open()` 打开输入设备文件。如果忘记打开，`read()` 或 `ioctl()` 会返回错误。
   ```c
   int fd;
   struct input_event event;

   // 错误：忘记打开设备文件
   // fd = open("/dev/input/event0", O_RDONLY);
   // if (fd < 0) { perror("open"); return -1; }

   ssize_t bytes_read = read(fd, &event, sizeof(event)); // 可能导致错误
   ```

2. **使用错误的设备文件路径:**  不同的输入设备对应不同的文件路径 (例如 `/dev/input/event0`, `/dev/input/event1` 等)。使用错误的路径将无法访问到目标设备。
   ```c
   int fd = open("/dev/input/event99", O_RDONLY); // 假设不存在这个设备
   if (fd < 0) {
       perror("open"); // 会输出 "No such file or directory"
       return -1;
   }
   ```

3. **读取数据大小错误:**  应该读取 `sizeof(struct input_event)` 字节的数据。读取不足或过多的字节可能导致数据解析错误。
   ```c
   int fd = open("/dev/input/event0", O_RDONLY);
   if (fd < 0) { perror("open"); return -1; }

   struct input_event event;
   ssize_t bytes_read = read(fd, &event, sizeof(event) - 1); // 错误：少读了一个字节
   if (bytes_read < 0) { perror("read"); }
   close(fd);
   ```

4. **使用错误的 `ioctl` 命令或参数:**  `ioctl` 命令需要正确的命令码和参数类型。使用错误的命令码或参数会导致 `ioctl` 调用失败或产生意外的结果。
   ```c
   int fd = open("/dev/input/event0", O_RDWR); // 需要可写权限才能发送某些 ioctl
   if (fd < 0) { perror("open"); return -1; }

   int version;
   if (ioctl(fd, EVIOCGID, &version) < 0) { // 错误：EVIOCGID 需要的是 struct input_id*
       perror("ioctl");
   }
   close(fd);
   ```

5. **没有处理同步事件 (EV_SYN):**  对于某些输入设备（特别是多点触摸），会发送 `EV_SYN` 事件来标记一个完整事件的结束。如果没有正确处理同步事件，可能会导致数据混乱或丢失。

6. **权限问题:**  访问 `/dev/input/event*` 文件通常需要特定的权限。应用程序可能需要以 root 权限或属于特定用户组运行才能访问这些文件。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `input.h` 的路径：**

1. **硬件事件发生:** 例如，用户触摸屏幕。
2. **内核驱动程序:**  触摸屏驱动程序捕获硬件事件，并将其转换为 `input_event` 结构体。
3. **内核输入子系统:**  内核将 `input_event` 数据发送到与设备关联的 `/dev/input/event*` 文件。
4. **`InputReader` (Android Framework):**  在 Android Framework 中，`InputReader` 组件负责从 `/dev/input/event*` 文件中读取原始的 `input_event` 数据。这通常是通过 JNI 调用到 native 代码实现的。
5. **Native 代码 (libinput.so 或相关库):**  `InputReader` 使用 `open()`, `read()` 等系统调用来读取设备文件。读取的数据会填充到 `input_event` 结构体中 (这个结构体的定义就来自 `bionic/libc/kernel/uapi/linux/input.h`)。
6. **事件处理和分发:**  `InputReader` 将原始的 `input_event` 数据解析并转换为 Android Framework 可以理解的事件对象 (例如 `MotionEvent`, `KeyEvent`)。
7. **事件传递到应用层:**  这些事件对象最终会被传递到应用程序的 UI 线程进行处理。

**NDK 到达 `input.h` 的路径：**

1. **应用程序开发者:**  使用 NDK 开发的应用程序可以直接访问输入设备。
2. **打开设备文件:**  NDK 代码可以使用 `open("/dev/input/event0", O_RDONLY)` 打开输入设备文件。
3. **读取输入事件:**  使用 `read(fd, &event, sizeof(event))` 读取 `input_event` 结构体。
4. **处理输入事件:**  NDK 代码可以直接访问 `event.type`, `event.code`, `event.value` 来处理原始的输入事件数据。

**Frida Hook 示例：**

以下是一个使用 Frida hook `read` 系统调用的示例，以观察 Android Framework 或 NDK 如何从输入设备读取数据：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(['com.example.myapp']) # 替换为你的应用包名
    session = device.attach(pid)
except frida.core.DeviceNotFoundError:
    print("[-] No Android device found.")
    sys.exit()
except frida.core.ProcessNotFoundError:
    print("[-] Process not found. Make sure the app is running.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "read"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const buf = args[1];
        const count = args[2].toInt32();

        // 检查是否是 /dev/input/event* 文件
        const path = Memory.readCString(ptr(this.context.rsi)); // Requires context
        if (path && path.startsWith("/dev/input/event")) {
            console.log("[*] read() called on fd:", fd, "count:", count, "path:", path);
            this.input_event_ptr = buf;
            this.read_count = count;
        }
    },
    onLeave: function(retval) {
        if (this.input_event_ptr && retval.toInt32() > 0) {
            const bytesRead = retval.toInt32();
            console.log("[*] read() returned:", bytesRead);
            for (let i = 0; i < bytesRead / 24; i++) { // sizeof(input_event) = 24
                const eventPtr = this.input_event_ptr.add(i * 24);
                const timeSec = eventPtr.readU64(); // 假设是 64 位时间戳
                const type = eventPtr.add(16).readU16();
                const code = eventPtr.add(18).readU16();
                const value = eventPtr.add(20).readS32();
                console.log(`    [*] Event ${i}: Time: ${timeSec}, Type: ${type}, Code: ${code}, Value: ${value}`);
            }
            this.input_event_ptr = null;
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

try:
    sys.stdin.read()
except KeyboardInterrupt:
    session.detach()
    sys.exit()
```

**Frida Hook 示例解释：**

1. **导入模块:** 导入 `frida` 和 `sys` 模块。
2. **`on_message` 函数:** 定义消息处理函数，用于打印 Frida 发送的消息。
3. **连接设备和附加进程:**  尝试连接到 USB 设备，并附加到目标应用程序的进程。你需要将 `com.example.myapp` 替换为你想要调试的应用程序的包名。
4. **Frida Script:**
   * **`Interceptor.attach`:**  Hook `libc.so` 中的 `read` 函数。
   * **`onEnter`:**  在 `read` 函数被调用之前执行：
     * 获取文件描述符 (`fd`)、缓冲区指针 (`buf`) 和读取字节数 (`count`)。
     * 检查打开的文件路径是否以 `/dev/input/event` 开头，以判断是否是输入设备文件。
     * 保存缓冲区指针和读取计数到 `this` 上下文中，以便在 `onLeave` 中使用。
   * **`onLeave`:** 在 `read` 函数返回之后执行：
     * 检查返回值是否大于 0 (表示成功读取到数据)。
     * 遍历读取到的数据，每次读取 `sizeof(struct input_event)` (通常是 24 字节)。
     * 从缓冲区中读取 `input_event` 的成员 (时间戳、类型、代码、值)。
     * 打印读取到的输入事件信息。
5. **创建和加载脚本:**  创建 Frida 脚本并加载到目标进程。
6. **保持运行:**  通过 `sys.stdin.read()` 使脚本保持运行状态，直到按下 Ctrl+C。

运行这个 Frida 脚本，并在 Android 设备上操作目标应用程序的输入（例如触摸屏幕、按下按键），你将在终端看到 `read` 系统调用被 hook，并打印出从 `/dev/input/event*` 文件读取到的原始 `input_event` 数据。这可以帮助你理解 Android Framework 或 NDK 是如何一步步地从内核获取输入事件的。

请注意，这个 Frida 脚本只是一个基本的示例。根据你想要调试的具体场景，你可能需要修改脚本来 hook 不同的函数或提取更详细的信息。  你可能还需要 root 权限才能 hook 系统进程或某些受保护的应用程序。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/input.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_INPUT_H
#define _UAPI_INPUT_H
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/types.h>
#include "input-event-codes.h"
struct input_event {
#if __BITS_PER_LONG != 32 || !defined(__USE_TIME_BITS64)
  struct timeval time;
#define input_event_sec time.tv_sec
#define input_event_usec time.tv_usec
#else
  __kernel_ulong_t __sec;
#if defined(__sparc__) && defined(__arch64__)
  unsigned int __usec;
  unsigned int __pad;
#else
  __kernel_ulong_t __usec;
#endif
#define input_event_sec __sec
#define input_event_usec __usec
#endif
  __u16 type;
  __u16 code;
  __s32 value;
};
#define EV_VERSION 0x010001
struct input_id {
  __u16 bustype;
  __u16 vendor;
  __u16 product;
  __u16 version;
};
struct input_absinfo {
  __s32 value;
  __s32 minimum;
  __s32 maximum;
  __s32 fuzz;
  __s32 flat;
  __s32 resolution;
};
struct input_keymap_entry {
#define INPUT_KEYMAP_BY_INDEX (1 << 0)
  __u8 flags;
  __u8 len;
  __u16 index;
  __u32 keycode;
  __u8 scancode[32];
};
struct input_mask {
  __u32 type;
  __u32 codes_size;
  __u64 codes_ptr;
};
#define EVIOCGVERSION _IOR('E', 0x01, int)
#define EVIOCGID _IOR('E', 0x02, struct input_id)
#define EVIOCGREP _IOR('E', 0x03, unsigned int[2])
#define EVIOCSREP _IOW('E', 0x03, unsigned int[2])
#define EVIOCGKEYCODE _IOR('E', 0x04, unsigned int[2])
#define EVIOCGKEYCODE_V2 _IOR('E', 0x04, struct input_keymap_entry)
#define EVIOCSKEYCODE _IOW('E', 0x04, unsigned int[2])
#define EVIOCSKEYCODE_V2 _IOW('E', 0x04, struct input_keymap_entry)
#define EVIOCGNAME(len) _IOC(_IOC_READ, 'E', 0x06, len)
#define EVIOCGPHYS(len) _IOC(_IOC_READ, 'E', 0x07, len)
#define EVIOCGUNIQ(len) _IOC(_IOC_READ, 'E', 0x08, len)
#define EVIOCGPROP(len) _IOC(_IOC_READ, 'E', 0x09, len)
#define EVIOCGMTSLOTS(len) _IOC(_IOC_READ, 'E', 0x0a, len)
#define EVIOCGKEY(len) _IOC(_IOC_READ, 'E', 0x18, len)
#define EVIOCGLED(len) _IOC(_IOC_READ, 'E', 0x19, len)
#define EVIOCGSND(len) _IOC(_IOC_READ, 'E', 0x1a, len)
#define EVIOCGSW(len) _IOC(_IOC_READ, 'E', 0x1b, len)
#define EVIOCGBIT(ev,len) _IOC(_IOC_READ, 'E', 0x20 + (ev), len)
#define EVIOCGABS(abs) _IOR('E', 0x40 + (abs), struct input_absinfo)
#define EVIOCSABS(abs) _IOW('E', 0xc0 + (abs), struct input_absinfo)
#define EVIOCSFF _IOW('E', 0x80, struct ff_effect)
#define EVIOCRMFF _IOW('E', 0x81, int)
#define EVIOCGEFFECTS _IOR('E', 0x84, int)
#define EVIOCGRAB _IOW('E', 0x90, int)
#define EVIOCREVOKE _IOW('E', 0x91, int)
#define EVIOCGMASK _IOR('E', 0x92, struct input_mask)
#define EVIOCSMASK _IOW('E', 0x93, struct input_mask)
#define EVIOCSCLOCKID _IOW('E', 0xa0, int)
#define ID_BUS 0
#define ID_VENDOR 1
#define ID_PRODUCT 2
#define ID_VERSION 3
#define BUS_PCI 0x01
#define BUS_ISAPNP 0x02
#define BUS_USB 0x03
#define BUS_HIL 0x04
#define BUS_BLUETOOTH 0x05
#define BUS_VIRTUAL 0x06
#define BUS_ISA 0x10
#define BUS_I8042 0x11
#define BUS_XTKBD 0x12
#define BUS_RS232 0x13
#define BUS_GAMEPORT 0x14
#define BUS_PARPORT 0x15
#define BUS_AMIGA 0x16
#define BUS_ADB 0x17
#define BUS_I2C 0x18
#define BUS_HOST 0x19
#define BUS_GSC 0x1A
#define BUS_ATARI 0x1B
#define BUS_SPI 0x1C
#define BUS_RMI 0x1D
#define BUS_CEC 0x1E
#define BUS_INTEL_ISHTP 0x1F
#define BUS_AMD_SFH 0x20
#define MT_TOOL_FINGER 0x00
#define MT_TOOL_PEN 0x01
#define MT_TOOL_PALM 0x02
#define MT_TOOL_DIAL 0x0a
#define MT_TOOL_MAX 0x0f
#define FF_STATUS_STOPPED 0x00
#define FF_STATUS_PLAYING 0x01
#define FF_STATUS_MAX 0x01
struct ff_replay {
  __u16 length;
  __u16 delay;
};
struct ff_trigger {
  __u16 button;
  __u16 interval;
};
struct ff_envelope {
  __u16 attack_length;
  __u16 attack_level;
  __u16 fade_length;
  __u16 fade_level;
};
struct ff_constant_effect {
  __s16 level;
  struct ff_envelope envelope;
};
struct ff_ramp_effect {
  __s16 start_level;
  __s16 end_level;
  struct ff_envelope envelope;
};
struct ff_condition_effect {
  __u16 right_saturation;
  __u16 left_saturation;
  __s16 right_coeff;
  __s16 left_coeff;
  __u16 deadband;
  __s16 center;
};
struct ff_periodic_effect {
  __u16 waveform;
  __u16 period;
  __s16 magnitude;
  __s16 offset;
  __u16 phase;
  struct ff_envelope envelope;
  __u32 custom_len;
  __s16  * custom_data;
};
struct ff_rumble_effect {
  __u16 strong_magnitude;
  __u16 weak_magnitude;
};
struct ff_effect {
  __u16 type;
  __s16 id;
  __u16 direction;
  struct ff_trigger trigger;
  struct ff_replay replay;
  union {
    struct ff_constant_effect constant;
    struct ff_ramp_effect ramp;
    struct ff_periodic_effect periodic;
    struct ff_condition_effect condition[2];
    struct ff_rumble_effect rumble;
  } u;
};
#define FF_RUMBLE 0x50
#define FF_PERIODIC 0x51
#define FF_CONSTANT 0x52
#define FF_SPRING 0x53
#define FF_FRICTION 0x54
#define FF_DAMPER 0x55
#define FF_INERTIA 0x56
#define FF_RAMP 0x57
#define FF_EFFECT_MIN FF_RUMBLE
#define FF_EFFECT_MAX FF_RAMP
#define FF_SQUARE 0x58
#define FF_TRIANGLE 0x59
#define FF_SINE 0x5a
#define FF_SAW_UP 0x5b
#define FF_SAW_DOWN 0x5c
#define FF_CUSTOM 0x5d
#define FF_WAVEFORM_MIN FF_SQUARE
#define FF_WAVEFORM_MAX FF_CUSTOM
#define FF_GAIN 0x60
#define FF_AUTOCENTER 0x61
#define FF_MAX_EFFECTS FF_GAIN
#define FF_MAX 0x7f
#define FF_CNT (FF_MAX + 1)
#endif

"""

```