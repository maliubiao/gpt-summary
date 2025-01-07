Response:
Let's break down the thought process for analyzing this header file.

**1. Initial Understanding - The Context:**

The first step is to recognize the context. The prompt explicitly states: "这是目录为bionic/libc/kernel/uapi/linux/joystick.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker." This is crucial. It immediately tells us:

* **Location:** This isn't a standard C library header, but one specifically for the Android kernel interface related to joysticks. The `uapi` indicates "user-space API," so it's meant for programs running on Android to interact with the kernel's joystick driver.
* **Bionic:** This links the code to Android's core libraries, suggesting it's essential for how Android handles joystick input.
* **Kernel Interface:**  The presence of `ioctl` definitions (`JSIOCGVERSION`, etc.) strongly suggests this interacts directly with a kernel device driver.

**2. Core Functionality Identification - What Does It Do?**

The filename `joystick.h` and the presence of terms like `BUTTON`, `AXIS`, and `EVENT` immediately point to the file's purpose: handling joystick input. We can then scan for key data structures and definitions to get a more granular understanding:

* **`struct js_event`:** This is the most important structure. It represents a single joystick event. The members `time`, `value`, `type`, and `number` clearly indicate the time of the event, the value (e.g., axis position or button state), the type of event (button or axis), and the identifier of the button or axis.
* **`JS_EVENT_BUTTON`, `JS_EVENT_AXIS`, `JS_EVENT_INIT`:** These constants define the possible event types.
* **`JSIOCGVERSION`, `JSIOCGAXES`, `JSIOCGBUTTONS`, etc.:**  The `JSIOC` prefix and the patterns `G` (Get) and `S` (Set) strongly suggest these are `ioctl` commands used to interact with the joystick device. The suffixes (VERSION, AXES, BUTTONS, NAME, CORR, etc.) hint at the specific information they retrieve or set.
* **`struct js_corr`:** This looks like a structure for handling joystick axis calibration or correction.
* **`struct JS_DATA_TYPE`:**  Represents the current state of the joystick (buttons and axes).
* **`struct JS_DATA_SAVE_TYPE_32`, `struct JS_DATA_SAVE_TYPE_64`:** These seem related to saving or managing joystick state, potentially for timeout or calibration purposes. The 32/64 differentiation likely relates to system architecture (though in this context, it might be about time values).

**3. Android Relevance and Examples:**

Once the core functionality is identified, the next step is to connect it to Android.

* **Input System:**  The most obvious connection is Android's input system. Joysticks are input devices. This header file provides the low-level interface that higher-level Android frameworks would use.
* **Game Development:** Games are the primary use case for joysticks on Android. Game developers using the NDK would likely interact with this interface, either directly or indirectly through higher-level APIs.
* **UI Navigation (Less Common):**  While less frequent, joysticks could theoretically be used for general UI navigation.

Examples are crucial here. Imagine a game: when a button is pressed, the kernel driver detects it, creates a `js_event`, and this information is passed up to the Android framework. The framework then translates this into a game-specific action.

**4. libc Function Explanation:**

The prompt asks for an explanation of *libc functions*. This is a bit of a trick. This header file itself *doesn't define libc functions*. It defines *kernel structures and constants*. The interaction happens via *system calls*, often wrapped by libc functions like `open()`, `read()`, `ioctl()`, and `close()`. The explanation should focus on how these standard libc functions are used *in conjunction with* the definitions in this header to interact with the joystick device.

**5. Dynamic Linker and `so` Layout:**

The prompt specifically mentions the dynamic linker. While this header file doesn't directly involve the dynamic linker, understanding its role is important.

* **No Direct Linkage:** This header file is a kernel interface. User-space programs don't directly *link* against it in the traditional sense.
* **Indirect Usage:** However, libraries or processes that *use* joysticks will link against other libraries (like `libandroid.so` or platform-specific input libraries) that *internally* use the definitions from this header when interacting with the kernel.
* **`so` Layout:** The `so` layout example should show how a typical Android application or native library would be structured, including its dependencies. It's important to highlight that the dependency on this header is *implicit* through the use of system calls and potentially higher-level input APIs.

**6. Logical Reasoning, Assumptions, and Output:**

For `ioctl` calls, it's helpful to imagine the data flow:

* **Assumption:** A user-space application opens the joystick device file (e.g., `/dev/input/js0`).
* **Input to `ioctl`:** The `ioctl` command (like `JSIOCGVERSION`) and the file descriptor of the opened joystick device.
* **Output from `ioctl`:** The requested information (e.g., the joystick version number).

**7. Common Usage Errors:**

This focuses on how developers might misuse the API:

* **Incorrect File Paths:** Opening the wrong device file.
* **Incorrect `ioctl` Commands:** Using the wrong command for the desired action.
* **Incorrect Data Structures:** Passing incorrectly sized or formatted data to `ioctl`.
* **Permissions Issues:** Not having the necessary permissions to access the joystick device.

**8. Android Framework and NDK Path:**

This requires tracing the journey of a joystick event:

* **Kernel Driver:** The kernel detects the physical input.
* **Event Device:** The kernel exposes the joystick as an event device (using the input subsystem).
* **HAL (Hardware Abstraction Layer):** Android's HAL might interact with the event device.
* **InputReader/InputDispatcher:** Framework components that process input events.
* **View System/Game Engine:** The event is finally delivered to the application.

The Frida hook examples should target key points in this path, such as the `open()` call on the device file, the `ioctl()` calls, or even at the framework level within `InputReader`.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is a standard C header file."  **Correction:** The `uapi` directory indicates it's a *user-space API* definition for the *kernel*.
* **Initial thought:** "Explain the implementation of `ioctl`." **Correction:** `ioctl` is a system call. Focus on *how* it's used with the defined constants and structures.
* **Initial thought:** "This file is linked against directly." **Correction:** It's a kernel interface. The linkage is indirect through system calls and higher-level libraries.

By following these steps, iteratively refining the understanding, and connecting the information back to the specific context of Android, we arrive at a comprehensive and accurate explanation.
这个头文件 `bionic/libc/kernel/uapi/linux/joystick.handroid` 定义了 Linux 内核用户空间 API 中用于与游戏杆（joystick）设备交互的常量、数据结构和ioctl命令。由于它位于 `bionic` 目录下，这意味着它是 Android C 库的一部分，并且用于 Android 系统中处理游戏杆输入。

**功能列举:**

1. **定义了游戏杆事件类型:**
   - `JS_EVENT_BUTTON`:  表示一个按钮事件（按下或释放）。
   - `JS_EVENT_AXIS`: 表示一个轴事件（摇杆或方向键的移动）。
   - `JS_EVENT_INIT`:  表示一个初始化事件，通常在设备连接或配置更改时发送。

2. **定义了游戏杆事件的数据结构 `struct js_event`:**
   - `time`: 事件发生的时间戳。
   - `value`: 事件的值，对于按钮事件，通常是 0（释放）或 1（按下）；对于轴事件，是轴的位置值。
   - `type`: 事件类型 (JS_EVENT_BUTTON, JS_EVENT_AXIS, JS_EVENT_INIT)。
   - `number`:  按钮或轴的编号。

3. **定义了用于与游戏杆设备驱动通信的 ioctl 命令:**
   - `JSIOCGVERSION`: 获取驱动的版本号。
   - `JSIOCGAXES`: 获取轴的数量。
   - `JSIOCGBUTTONS`: 获取按钮的数量。
   - `JSIOCGNAME(len)`: 获取游戏杆的名称。
   - `JSIOCSCORR`: 设置轴的校准数据。
   - `JSIOCGCORR`: 获取轴的校准数据。
   - `JSIOCSAXMAP`: 设置轴的映射。
   - `JSIOCGAXMAP`: 获取轴的映射。
   - `JSIOCSBTNMAP`: 设置按钮的映射。
   - `JSIOCGBTNMAP`: 获取按钮的映射。

4. **定义了轴校准相关的数据结构 `struct js_corr` 和常量:**
   - `struct js_corr`: 包含轴的校准系数、精度和类型。
   - `JS_CORR_NONE`: 表示没有校准。
   - `JS_CORR_BROKEN`: 表示校准已损坏。

5. **定义了一些其他常量:**
   - `JS_VERSION`: 驱动的版本号。
   - `JS_TRUE`, `JS_FALSE`: 布尔值。
   - `JS_X_0`, `JS_Y_0`, `JS_X_1`, `JS_Y_1`:  可能用于标识轴的索引（虽然通常通过 `number` 字段来表示）。
   - `JS_MAX`:  可能表示最大轴数。
   - `JS_DEF_TIMEOUT`, `JS_DEF_CORR`, `JS_DEF_TIMELIMIT`:  默认的超时、校准值和时间限制。
   - `JS_SET_CAL`, `JS_GET_CAL`, `JS_SET_TIMEOUT`, `JS_GET_TIMEOUT`, `JS_SET_TIMELIMIT`, `JS_GET_TIMELIMIT`, `JS_GET_ALL`, `JS_SET_ALL`:  可能与特定于设备的自定义 ioctl 操作相关。

6. **定义了保存游戏杆数据的结构体 `struct JS_DATA_TYPE`、`struct JS_DATA_SAVE_TYPE_32` 和 `struct JS_DATA_SAVE_TYPE_64`:**
   - `struct JS_DATA_TYPE`: 包含按钮状态和轴的值。
   - `struct JS_DATA_SAVE_TYPE_32` 和 `struct JS_DATA_SAVE_TYPE_64`:  用于保存游戏杆的配置和状态，可能包括超时时间、忙碌状态、过期时间、时间限制以及校准数据。 区分 32 位和 64 位可能是为了兼容不同的架构或处理不同大小的时间值。

**与 Android 功能的关系和举例说明:**

这个头文件是 Android 系统处理游戏杆输入的基础。Android 应用程序（特别是游戏）可以使用这些定义来与连接到 Android 设备的物理游戏杆进行交互。

**举例:**

* **游戏操作:** 当用户按下游戏杆上的一个按钮时，Linux 内核的事件子系统会捕获这个事件，并创建一个 `js_event` 结构体。Android framework 通过某种机制（例如，读取 `/dev/input/jsX` 设备文件）接收到这个事件，并根据事件的 `type` 和 `number` 来判断是哪个按钮被按下。游戏应用可以通过 Android SDK 提供的 API (例如 `android.view.InputEvent`) 接收到这个事件，并执行相应的游戏逻辑（例如，角色跳跃、攻击等）。
* **UI 导航 (较少见):** 虽然主要用于游戏，但理论上游戏杆也可以用于导航 Android UI。例如，可以使用方向键在应用列表或设置菜单中移动焦点。

**libc 函数的功能实现:**

这个头文件本身并不包含 libc 函数的实现，它只是定义了常量和数据结构。用户空间的程序需要使用标准的 libc 函数来与内核驱动进行交互：

1. **`open()`:** 用于打开游戏杆设备文件，通常位于 `/dev/input/jsX`。例如：
   ```c
   #include <fcntl.h>
   #include <stdio.h>
   #include <unistd.h>

   int main() {
       int fd = open("/dev/input/js0", O_RDONLY);
       if (fd == -1) {
           perror("打开游戏杆设备失败");
           return 1;
       }
       // ... 后续操作
       close(fd);
       return 0;
   }
   ```

2. **`read()`:**  用于从打开的游戏杆设备文件中读取 `struct js_event` 结构体，从而获取游戏杆事件。例如：
   ```c
   #include <fcntl.h>
   #include <stdio.h>
   #include <unistd.h>
   #include <linux/joystick.h>

   int main() {
       int fd = open("/dev/input/js0", O_RDONLY);
       if (fd == -1) {
           perror("打开游戏杆设备失败");
           return 1;
       }

       struct js_event event;
       while (read(fd, &event, sizeof(event)) == sizeof(event)) {
           printf("时间: %u, 值: %d, 类型: %u, 编号: %u\n",
                  event.time, event.value, event.type, event.number);
       }

       close(fd);
       return 0;
   }
   ```

3. **`ioctl()`:**  用于发送控制命令到游戏杆设备驱动，例如获取设备信息、设置校准等。这需要使用头文件中定义的 `JSIOCG...` 和 `JSIOCS...` 宏。例如，获取轴的数量：
   ```c
   #include <fcntl.h>
   #include <stdio.h>
   #include <unistd.h>
   #include <sys/ioctl.h>
   #include <linux/joystick.h>

   int main() {
       int fd = open("/dev/input/js0", O_RDONLY);
       if (fd == -1) {
           perror("打开游戏杆设备失败");
           return 1;
       }

       __u8 axes;
       if (ioctl(fd, JSIOCGAXES, &axes) == -1) {
           perror("获取轴数量失败");
           close(fd);
           return 1;
       }
       printf("轴的数量: %d\n", axes);

       close(fd);
       return 0;
   }
   ```

4. **`close()`:** 用于关闭打开的游戏杆设备文件。

这些 libc 函数的实现位于 bionic 库中，它们会执行相应的系统调用，与 Linux 内核进行交互。例如，`open()` 会触发 `sys_open` 系统调用，`read()` 会触发 `sys_read` 系统调用，`ioctl()` 会触发 `sys_ioctl` 系统调用。

**涉及 dynamic linker 的功能:**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker 的主要作用是在程序启动时加载程序依赖的共享库 (`.so` 文件），并解析符号引用。

然而，当一个 Android 应用或 Native Library 需要使用游戏杆功能时，它会链接到提供相关功能的共享库，例如 Android 的 NDK 提供的输入相关库或者平台相关的库。这些库在内部可能会使用到这个头文件中定义的常量和结构体，并通过系统调用与内核交互。

**`so` 布局样本:**

假设一个名为 `libgame.so` 的 Native Library 需要使用游戏杆功能：

```
libgame.so:
    NEEDED libandroid.so
    ... 其他依赖 ...
    (包含处理游戏杆输入的代码，内部使用 <linux/joystick.h> 中的定义)

libandroid.so:
    ... 其他功能 ...
    (可能包含处理底层输入事件的代码，例如从 /dev/input/jsX 读取数据并解析 js_event)
```

**链接的处理过程:**

1. 当 Android 应用程序加载 `libgame.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会解析 `libgame.so` 的 `NEEDED` 字段，发现它依赖于 `libandroid.so`。
2. Dynamic linker 会尝试在系统路径中找到 `libandroid.so` 并加载到内存中。
3. 在加载过程中，dynamic linker 会解析 `libgame.so` 和 `libandroid.so` 中的符号表，解决它们之间的函数和变量引用。例如，如果 `libgame.so` 调用了 `libandroid.so` 中处理输入事件的函数，dynamic linker 会将这些调用链接到正确的内存地址。

**逻辑推理，假设输入与输出:**

**假设输入:** 一个游戏杆在 `/dev/input/js0` 上连接到 Android 设备，并且用户按下了编号为 `0` 的按钮。

**输出:**

1. **内核驱动:** 内核的 joystick 驱动程序会检测到按钮按下事件，并创建一个 `struct js_event` 结构体，内容可能如下：
   ```
   event.time = <当前时间戳>;
   event.value = 1; // 表示按钮按下
   event.type = JS_EVENT_BUTTON | JS_EVENT_INIT; // 可能是 JS_EVENT_BUTTON | JS_EVENT_INIT，也可能只是 JS_EVENT_BUTTON，取决于事件的性质
   event.number = 0;
   ```
   （注意：`JS_EVENT_INIT` 标志通常用于指示初始状态或配置更改。）

2. **用户空间程序 (通过 `read()`):**  一个打开了 `/dev/input/js0` 的程序调用 `read()` 会读取到这个 `js_event` 结构体。

3. **Android Framework:** Android framework 可能会接收到这个事件，并将其转换为更高层次的输入事件对象。

**假设输入:**  一个程序调用 `ioctl()` 来获取游戏杆的名称。

**输出:**

1. **`ioctl()` 调用:** 程序调用 `ioctl(fd, JSIOCGNAME(len), buffer)`，其中 `fd` 是打开的游戏杆设备文件的文件描述符，`len` 是缓冲区大小，`buffer` 是用于存储名称的缓冲区。

2. **内核驱动:**  内核驱动程序会读取游戏杆的设备信息，并将名称复制到用户空间提供的 `buffer` 中。

3. **返回值:** `ioctl()` 调用成功返回 0，`buffer` 中包含游戏杆的名称。

**用户或编程常见的使用错误:**

1. **没有检查 `open()` 的返回值:** 如果 `open()` 返回 -1，表示打开设备失败，可能是因为设备文件不存在或权限不足。程序应该处理这种情况。

2. **读取的字节数不足:**  使用 `read()` 读取游戏杆事件时，应该确保读取的字节数等于 `sizeof(struct js_event)`。否则，读取到的数据可能不完整或无效。

3. **错误的 `ioctl` 命令或参数:**  使用 `ioctl()` 时，必须使用正确的命令宏 (`JSIOCG...`, `JSIOCS...`)，并传递正确的参数类型和大小。错误的命令或参数可能导致 `ioctl()` 调用失败或产生未定义的行为。

4. **没有正确处理设备移除:**  如果游戏杆在程序运行时被移除，尝试读取或写入设备文件可能会失败。程序应该能够处理这种情况。

5. **权限问题:**  访问 `/dev/input/jsX` 设备通常需要特定的权限。如果用户运行的程序没有足够的权限，`open()` 调用可能会失败。

**Android framework or ndk 是如何一步步的到达这里:**

1. **硬件事件发生:**  当用户操作游戏杆时，硬件产生电信号。
2. **内核驱动:** Linux 内核中的 `evdev` (Event Device) 子系统和特定的 joystick 驱动程序（例如 `hid-generic`）会接收和处理这些信号。
3. **生成 `input_event`:** 驱动程序将硬件事件转换为内核中的 `input_event` 结构体。
4. **`js_event` 转换 (可选):**  对于 joystick 设备，内核可能会将 `input_event` 转换为 `js_event` 结构体，并通过 `/dev/input/jsX` 接口暴露给用户空间。
5. **Android HAL (Hardware Abstraction Layer):**  Android 的 HAL 层 (特别是 `input` HAL) 可能会监听 `/dev/input/eventX` 设备 (而不是 `/dev/input/jsX`)，读取原始的 `input_event`。
6. **InputReader 和 InputDispatcher:** Android framework 的 `InputReader` 从 HAL 获取输入事件，`InputDispatcher` 将这些事件分发到相应的窗口和应用程序。
7. **View 系统:**  对于 UI 事件，事件会被传递到相应的 View 对象。
8. **Game 引擎 (NDK):**  对于使用 NDK 开发的游戏，可以通过 Android 的 `InputEvent` 类（例如 `MotionEvent`, `KeyEvent`）接收到游戏杆事件。这些事件在底层可能源自内核的 `input_event` 或 `js_event`。

**Frida hook 示例调试步骤:**

以下是一些可以使用 Frida hook 的关键点来调试游戏杆输入：

**1. Hook `open()` 系统调用:**

   ```javascript
   Interceptor.attach(Module.findExportByName(null, "open"), {
       onEnter: function(args) {
           const pathname = Memory.readUtf8String(args[0]);
           if (pathname.startsWith("/dev/input/js")) {
               console.log("[open] 打开游戏杆设备:", pathname);
               this.fd = args[0]; // 保存文件路径以便在 onLeave 中使用
           }
       },
       onLeave: function(retval) {
           if (this.fd) {
               console.log("[open] 文件描述符:", retval.toInt32());
           }
       }
   });
   ```

**2. Hook `read()` 系统调用:**

   ```javascript
   Interceptor.attach(Module.findExportByName(null, "read"), {
       onEnter: function(args) {
           const fd = args[0].toInt32();
           // 假设我们已经通过 hook open 知道了游戏杆的文件描述符
           if (fd == /* 游戏杆的文件描述符 */) {
               this.buf = args[1];
               this.count = args[2].toInt32();
               console.log("[read] 读取游戏杆设备, 字节数:", this.count);
           }
       },
       onLeave: function(retval) {
           if (this.buf && retval.toInt32() > 0) {
               const event = Memory.readByteArray(this.buf, retval.toInt32());
               console.log("[read] 读取到的数据:", hexdump(event, { ansi: true }));
               // 可以进一步解析 js_event 结构体
           }
       }
   });
   ```

**3. Hook `ioctl()` 系统调用:**

   ```javascript
   Interceptor.attach(Module.findExportByName(null, "ioctl"), {
       onEnter: function(args) {
           const fd = args[0].toInt32();
           const request = args[1].toInt32();
           // 检查是否是与 joystick 相关的 ioctl 命令
           if ((request & 0xFF) == 'j'.charCodeAt(0)) {
               console.log("[ioctl] 调用, 文件描述符:", fd, "命令:", request.toString(16));
               this.request = request;
               this.argp = args[2];
           }
       },
       onLeave: function(retval) {
           if (this.request) {
               console.log("[ioctl] 返回值:", retval.toInt32());
               // 可以根据 this.request 的值来解析 argp 指向的数据
           }
       }
   });
   ```

**4. Hook Android Framework 中处理输入事件的函数:**

   可以使用 Frida hook Android framework 中的相关类和方法，例如 `android.view.InputReader` 或 `android.view.InputDispatcher` 中的方法，来观察事件是如何被处理和分发的。这需要一些对 Android framework 源码的了解。

**调试步骤:**

1. 编写 Frida hook 脚本，根据需要 hook 相应的函数。
2. 使用 Frida 连接到目标 Android 设备或模拟器上的进程。
3. 运行 hook 脚本。
4. 操作游戏杆，观察 Frida 输出的日志，了解数据是如何流动的，以及在哪里可能出现问题。

通过这些 hook 示例，你可以深入了解 Android 系统如何处理游戏杆输入，以及如何在不同的层级上进行调试和分析。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/joystick.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_JOYSTICK_H
#define _UAPI_LINUX_JOYSTICK_H
#include <linux/types.h>
#include <linux/input.h>
#define JS_VERSION 0x020100
#define JS_EVENT_BUTTON 0x01
#define JS_EVENT_AXIS 0x02
#define JS_EVENT_INIT 0x80
struct js_event {
  __u32 time;
  __s16 value;
  __u8 type;
  __u8 number;
};
#define JSIOCGVERSION _IOR('j', 0x01, __u32)
#define JSIOCGAXES _IOR('j', 0x11, __u8)
#define JSIOCGBUTTONS _IOR('j', 0x12, __u8)
#define JSIOCGNAME(len) _IOC(_IOC_READ, 'j', 0x13, len)
#define JSIOCSCORR _IOW('j', 0x21, struct js_corr)
#define JSIOCGCORR _IOR('j', 0x22, struct js_corr)
#define JSIOCSAXMAP _IOW('j', 0x31, __u8[ABS_CNT])
#define JSIOCGAXMAP _IOR('j', 0x32, __u8[ABS_CNT])
#define JSIOCSBTNMAP _IOW('j', 0x33, __u16[KEY_MAX - BTN_MISC + 1])
#define JSIOCGBTNMAP _IOR('j', 0x34, __u16[KEY_MAX - BTN_MISC + 1])
#define JS_CORR_NONE 0x00
#define JS_CORR_BROKEN 0x01
struct js_corr {
  __s32 coef[8];
  __s16 prec;
  __u16 type;
};
#define JS_RETURN sizeof(struct JS_DATA_TYPE)
#define JS_TRUE 1
#define JS_FALSE 0
#define JS_X_0 0x01
#define JS_Y_0 0x02
#define JS_X_1 0x04
#define JS_Y_1 0x08
#define JS_MAX 2
#define JS_DEF_TIMEOUT 0x1300
#define JS_DEF_CORR 0
#define JS_DEF_TIMELIMIT 10L
#define JS_SET_CAL 1
#define JS_GET_CAL 2
#define JS_SET_TIMEOUT 3
#define JS_GET_TIMEOUT 4
#define JS_SET_TIMELIMIT 5
#define JS_GET_TIMELIMIT 6
#define JS_GET_ALL 7
#define JS_SET_ALL 8
struct JS_DATA_TYPE {
  __s32 buttons;
  __s32 x;
  __s32 y;
};
struct JS_DATA_SAVE_TYPE_32 {
  __s32 JS_TIMEOUT;
  __s32 BUSY;
  __s32 JS_EXPIRETIME;
  __s32 JS_TIMELIMIT;
  struct JS_DATA_TYPE JS_SAVE;
  struct JS_DATA_TYPE JS_CORR;
};
struct JS_DATA_SAVE_TYPE_64 {
  __s32 JS_TIMEOUT;
  __s32 BUSY;
  __s64 JS_EXPIRETIME;
  __s64 JS_TIMELIMIT;
  struct JS_DATA_TYPE JS_SAVE;
  struct JS_DATA_TYPE JS_CORR;
};
#endif

"""

```