Response:
Let's break down the thought process to arrive at the comprehensive answer.

**1. Deconstructing the Request:**

The request is multi-faceted. It asks for:

* **Functionality:** What does this header file *do*?  What are its components for?
* **Android Relevance:** How does it fit into the broader Android ecosystem?
* **`libc` Function Explanation:** Detailed explanation of how `libc` functions work *within this context*. This is tricky because the header itself doesn't *implement* `libc` functions, it *uses* them. The request is implicitly asking about the underlying system calls and device driver interaction.
* **Dynamic Linker:** How does this relate to shared libraries?
* **Logic & Examples:** Scenarios, inputs, outputs, and error cases.
* **Framework/NDK Path:** How does a request from a higher level reach this low-level interface?
* **Frida Hooking:**  Practical debugging.

**2. Initial Analysis of the Header File:**

* **`auto-generated`:** This is a crucial clue. It suggests this file isn't written by hand but generated from some other source, likely kernel definitions. This implies it's an *interface* to something.
* **`#ifndef _DVBOSD_H_`, `#define _DVBOSD_H_`, `#endif`:** Standard header guard, preventing multiple inclusions.
* **`#include <linux/compiler.h>`:** Includes kernel-specific compiler attributes. Reinforces the kernel interface idea.
* **`typedef enum { ... } OSD_Command;`:** Defines an enumeration of commands related to an On-Screen Display (OSD). Keywords like "Close," "Open," "Show," "Hide," "Clear," "Fill," "Text," "Window" are strong indicators of OSD manipulation.
* **`typedef struct osd_cmd_s { ... } osd_cmd_t;`:** Defines a structure to encapsulate an OSD command and its parameters (coordinates, color, data). This structure likely gets passed to a lower-level driver.
* **`typedef enum { ... } osd_raw_window_t;`:** Defines an enumeration of raw window types, suggesting different pixel formats and sizes. The "HR" suffix likely means "High Resolution."
* **`typedef struct osd_cap_s { ... } osd_cap_t;`:** Defines a structure to query OSD capabilities.
* **`#define OSD_CAP_MEMSIZE 1`:**  A constant for the memory size capability.
* **`#define OSD_SEND_CMD _IOW('o', 160, osd_cmd_t)`:**  A crucial macro. `_IOW` is a standard Linux macro for creating ioctl commands. This strongly suggests communication with a device driver. The `'o'` likely represents the device type, and `160` is a command number. It takes `osd_cmd_t` as input.
* **`#define OSD_GET_CAPABILITY _IOR('o', 161, osd_cap_t)`:**  Another ioctl command, this time for getting capability information (`_IOR`), taking `osd_cap_t` as input.

**3. Connecting to Android:**

* **DVB:** The directory name `dvb` points to Digital Video Broadcasting. This is a standard for digital television.
* **OSD:**  On-Screen Display is a common feature in TV and media devices.
* **`bionic/libc/kernel/uapi/linux/`:**  This path indicates these are user-space definitions mirroring kernel definitions. The `uapi` directory is where user-space programs find the system call interfaces.
* **Putting it Together:**  This header defines the interface for user-space applications (like media players or TV apps on Android) to control the OSD hardware related to DVB functionality.

**4. Addressing Specific Questions:**

* **Functionality:** Directly derived from the analysis of the enums and structures.
* **Android Relevance:** Explain the DVB context in Android, linking it to multimedia and TV apps.
* **`libc` Functions:** This requires understanding the *flow*. The header defines structures and ioctl codes. The *actual* `libc` function used is `ioctl()`. Therefore, the explanation needs to focus on `ioctl()`'s role in sending commands to device drivers. It's important to *not* try to explain the implementation of every enum or struct as a `libc` function.
* **Dynamic Linker:** The header file itself doesn't *directly* involve the dynamic linker. However, the *user-space library* that uses this header (the DVB library) *will* be dynamically linked. Therefore, the explanation needs to focus on how shared libraries work in Android and provide a sample `so` layout.
* **Logic & Examples:**  Think of common OSD operations and how the commands would be used. Consider both valid and invalid input to demonstrate potential errors.
* **Framework/NDK Path:**  Start from a user-level action (like displaying subtitles) and trace it down through the Android framework (MediaCodec, Surface, etc.) to the NDK and eventually to the system call layer where `ioctl()` would be used.
* **Frida Hooking:** Focus on hooking the `ioctl()` system call, as that's the entry point for these commands. Provide a basic Frida script targeting `ioctl` and filtering for the specific ioctl numbers.

**5. Iteration and Refinement:**

* **Clarity:** Ensure the language is clear and avoids jargon where possible.
* **Completeness:** Address all parts of the request.
* **Accuracy:** Verify the technical details (ioctl usage, etc.).
* **Structure:** Organize the answer logically, following the order of the questions. Use headings and bullet points for better readability.

**Self-Correction/Refinement Example During the Process:**

* **Initial thought:** "This header defines functions for OSD."  **Correction:** The header defines *data structures and ioctl codes*, not functions directly implemented in `libc`. The functions are in a *separate* DVB library.
* **Initial thought:** "Explain the implementation of `OSD_Close`." **Correction:** `OSD_Close` is an enum value. Explain how this enum value is used within the `osd_cmd_t` structure and passed to the driver via `ioctl()`.
* **Initial thought:** "Focus heavily on the specific details of DVB." **Correction:** While DVB is the context, the answer should focus on the *general principles* of how user-space interacts with kernel drivers via ioctl in the Android context.

By following this detailed thinking process, breaking down the problem, analyzing the input, connecting concepts, and iteratively refining the answer, a comprehensive and accurate response can be constructed.
这个头文件 `osd.handroid` 定义了用户空间程序与 Linux 内核中 DVB（Digital Video Broadcasting，数字视频广播）子系统的 OSD（On-Screen Display，屏幕显示）功能进行交互的接口。由于它位于 `bionic/libc/kernel/uapi/linux/` 目录下，说明它是 Linux 内核提供给用户空间的 API (Application Programming Interface) 的一部分，用于定义用户空间可以使用的常量、结构体和宏。`bionic` 是 Android 的 C 库，这个头文件被包含在 `bionic` 中，意味着 Android 系统中的某些组件可能会使用到这些定义来控制 DVB 设备的 OSD 功能。

**它的功能：**

这个头文件定义了以下主要功能：

1. **定义了 OSD 操作命令 (`OSD_Command` 枚举)：**  列举了可以对 OSD 进行的各种操作，例如打开、关闭、显示、隐藏、清除、填充颜色、设置调色板、设置透明度、绘制像素、绘制线条、填充区域、查询状态等等。

2. **定义了 OSD 命令结构体 (`osd_cmd_t`)：**  这个结构体用于封装要执行的 OSD 命令及其相关的参数，例如命令类型、坐标、颜色、数据指针等。用户空间程序需要填充这个结构体，然后将其传递给内核驱动。

3. **定义了原始窗口类型 (`osd_raw_window_t` 枚举)：**  定义了不同格式的原始 OSD 窗口类型，包括不同的位图格式（1位、2位、4位、8位，可能带有 HR 表示高分辨率）、YCrCb 颜色空间格式以及一些用于查询视频大小的类型。

4. **定义了 OSD 能力查询结构体 (`osd_cap_s`)：**  用于查询 OSD 设备的能力，例如可以使用的内存大小。

5. **定义了 ioctl 命令宏 (`OSD_SEND_CMD`, `OSD_GET_CAPABILITY`)：**  这是与内核驱动进行通信的关键。这两个宏定义了用于发送 OSD 命令和获取 OSD 能力的 `ioctl` 系统调用命令。

**与 Android 功能的关系及举例说明：**

尽管这个头文件是 Linux 内核的一部分，但由于 Android 基于 Linux 内核，Android 系统中的某些低层组件，特别是与多媒体和电视功能相关的部分，可能会使用这些定义。

**举例说明：**

* **Android TV 应用显示字幕或菜单：**  Android TV 设备需要能够显示字幕、音量控制、频道列表等 OSD 信息。底层的 DVB 驱动可能使用这里定义的接口来控制硬件 OSD 覆盖层，从而在屏幕上绘制这些信息。Android Framework 中的 TV Input Framework (TIF) 或者更底层的媒体解码器可能最终会调用到相关的驱动程序，而驱动程序会解释这里定义的 `OSD_Command` 和 `osd_cmd_t` 结构体。

* **机顶盒应用的 OSD 控制：**  运行在 Android 系统上的机顶盒应用可能直接或间接地使用这些接口来控制其用户界面元素的显示。例如，当用户切换频道时，应用可能会调用相关的 API 来更新屏幕上的频道号。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身并没有定义或实现 `libc` 函数。它定义的是数据结构和宏，用于与内核进行交互。真正执行 OSD 操作的是 Linux 内核中的 DVB 驱动程序。

用户空间程序（比如 Android 的一个 Service 或 Native 应用）会使用 `libc` 提供的 `ioctl` 函数来与内核驱动进行通信。

* **`ioctl()` 函数的功能实现：**
    `ioctl` (input/output control) 是一个系统调用，它允许用户空间程序向设备驱动程序发送控制命令并传递数据。
    1. **系统调用入口：** 当用户空间程序调用 `ioctl()` 时，会触发一个系统调用，陷入内核态。
    2. **查找设备驱动：** 内核会根据 `ioctl()` 的第一个参数（文件描述符）找到对应的设备驱动程序。
    3. **调用驱动程序处理函数：** 内核会将 `ioctl()` 的命令码（第二个参数，例如 `OSD_SEND_CMD`）和第三个参数（数据指针，例如指向 `osd_cmd_t` 结构体的指针）传递给设备驱动程序的 `ioctl` 处理函数。
    4. **驱动程序处理：** DVB 驱动程序会根据接收到的命令码和数据，解析 `osd_cmd_t` 结构体中的信息，然后配置底层的硬件 OSD 控制器来执行相应的操作，例如在指定的坐标绘制像素、填充颜色等。
    5. **返回结果：** 驱动程序处理完成后，会将结果返回给内核，内核再将结果返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身并不直接涉及 dynamic linker。Dynamic linker (如 Android 的 `linker64` 或 `linker`) 的作用是在程序启动时将程序依赖的共享库加载到内存中，并解析符号引用。

**假设一个使用 OSD 功能的共享库 (`libdvbosd.so`)：**

**`libdvbosd.so` 布局样本：**

```
libdvbosd.so:
    .text         # 代码段
        dvb_osd_open:  # 实现打开 OSD 功能的函数
            # ... 调用 open() 打开 DVB 设备文件 ...
        dvb_osd_show:  # 实现显示 OSD 功能的函数
            # ... 填充 osd_cmd_t 结构体 ...
            # ... 调用 ioctl(fd, OSD_SEND_CMD, &cmd) ...
        dvb_osd_close: # 实现关闭 OSD 功能的函数
            # ... 调用 close() 关闭 DVB 设备文件 ...
        # ... 其他 OSD 相关函数 ...
    .rodata       # 只读数据段
        # ... 可能包含一些常量数据 ...
    .data         # 可读写数据段
        # ... 可能包含一些全局变量 ...
    .dynsym       # 动态符号表 (包含导出的和导入的符号)
        dvb_osd_open
        dvb_osd_show
        dvb_osd_close
        ioctl         # 导入的 ioctl 函数
    .dynstr       # 动态字符串表 (存储符号名称)
    .plt          # 程序链接表 (用于延迟绑定)
        ioctl
    .got.plt      # 全局偏移量表 (用于存储外部符号的地址)
        # ... ioctl 的地址 ...
    # ... 其他段 ...
```

**链接的处理过程：**

1. **编译时链接：** 当开发者编译使用 OSD 功能的程序或库时，编译器会遇到对 `ioctl` 函数的调用以及对 `OSD_SEND_CMD` 等宏的引用。由于 `ioctl` 是 `libc` 的一部分，链接器会记录下需要链接 `libc.so`。`OSD_SEND_CMD` 等宏在预编译阶段会被替换为具体的数值。

2. **程序启动：** 当 Android 系统启动一个依赖 `libdvbosd.so` 的进程时，`linker` 会执行以下步骤：
    * **加载共享库：** `linker` 会将 `libdvbosd.so` 和它依赖的 `libc.so` 加载到进程的地址空间。
    * **解析符号：** `linker` 会解析 `libdvbosd.so` 中的符号引用。例如，当遇到对 `ioctl` 的调用时，`linker` 会在 `libc.so` 的符号表中查找 `ioctl` 的地址，并将其填入 `libdvbosd.so` 的 `.got.plt` 表中。
    * **重定位：** `linker` 会调整共享库中的地址，因为共享库被加载到内存的哪个位置是不确定的。

3. **运行时调用：** 当 `libdvbosd.so` 中的 `dvb_osd_show` 函数被调用时，它会执行 `ioctl(fd, OSD_SEND_CMD, &cmd)`。由于使用了 PLT/GOT 机制（延迟绑定），第一次调用 `ioctl` 时，会跳转到 PLT 中的一段代码，该代码会调用 `linker` 来真正解析 `ioctl` 的地址，并将其写入 GOT 表。后续的调用将直接通过 GOT 表跳转到 `ioctl` 的实现。

**假设输入与输出（逻辑推理）：**

**假设输入：** 一个 Android TV 应用想要在屏幕坐标 (100, 100) 处显示红色的 "Hello" 字样。

1. **应用层：**  应用调用 Android Framework 提供的相关 API (例如，通过 Surface 或 Canvas 进行绘制)。
2. **Framework 层：** Framework 可能会将这个绘制请求转换为底层的 OSD 操作。
3. **Native 层 (假设存在一个 `libdvbosd.so`)：**
   * 应用或 Framework 调用 `libdvbosd.so` 提供的 `dvb_osd_show_text` 函数（假设存在）。
   * `dvb_osd_show_text` 函数内部会：
     * 填充 `osd_cmd_t` 结构体：
       * `cmd = OSD_Text`
       * `x0 = 100`
       * `y0 = 100`
       * `color = RED` (假设定义了红色常量)
       * `data` 指向包含 "Hello" 字符串的内存。
     * 调用 `ioctl(fd, OSD_SEND_CMD, &cmd)`，其中 `fd` 是打开的 DVB 设备文件描述符。

**假设输出：**  屏幕上 (100, 100) 的位置会显示红色的 "Hello" 字样。

**用户或编程常见的使用错误：**

1. **传递错误的命令码：**  例如，本意是清除屏幕，却传递了显示屏幕的命令码。这会导致 OSD 执行错误的操作。

   ```c
   osd_cmd_t cmd;
   cmd.cmd = OSD_Show; // 错误：本意是清除
   // ... 其他参数 ...
   ioctl(fd, OSD_SEND_CMD, &cmd);
   ```

2. **坐标越界：**  设置的绘制坐标超出了 OSD 缓冲区的范围，可能导致程序崩溃或显示异常。

   ```c
   osd_cmd_t cmd;
   cmd.cmd = OSD_SetPixel;
   cmd.x0 = 9999; // 错误：超出屏幕宽度
   cmd.y0 = 9999; // 错误：超出屏幕高度
   // ...
   ioctl(fd, OSD_SEND_CMD, &cmd);
   ```

3. **数据指针错误：**  `osd_cmd_t` 结构体中的 `data` 指针指向无效的内存地址，或者数据大小与预期不符，会导致内核访问非法内存。

   ```c
   osd_cmd_t cmd;
   cmd.cmd = OSD_Text;
   cmd.data = NULL; // 错误：数据指针为空
   // ...
   ioctl(fd, OSD_SEND_CMD, &cmd);
   ```

4. **忘记打开设备文件：**  在使用 `ioctl` 发送命令前，必须先使用 `open()` 系统调用打开对应的 DVB 设备文件，获取有效的文件描述符。

   ```c
   int fd = -1; // 忘记打开设备文件
   osd_cmd_t cmd;
   cmd.cmd = OSD_Clear;
   ioctl(fd, OSD_SEND_CMD, &cmd); // 错误：文件描述符无效
   ```

5. **权限不足：**  用户空间程序可能没有足够的权限访问 `/dev/dvb/...` 等设备文件，导致 `open()` 或 `ioctl()` 调用失败。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**步骤：**

1. **Android 应用层 (Java/Kotlin)：**  用户在 Android TV 应用中执行某个操作，例如点击菜单按钮，或者播放视频显示字幕。

2. **Android Framework 层 (Java)：**
   * **View 系统：**  如果涉及 UI 元素的绘制，可能会涉及到 View 系统的渲染流程。
   * **Media Framework：** 如果是视频字幕，`MediaCodec` 或 `SubtitleController` 等组件会负责处理字幕数据。
   * **TV Input Framework (TIF)：** 如果是 TV 应用相关的 OSD，TIF 可能会参与管理。
   * 这些 Framework 组件最终可能需要将绘制请求传递到更底层的 Native 层。

3. **NDK 层 (C/C++)：**
   * **JNI 调用：** Framework 层通过 JNI (Java Native Interface) 调用 Native 代码。
   * **Native 库：** 可能存在一个或多个 Native 库（`.so` 文件）负责与底层硬件交互。这些库可能会使用到这个 `osd.handroid` 头文件中定义的结构体和宏。
   * 例如，一个负责 DVB OSD 控制的 Native 库可能会包含类似以下的 C++ 代码：

     ```c++
     #include <sys/ioctl.h>
     #include <fcntl.h>
     #include <linux/dvb/osd.handroid> // 包含头文件
     #include <unistd.h>

     void showTextOnOsd(const char* text, int x, int y, int color) {
         int fd = open("/dev/dvb0.osd0", O_RDWR); // 打开 OSD 设备文件
         if (fd < 0) {
             perror("open");
             return;
         }

         osd_cmd_t cmd;
         cmd.cmd = OSD_Text;
         cmd.x0 = x;
         cmd.y0 = y;
         cmd.color = color;
         cmd.data = const_cast<char*>(text); // 注意生命周期管理
         cmd.x1 = strlen(text); // 假设 x1 用于传递文本长度

         if (ioctl(fd, OSD_SEND_CMD, &cmd) < 0) {
             perror("ioctl");
         }

         close(fd);
     }
     ```

4. **系统调用层：**  Native 库最终会调用 `ioctl` 系统调用，并将 `OSD_SEND_CMD` 和填充好的 `osd_cmd_t` 结构体传递给内核。

5. **内核驱动层：** Linux 内核中的 DVB 驱动程序接收到 `ioctl` 调用，解析命令和参数，并控制底层的 OSD 硬件。

**Frida Hook 示例调试：**

可以使用 Frida Hook `ioctl` 系统调用来观察参数，验证 Framework 或 NDK 层是否正确地构造了 OSD 命令。

```python
import frida
import sys

package_name = "your.tv.app.package" # 替换为你的 TV 应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 定义 OSD_SEND_CMD 的值 (需要根据头文件中的定义)
        const OSD_SEND_CMD = 0xbf8000a0; // _IOW('o', 160, osd_cmd_t) 的值

        if (request === OSD_SEND_CMD) {
            console.log("----------------- ioctl(OSD_SEND_CMD) called -----------------");
            console.log("File Descriptor:", fd);
            console.log("Request:", request);

            // 读取 osd_cmd_t 结构体
            const osd_cmd_t = {
                cmd: argp.readU32(),
                x0: argp.add(4).readS32(),
                y0: argp.add(8).readS32(),
                x1: argp.add(12).readS32(),
                y1: argp.add(16).readS32(),
                color: argp.add(20).readS32(),
                data: argp.add(24).readPointer()
            };

            console.log("OSD Command:", osd_cmd_t.cmd);
            console.log("x0:", osd_cmd_t.x0);
            console.log("y0:", osd_cmd_t.y0);
            console.log("x1:", osd_cmd_t.x1);
            console.log("y1:", osd_cmd_t.y1);
            console.log("Color:", osd_cmd_t.color);
            console.log("Data Pointer:", osd_cmd_t.data);

            if (osd_cmd_t.cmd === 19) { // 假设 OSD_Text 的值为 19
                // 读取字符串数据 (需要知道字符串的长度，这里假设最大长度为 128)
                try {
                    const text = osd_cmd_t.data.readUtf8String(128);
                    console.log("Text Data:", text);
                } catch (e) {
                    console.log("Error reading text data:", e);
                }
            }
        }
    },
    onLeave: function(retval) {
        // console.log("ioctl returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. 将上面的 Python 代码保存为 `hook_osd.py`。
2. 将 `your.tv.app.package` 替换为你想要调试的 Android TV 应用的包名。
3. 确保你的 Android 设备已连接并通过 USB 调试模式连接到电脑。
4. 确保已安装 Frida 和 Frida 的 Python 绑定 (`pip install frida-tools`).
5. 运行你的 Android TV 应用。
6. 在电脑上运行 `python hook_osd.py`。
7. 在 Android TV 应用中执行会触发 OSD 操作的动作。
8. Frida 脚本会在控制台上打印出 `ioctl` 系统调用的参数，包括文件描述符、命令码以及 `osd_cmd_t` 结构体的内容。

通过分析 Frida 的输出，你可以了解 Android Framework 或 NDK 层是如何构造和传递 OSD 命令的，从而帮助你调试 OSD 相关的问题。需要注意的是，`OSD_SEND_CMD` 的具体数值需要根据你的系统和内核头文件进行确认。你可以通过查看 `/usr/include/linux/dvb/osd.h` 或类似的路径找到确切的值。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/dvb/osd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _DVBOSD_H_
#define _DVBOSD_H_
#include <linux/compiler.h>
typedef enum {
  OSD_Close = 1,
  OSD_Open,
  OSD_Show,
  OSD_Hide,
  OSD_Clear,
  OSD_Fill,
  OSD_SetColor,
  OSD_SetPalette,
  OSD_SetTrans,
  OSD_SetPixel,
  OSD_GetPixel,
  OSD_SetRow,
  OSD_SetBlock,
  OSD_FillRow,
  OSD_FillBlock,
  OSD_Line,
  OSD_Query,
  OSD_Test,
  OSD_Text,
  OSD_SetWindow,
  OSD_MoveWindow,
  OSD_OpenRaw,
} OSD_Command;
typedef struct osd_cmd_s {
  OSD_Command cmd;
  int x0;
  int y0;
  int x1;
  int y1;
  int color;
  void  * data;
} osd_cmd_t;
typedef enum {
  OSD_BITMAP1,
  OSD_BITMAP2,
  OSD_BITMAP4,
  OSD_BITMAP8,
  OSD_BITMAP1HR,
  OSD_BITMAP2HR,
  OSD_BITMAP4HR,
  OSD_BITMAP8HR,
  OSD_YCRCB422,
  OSD_YCRCB444,
  OSD_YCRCB444HR,
  OSD_VIDEOTSIZE,
  OSD_VIDEOHSIZE,
  OSD_VIDEOQSIZE,
  OSD_VIDEODSIZE,
  OSD_VIDEOTHSIZE,
  OSD_VIDEOTQSIZE,
  OSD_VIDEOTDSIZE,
  OSD_VIDEONSIZE,
  OSD_CURSOR
} osd_raw_window_t;
typedef struct osd_cap_s {
  int cmd;
#define OSD_CAP_MEMSIZE 1
  long val;
} osd_cap_t;
#define OSD_SEND_CMD _IOW('o', 160, osd_cmd_t)
#define OSD_GET_CAPABILITY _IOR('o', 161, osd_cap_t)
#endif
```