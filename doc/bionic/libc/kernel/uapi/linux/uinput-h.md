Response:
Let's break down the thought process for analyzing this header file and generating the comprehensive response.

**1. Understanding the Context and Goal:**

The request clearly states the file is `uinput.h` from the Android Bionic library, specifically the kernel uAPI (userspace API). The core goal is to explain its functionality, how it relates to Android, how the underlying libc functions work, and how it's used in the Android framework and NDK. The request also asks for examples of common errors, dynamic linker information (though less relevant here), and Frida hooks.

**2. Initial Read and Keyword Spotting:**

My first pass through the code involves identifying key terms and structures:

* `#ifndef`, `#define`: Standard C header guard.
* `linux/types.h`, `linux/input.h`:  Dependencies on other Linux kernel headers, indicating interaction with the kernel's input subsystem.
* `UINPUT_VERSION`, `UINPUT_MAX_NAME_SIZE`:  Constants defining version and name limits.
* `struct uinput_ff_upload`, `struct uinput_ff_erase`: Structures related to force feedback.
* `UINPUT_IOCTL_BASE`, `UI_DEV_CREATE`, `UI_DEV_DESTROY`, etc.:  Macros defining ioctl commands. This is a **major clue** indicating this header defines the interface for controlling a Uinput device via ioctl system calls.
* `struct uinput_setup`, `struct uinput_abs_setup`: Structures for configuring the Uinput device.
* `UI_SET_EVBIT`, `UI_SET_KEYBIT`, etc.: Macros for setting supported event types and device capabilities.
* `struct uinput_user_dev`:  Another structure for defining a Uinput device.
* `EV_UINPUT`, `UI_FF_UPLOAD`, `UI_FF_ERASE`: Constants for specific events/operations.

**3. High-Level Functionality Identification:**

Based on the keywords, especially the `ioctl` definitions and the structures, I can deduce the primary function of this header: **It defines the userspace API for creating and controlling virtual input devices in the Linux kernel using the Uinput driver.**  This allows applications to simulate input events (keyboard presses, mouse movements, joystick actions, etc.) without a physical device.

**4. Connecting to Android:**

The fact that it's part of Bionic immediately links it to Android. I then think about how virtual input devices are relevant to Android:

* **Testing:**  Automated testing can use Uinput to simulate user interactions.
* **Accessibility:**  Assistive technologies might use Uinput to inject input events.
* **Gaming:**  Emulators or games might use Uinput to map input from external controllers or simulate touch events.
* **Remote control/virtualization:** Applications controlling Android remotely could use Uinput.

**5. Deeper Dive into Structures and Macros:**

Now I examine the individual structures and macros more closely:

* **`uinput_ff_upload`, `uinput_ff_erase`:**  Clearly related to force feedback. The `request_id` and `retval` suggest a request/response mechanism, likely with ioctl. The embedded `ff_effect` and `old` structures hint at updating force feedback effects.
* **`UI_DEV_CREATE`, `UI_DEV_DESTROY`, `UI_DEV_SETUP`, `UI_ABS_SETUP`:** These `ioctl` commands suggest a lifecycle for Uinput devices: create, configure (name, capabilities, axes), and destroy.
* **`UI_SET_*BIT` macros:** These are for setting which types of events (key presses, mouse movements, absolute axes, etc.) the virtual device will support. This aligns with the `input.h` dependency.
* **`uinput_user_dev`:**  This structure seems like another way to define a Uinput device, likely used during the initial creation or setup. The `absmax`, `absmin`, etc., members relate to the range and precision of absolute axes (like joystick or touchscreen coordinates).

**6. Explanation of libc Functions and Dynamic Linking (Less Relevant Here):**

The request asks about libc functions. The key libc function involved here is `ioctl`. I need to explain:

* **`ioctl()` signature and purpose:**  Controlling device-specific operations.
* **How `ioctl` relates to the defined macros:**  The macros define the command codes passed to `ioctl`.
* **The data structures passed to `ioctl`:** The `uinput_*` structures.

Dynamic linking is less directly involved here because this is a header file defining the kernel API. However, an application using this header would link against `libc.so` to use the `ioctl` function. I should briefly touch upon this.

**7. Logical Inference, Assumptions, and Examples:**

I need to provide examples of how these components work together. This involves:

* **Scenario:**  Creating a simple virtual keyboard.
* **Steps:** Open `/dev/uinput`, use `UI_DEV_CREATE`, `UI_DEV_SETUP` (with keyboard event bits), and then write `input_event` structures to simulate key presses.
* **Assumptions:**  The kernel has the `uinput` module loaded.
* **Input/Output:** The simulated key presses should be visible to applications listening for keyboard events.

**8. Common Usage Errors:**

Think about what could go wrong:

* **Permissions:**  Not having write access to `/dev/uinput`.
* **Incorrect `ioctl` calls:**  Using the wrong command codes or data structures.
* **Forgetting to set event bits:** The virtual device won't generate events if the corresponding bits aren't set.
* **Incorrect data format:** Sending malformed `input_event` structures.
* **Resource leaks:** Not destroying the device after use.

**9. Android Framework/NDK Usage and Frida Hooks:**

Trace the path from the Android framework or NDK to this header:

* **NDK:**  An NDK application can directly include this header and use the `ioctl` system call.
* **Framework:**  The framework likely has higher-level APIs that abstract away the direct `ioctl` calls, but these APIs ultimately rely on interacting with the Uinput driver. Think about input injection mechanisms in the framework.

For Frida hooks, demonstrate how to intercept the `ioctl` call with the relevant `UI_*` commands to observe the interactions.

**10. Structuring the Response:**

Finally, organize the information logically with clear headings and examples. Use code blocks for the header file and Frida snippets. Maintain a conversational and informative tone.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus heavily on the force feedback aspects. **Correction:** Realize that the core functionality is about general virtual input device creation, and force feedback is a specific feature.
* **Overemphasis on dynamic linking:**  Recognize that while related, it's not the primary focus of this header file. Keep the explanation concise.
* **Vague examples:**  Ensure the examples are concrete and illustrative, showing the flow of actions.
* **Missing details:** Double-check for important aspects like permissions and resource management.

By following these steps, including iterative refinement, I can generate a comprehensive and accurate answer to the user's request.
这是一个关于 Linux Uinput 驱动的用户空间 API 头文件 (`uinput.h`)。它定义了用户空间程序如何与 Uinput 驱动进行交互，从而创建和控制虚拟输入设备。

**功能列表:**

1. **创建和销毁虚拟输入设备:**
   - `UI_DEV_CREATE`: 用于创建一个新的虚拟输入设备。
   - `UI_DEV_DESTROY`: 用于销毁一个已创建的虚拟输入设备。

2. **配置虚拟输入设备的基本属性:**
   - `struct uinput_setup`: 用于设置虚拟输入设备的 ID (vendor, product, version) 和名称。
   - `UI_DEV_SETUP`: 用于将 `uinput_setup` 结构体的信息传递给内核，配置虚拟设备。

3. **配置虚拟输入设备的事件类型和能力:**
   - `UI_SET_EVBIT`: 设置设备支持的事件类型（例如，EV_KEY, EV_REL, EV_ABS）。
   - `UI_SET_KEYBIT`: 设置设备支持的按键码。
   - `UI_SET_RELBIT`: 设置设备支持的相对轴（例如，鼠标的 X 和 Y 轴）。
   - `UI_SET_ABSBIT`: 设置设备支持的绝对轴（例如，触摸屏的 X 和 Y 轴，摇杆）。
   - `UI_SET_MSCBIT`: 设置设备支持的杂项事件。
   - `UI_SET_LEDBIT`: 设置设备支持的 LED 指示灯。
   - `UI_SET_SNDBIT`: 设置设备支持的声音事件。
   - `UI_SET_FFBIT`: 设置设备支持的力反馈效果。
   - `UI_SET_PHYS`: 设置设备的物理路径信息。
   - `UI_SET_SWBIT`: 设置设备支持的开关事件。
   - `UI_SET_PROPBIT`: 设置设备的属性位。

4. **配置绝对轴的属性:**
   - `struct uinput_abs_setup`: 用于设置特定绝对轴的代码和属性（最小值、最大值、模糊度、平坦度）。
   - `UI_ABS_SETUP`: 用于将 `uinput_abs_setup` 结构体的信息传递给内核，配置绝对轴。

5. **力反馈功能:**
   - `struct uinput_ff_upload`: 用于上传一个新的力反馈效果到设备。
   - `struct uinput_ff_erase`: 用于删除设备上的一个力反馈效果。
   - `UI_BEGIN_FF_UPLOAD`, `UI_END_FF_UPLOAD`: 成对使用，用于启动和结束力反馈效果的上传过程。
   - `UI_BEGIN_FF_ERASE`, `UI_END_FF_ERASE`: 成对使用，用于启动和结束力反馈效果的删除过程。

6. **获取系统信息:**
   - `UI_GET_SYSNAME(len)`: 获取设备的系统名称。
   - `UI_GET_VERSION`: 获取 Uinput 接口的版本号。

7. **定义 Uinput 特有的事件类型:**
   - `EV_UINPUT`: 表示一个 Uinput 特有的事件。
   - `UI_FF_UPLOAD`, `UI_FF_ERASE`:  用于标识力反馈上传和删除操作。

8. **定义 Uinput 用户设备结构体:**
   - `struct uinput_user_dev`:  包含虚拟输入设备的名称、ID、支持的最大力反馈效果数量以及绝对轴的属性。

**与 Android 功能的关系及举例说明:**

Uinput 在 Android 中被广泛用于模拟输入事件，这对于以下场景至关重要：

* **自动化测试:** Android 框架和开发者可以使用 Uinput 来编写自动化测试脚本，模拟用户与应用的交互，例如点击按钮、滑动屏幕、输入文本等。
    * **举例:**  一个自动化测试脚本可以创建一个虚拟的触摸屏设备，然后通过 Uinput 向其发送触摸事件，模拟用户在屏幕上的操作，从而测试应用的 UI 和功能。

* **辅助功能:**  辅助功能应用可以使用 Uinput 来模拟输入，帮助残障人士操作设备。
    * **举例:** 一个辅助功能应用可以监听用户的语音指令，然后使用 Uinput 将这些指令转换为触摸或按键事件，从而实现语音控制设备。

* **远程控制和虚拟化:**  远程控制应用或虚拟化环境可以使用 Uinput 将远程的输入事件传递到 Android 系统。
    * **举例:**  一个远程桌面应用可以将用户在电脑键盘上的输入转换为 Uinput 事件，发送到 Android 设备，从而实现远程控制。

* **游戏模拟器:**  游戏模拟器可以使用 Uinput 将手柄或键盘的输入映射到模拟的游戏设备上。
    * **举例:** 一个 PSP 模拟器可以使用 Uinput 创建一个虚拟的游戏手柄，并将用户连接的物理手柄的输入转换为该虚拟手柄的事件，从而让用户在 Android 上玩 PSP 游戏。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并没有定义 libc 函数的实现，它定义的是与内核交互的常量、结构体和宏。实际的交互是通过系统调用完成的，最常用的系统调用是 `ioctl`。

* **`ioctl()` 函数:**  `ioctl` (input/output control) 是一个用于设备驱动程序执行设备特定操作的系统调用。

   在 Uinput 的上下文中，`ioctl` 用于发送命令到 `/dev/uinput` 设备节点，从而执行诸如创建、销毁、配置虚拟输入设备以及上传/删除力反馈效果等操作。

   **实现原理:**
   1. 用户空间的程序调用 `ioctl` 函数，传入文件描述符（`/dev/uinput` 的文件描述符）、一个请求码（例如 `UI_DEV_CREATE`），以及一个可选的指向数据的指针（例如指向 `uinput_setup` 结构体的指针）。
   2. 内核接收到 `ioctl` 系统调用，并根据文件描述符找到对应的设备驱动程序（Uinput 驱动）。
   3. Uinput 驱动根据接收到的请求码执行相应的操作。例如，如果请求码是 `UI_DEV_CREATE`，驱动程序会创建一个新的虚拟输入设备；如果请求码是 `UI_SET_KEYBIT`，驱动程序会设置该虚拟设备支持的按键。
   4. 如果 `ioctl` 调用需要返回数据，驱动程序会将数据写入用户空间程序提供的缓冲区。
   5. `ioctl` 函数返回一个状态码，指示操作是否成功。

   例如，当调用 `ioctl(fd, UI_DEV_CREATE)` 时，内核中的 Uinput 驱动会创建一个新的虚拟输入设备实例，并返回成功或失败的状态。当调用 `ioctl(fd, UI_DEV_SETUP, &setup)` 时，驱动程序会读取 `setup` 结构体中的信息，并配置刚刚创建的虚拟设备的名称和 ID。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不涉及 dynamic linker 的功能。dynamic linker (例如 Android 中的 `linker64` 或 `linker`) 负责在程序启动时加载共享库，并解析符号引用。

如果一个用户空间的程序使用了这个头文件中定义的常量和结构体，它会链接到 `libc.so`，因为 `ioctl` 函数是 `libc` 提供的。

**so 布局样本 (libc.so 的简化示例):**

```
libc.so:
    .text:  # 包含可执行代码
        ...
        ioctl:  # ioctl 函数的实现代码
        ...
    .data:  # 包含已初始化的全局变量
        ...
    .bss:   # 包含未初始化的全局变量
        ...
    .symtab: # 符号表，包含导出的符号（例如 ioctl）
        ...
        ioctl (地址)
        ...
    .dynsym: # 动态符号表
        ...
        ioctl (地址)
        ...
    .rel.dyn: # 动态重定位表
        ...
```

**链接的处理过程:**

1. **编译时:** 编译器在编译用户程序时，如果遇到了 `ioctl` 函数的调用，它会在生成的目标文件中记录一个对 `ioctl` 符号的未定义引用。

2. **链接时:** 链接器 (`ld`) 将用户程序的目标文件与所需的共享库（例如 `libc.so`) 链接在一起。链接器会查找 `libc.so` 的符号表 (`.symtab` 或 `.dynsym`)，找到 `ioctl` 符号的定义，并将用户程序中对 `ioctl` 的未定义引用解析为 `libc.so` 中 `ioctl` 函数的地址。

3. **运行时:** 当程序启动时，dynamic linker 会加载 `libc.so` 到内存中。它会遍历用户程序的动态重定位表 (`.rel.dyn`)，根据记录的信息，将用户程序中对 `ioctl` 函数的调用地址修改为 `libc.so` 中 `ioctl` 函数的实际加载地址。这样，程序在运行时就可以正确地调用 `ioctl` 函数。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户程序想要创建一个简单的虚拟键盘设备：

**假设输入:**

1. 打开 `/dev/uinput` 设备节点得到文件描述符 `fd`。
2. 定义 `struct uinput_setup setup`:
   ```c
   struct uinput_setup setup;
   memset(&setup, 0, sizeof(setup));
   setup.id.bustype = BUS_VIRTUAL;
   setup.id.vendor = 0x1234;
   setup.id.product = 0x5678;
   strcpy(setup.name, "My Virtual Keyboard");
   ```
3. 调用 `ioctl(fd, UI_DEV_CREATE)`。
4. 调用 `ioctl(fd, UI_DEV_SETUP, &setup)`。
5. 调用 `ioctl(fd, UI_SET_EVBIT, EV_KEY)`。
6. 调用 `ioctl(fd, UI_SET_KEYBIT, KEY_A)`。
7. 调用 `ioctl(fd, UI_SET_KEYBIT, KEY_B)`。
8. 发送按键事件模拟按下 'A' 键:
   ```c
   struct input_event event;
   memset(&event, 0, sizeof(event));
   event.type = EV_KEY;
   event.code = KEY_A;
   event.value = 1; // 按下
   write(fd, &event, sizeof(event));

   memset(&event, 0, sizeof(event));
   event.type = EV_SYN;
   event.code = SYN_REPORT;
   event.value = 0;
   write(fd, &event, sizeof(event));
   ```
9. 发送按键事件模拟释放 'A' 键:
   ```c
   memset(&event, 0, sizeof(event));
   event.type = EV_KEY;
   event.code = KEY_A;
   event.value = 0; // 释放
   write(fd, &event, sizeof(event));

   memset(&event, 0, sizeof(event));
   event.type = EV_SYN;
   event.code = SYN_REPORT;
   event.value = 0;
   write(fd, &event, sizeof(event));
   ```
10. 调用 `ioctl(fd, UI_DEV_DESTROY)`。
11. 关闭文件描述符 `fd`。

**假设输出:**

如果在系统中运行了这个程序，并且有其他程序监听键盘事件（例如，文本编辑器），那么当程序执行到发送按键事件的步骤时，文本编辑器中将会显示字母 'a'。这表明虚拟键盘成功模拟了按键事件。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **权限问题:** 用户程序没有足够的权限访问 `/dev/uinput`。
   * **错误示例:** 运行程序时出现 "Permission denied" 错误。
   * **解决方法:** 确保用户具有访问 `/dev/uinput` 的权限，可能需要使用 `sudo` 运行程序或配置 Udev 规则。

2. **忘记设置必要的事件位:**  在创建虚拟设备后，忘记使用 `UI_SET_EVBIT` 设置设备支持的事件类型，或者忘记使用 `UI_SET_KEYBIT` 等设置具体的按键或轴。
   * **错误示例:** 创建的虚拟设备虽然存在，但是无法产生任何输入事件。
   * **解决方法:** 确保使用 `UI_SET_EVBIT` 设置了相应的事件类型（例如 `EV_KEY`），并使用 `UI_SET_KEYBIT`、`UI_SET_RELBIT`、`UI_SET_ABSBIT` 等设置了具体的按键、相对轴或绝对轴。

3. **发送事件时缺少 `EV_SYN` 事件:**  在发送一系列输入事件后，忘记发送 `EV_SYN` 同步事件。
   * **错误示例:** 接收输入事件的程序可能无法正确识别完整的事件序列，导致行为异常。
   * **解决方法:**  在每次发送一个完整的输入事件（例如，按下和释放一个按键）后，务必发送 `EV_SYN` 事件，告诉接收者这是一个完整的事件。

4. **使用错误的 `ioctl` 命令码或结构体:**  传递给 `ioctl` 的命令码与实际要执行的操作不符，或者传递了错误的结构体类型或数据。
   * **错误示例:**  程序运行时可能崩溃或产生不可预测的行为。
   * **解决方法:**  仔细查阅 `uinput.h` 头文件，确保使用的 `ioctl` 命令码和结构体类型与所需的操作一致。

5. **忘记销毁虚拟设备:**  在程序结束时，忘记使用 `UI_DEV_DESTROY` 销毁创建的虚拟设备。
   * **后果:**  虽然不会立即导致错误，但可能会导致系统资源泄漏。
   * **解决方法:**  在程序不再需要虚拟设备时，始终调用 `ioctl(fd, UI_DEV_DESTROY)` 来释放资源。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 Uinput 的路径:**

Android Framework 通常不会直接操作 `/dev/uinput`。相反，它会使用更高层次的抽象 API，这些 API 会在底层与 Uinput 驱动交互。

1. **InputManagerService:** Android Framework 中负责处理所有输入事件的核心服务是 `InputManagerService`。

2. **InputReader:** `InputManagerService` 使用 `InputReader` 从各种输入设备（包括物理设备和虚拟设备）读取原始输入事件。对于虚拟输入设备，`InputReader` 可以通过 Uinput 驱动接收事件。

3. **Native 代码:**  `InputManagerService` 和 `InputReader` 的某些部分是用 C++ 编写的，并通过 JNI 与 Java 代码交互。这些 native 代码会使用底层的 Linux 系统调用（例如 `open`, `ioctl`, `write`）与 `/dev/uinput` 进行通信。

4. **NDK 应用:** NDK 应用可以直接包含 `uinput.h` 头文件，并使用标准 C 库函数（如 `open`, `ioctl`, `write`) 与 Uinput 驱动交互。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 NDK 应用调用 `ioctl` 与 Uinput 驱动交互的示例：

```javascript
// attach 到目标进程
const processName = "your.ndk.app.package"; // 替换为你的 NDK 应用包名
const session = Frida.attach(processName);

// 拦截 ioctl 函数
const ioctlPtr = Module.findExportByName("libc.so", "ioctl");

if (ioctlPtr) {
  Interceptor.attach(ioctlPtr, {
    onEnter: function (args) {
      const fd = args[0].toInt32();
      const request = args[1].toInt32();

      // 检查是否是与 Uinput 相关的 ioctl 调用
      if (fd > 0) { // 假设文件描述符大于 0 是有效的文件描述符
        console.log("ioctl called");
        console.log("  fd:", fd);
        console.log("  request:", request, "(" + request.toString(16) + ")");

        // 根据 request 的值判断具体的操作
        if (request === 0x55015501) { // UI_DEV_CREATE
          console.log("  Operation: UI_DEV_CREATE");
        } else if (request === 0x55025501) { // UI_DEV_DESTROY
          console.log("  Operation: UI_DEV_DESTROY");
        } else if (request === 0xc0145503) { // UI_DEV_SETUP
          console.log("  Operation: UI_DEV_SETUP");
          const setupPtr = ptr(args[2]);
          const setup = setupPtr.readByteArray(108); // sizeof(struct uinput_setup)
          console.log("  uinput_setup:", hexdump(setup));
        } else if (request === 0xc0045504) { // UI_ABS_SETUP
          console.log("  Operation: UI_ABS_SETUP");
          const absSetupPtr = ptr(args[2]);
          const absSetup = absSetupPtr.readByteArray(12); // sizeof(struct uinput_abs_setup)
          console.log("  uinput_abs_setup:", hexdump(absSetup));
        } else if (request === 0xc0045564) { // UI_SET_EVBIT
          console.log("  Operation: UI_SET_EVBIT");
          const evBit = args[2].toInt32();
          console.log("  EV Code:", evBit);
        }
        // ... 其他 Uinput 相关的 ioctl 命令
      }
    },
    onLeave: function (retval) {
      console.log("ioctl returned:", retval);
    },
  });
} else {
  console.error("Failed to find ioctl in libc.so");
}
```

**使用方法:**

1. 将上面的 JavaScript 代码保存为 `.js` 文件（例如 `uinput_hook.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f your.ndk.app.package -l uinput_hook.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U your.ndk.app.package -l uinput_hook.js
   ```
3. 当目标 NDK 应用调用 `ioctl` 函数时，Frida 会拦截调用，并打印出相关的参数信息，包括文件描述符、请求码以及传递的数据结构的内容。

**注意:**

* 你需要将 `your.ndk.app.package` 替换为你想要调试的 NDK 应用的实际包名。
* 上面的 Frida Hook 示例仅拦截了部分常见的 Uinput `ioctl` 命令，你需要根据需要添加对其他命令的拦截。
* `ioctl` 的请求码可以使用 `grep "UI_.* =" bionic/libc/kernel/uapi/linux/uinput.h` 命令查找。
* 对于传递结构体的 `ioctl` 调用，需要根据结构体的大小读取内存数据并进行解析。

通过这种方式，你可以观察 NDK 应用如何使用 Uinput 驱动创建和控制虚拟输入设备，从而进行调试和分析。对于 Android Framework，你可以尝试 hook `InputManagerService` 或 `InputReader` 中与 Uinput 交互的 native 函数，但通常会更复杂一些。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/uinput.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__UINPUT_H_
#define _UAPI__UINPUT_H_
#include <linux/types.h>
#include <linux/input.h>
#define UINPUT_VERSION 5
#define UINPUT_MAX_NAME_SIZE 80
struct uinput_ff_upload {
  __u32 request_id;
  __s32 retval;
  struct ff_effect effect;
  struct ff_effect old;
};
struct uinput_ff_erase {
  __u32 request_id;
  __s32 retval;
  __u32 effect_id;
};
#define UINPUT_IOCTL_BASE 'U'
#define UI_DEV_CREATE _IO(UINPUT_IOCTL_BASE, 1)
#define UI_DEV_DESTROY _IO(UINPUT_IOCTL_BASE, 2)
struct uinput_setup {
  struct input_id id;
  char name[UINPUT_MAX_NAME_SIZE];
  __u32 ff_effects_max;
};
#define UI_DEV_SETUP _IOW(UINPUT_IOCTL_BASE, 3, struct uinput_setup)
struct uinput_abs_setup {
  __u16 code;
  struct input_absinfo absinfo;
};
#define UI_ABS_SETUP _IOW(UINPUT_IOCTL_BASE, 4, struct uinput_abs_setup)
#define UI_SET_EVBIT _IOW(UINPUT_IOCTL_BASE, 100, int)
#define UI_SET_KEYBIT _IOW(UINPUT_IOCTL_BASE, 101, int)
#define UI_SET_RELBIT _IOW(UINPUT_IOCTL_BASE, 102, int)
#define UI_SET_ABSBIT _IOW(UINPUT_IOCTL_BASE, 103, int)
#define UI_SET_MSCBIT _IOW(UINPUT_IOCTL_BASE, 104, int)
#define UI_SET_LEDBIT _IOW(UINPUT_IOCTL_BASE, 105, int)
#define UI_SET_SNDBIT _IOW(UINPUT_IOCTL_BASE, 106, int)
#define UI_SET_FFBIT _IOW(UINPUT_IOCTL_BASE, 107, int)
#define UI_SET_PHYS _IOW(UINPUT_IOCTL_BASE, 108, char *)
#define UI_SET_SWBIT _IOW(UINPUT_IOCTL_BASE, 109, int)
#define UI_SET_PROPBIT _IOW(UINPUT_IOCTL_BASE, 110, int)
#define UI_BEGIN_FF_UPLOAD _IOWR(UINPUT_IOCTL_BASE, 200, struct uinput_ff_upload)
#define UI_END_FF_UPLOAD _IOW(UINPUT_IOCTL_BASE, 201, struct uinput_ff_upload)
#define UI_BEGIN_FF_ERASE _IOWR(UINPUT_IOCTL_BASE, 202, struct uinput_ff_erase)
#define UI_END_FF_ERASE _IOW(UINPUT_IOCTL_BASE, 203, struct uinput_ff_erase)
#define UI_GET_SYSNAME(len) _IOC(_IOC_READ, UINPUT_IOCTL_BASE, 44, len)
#define UI_GET_VERSION _IOR(UINPUT_IOCTL_BASE, 45, unsigned int)
#define EV_UINPUT 0x0101
#define UI_FF_UPLOAD 1
#define UI_FF_ERASE 2
struct uinput_user_dev {
  char name[UINPUT_MAX_NAME_SIZE];
  struct input_id id;
  __u32 ff_effects_max;
  __s32 absmax[ABS_CNT];
  __s32 absmin[ABS_CNT];
  __s32 absfuzz[ABS_CNT];
  __s32 absflat[ABS_CNT];
};
#endif

"""

```