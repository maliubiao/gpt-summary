Response:
Let's break down the thought process for analyzing the `termios_test.cpp` file.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the provided C++ test file and relate it to the broader Android ecosystem. This involves identifying the tested functions, their purpose, and how they interact with the underlying system. The prompt also asks for specific details like libc implementation, dynamic linker involvement, error handling, and debugging techniques.

**2. Initial Scan and Keyword Identification:**

First, a quick skim of the code reveals several key elements:

* `#include <termios.h>`:  This immediately tells us the file is about testing the `termios` interface, which is used for controlling terminal I/O.
* `#include <errno.h>`, `#include <fcntl.h>`, `#include <pty.h>`:  These headers indicate dependencies on error handling, file operations, and pseudo-terminals, respectively.
* `#include <gtest/gtest.h>`: This signals that the file uses Google Test for unit testing.
* `TEST(termios, ...)`:  This confirms that the file defines several test cases within a "termios" test suite.
* Function names like `cfgetispeed`, `cfsetispeed`, `cfgetospeed`, `cfsetospeed`, `cfsetspeed`, `cfmakeraw`, `tcgetwinsize`, `tcsetwinsize`: These are the core functions being tested.
* Constants like `B1200`, `EINVAL`, `EBADF`, `IGNBRK`, `BRKINT`, etc.: These are flags and error codes related to terminal settings.

**3. Analyzing Each Test Case:**

The next step is to examine each `TEST` block individually to understand what it's testing.

* **`cfgetispeed_cfsetispeed`:**  This test verifies that `cfsetispeed` correctly sets the input baud rate and `cfgetispeed` retrieves it. It uses the standard baud rate constant `B1200`.
* **`cfsetispeed_EINVAL`:** This checks the error handling of `cfsetispeed` when an invalid baud rate (1200, which is an integer, not a `speed_t` enum value) is provided. It expects the function to return -1 and set `errno` to `EINVAL`.
* **`cfgetospeed_cfsetospeed`:**  Similar to the input speed test, this verifies setting and getting the *output* baud rate.
* **`cfsetospeed_EINVAL`:**  Similar to the input speed error test, this checks error handling for invalid output baud rate.
* **`cfsetspeed`:** This tests the `cfsetspeed` function, which sets both input and output baud rates simultaneously.
* **`cfsetspeed_EINVAL`:** This checks error handling for `cfsetspeed` with an invalid baud rate. The comment about glibc compatibility is an interesting detail.
* **`cfmakeraw`:** This is a crucial test. It verifies that `cfmakeraw` correctly sets the terminal to "raw" mode by clearing various flags related to input processing, output processing, local modes, and control modes.
* **`tcgetwinsize_tcsetwinsize_invalid`:** This test specifically checks the error handling of `tcgetwinsize` and `tcsetwinsize` when called with an invalid file descriptor (-1). It expects `EBADF` (Bad file descriptor). The `#if !defined(__GLIBC__)` is important because it highlights a platform-specific behavior. Older glibc versions might not have these specific error checks.
* **`tcgetwinsize_tcsetwinsize`:** This is a more complex test. It uses `openpty` to create a pseudo-terminal pair, then sets and retrieves the window size using `tcsetwinsize` and `tcgetwinsize`. This demonstrates the interaction of these functions with a real terminal device.

**4. Connecting to Android Functionality:**

At this point, it's crucial to consider how these `termios` functions are used in Android.

* **Terminal Emulators:** The most obvious connection is to terminal emulator apps (like Termux or the built-in Android shell). These apps heavily rely on `termios` to configure the terminal interface for the user.
* **ADB Shell:** When you connect to an Android device via `adb shell`, you're interacting with a terminal. The `adb` daemon on the device uses `termios` to manage the shell session.
* **System Services:** Some system services might interact with serial ports or other terminal-like devices, potentially using `termios`.
* **NDK Development:**  NDK developers working with serial communication or terminal interfaces will directly use these `termios` functions.

**5. Explaining libc Function Implementations:**

This requires a deeper understanding of the underlying operating system. For each tested function:

* **`cfgetispeed`, `cfsetispeed`, `cfgetospeed`, `cfsetospeed`, `cfsetspeed`:** These functions manipulate bits within the `c_cflag` member of the `termios` struct. The specific bit patterns correspond to different baud rates. The implementation involves bitwise operations and potentially lookup tables to translate baud rate constants to bit patterns. Error checking involves validating the provided baud rate against the supported values.
* **`cfmakeraw`:**  This function is a convenience function that sets specific bits in the `termios` structure to disable various terminal processing features. The implementation directly manipulates the `c_iflag`, `c_oflag`, `c_lflag`, and `c_cflag` members.
* **`tcgetwinsize`, `tcsetwinsize`:** These functions typically make system calls (like `ioctl`) to interact with the terminal driver. The driver maintains the window size information. `tcgetwinsize` retrieves this information, and `tcsetwinsize` updates it. Error checking involves validating the file descriptor and potentially permissions.

**6. Dynamic Linker Involvement:**

The `termios_test.cpp` itself doesn't directly use dynamic linker features. However, the *libc* implementation that provides the `termios` functions *does* involve the dynamic linker.

* **libc.so:** The `termios` functions are part of the standard C library (`libc.so`).
* **Linking:** When an application (or a test program) uses `termios.h`, the linker resolves the calls to the `termios` functions to their implementations within `libc.so`.
* **SO Layout:**  `libc.so` will contain the compiled code for functions like `cfgetispeed`, `cfsetattr`, etc. It will also have symbol tables that the dynamic linker uses for resolving function calls.

**7. Error Handling and Common Mistakes:**

The test file itself provides examples of error handling (checking for `-1` return and `errno`). Common user errors include:

* **Incorrect Baud Rate Values:**  Using integer values instead of the `Bxxxx` constants.
* **Invalid File Descriptors:**  Passing closed or invalid file descriptors to functions like `tcsetattr`.
* **Incorrect Struct Initialization:**  Not properly initializing the `termios` struct before calling functions.

**8. Android Framework and NDK Path:**

* **NDK:** An NDK developer would directly include `<termios.h>` and call the functions. The NDK toolchain links against `libc.so`.
* **Framework:**  Framework components (written in Java) that need terminal-like functionality might use JNI to call native code that uses `termios`. For example, the `system/core/toolbox/getty` process (which manages login sessions) would use these functions. The path would involve Java code calling native methods, which in turn call the `termios` functions in `libc.so`.

**9. Frida Hooking:**

Frida can be used to intercept calls to these functions. Examples demonstrate how to hook `cfsetispeed`, `tcsetattr`, etc., logging arguments and return values.

**10. Structuring the Response:**

Finally, the information needs to be organized clearly, addressing each part of the prompt:

* Functionality overview.
* Relationship to Android.
* Detailed explanation of libc functions.
* Dynamic linker aspects.
* Logical reasoning with examples.
* Common errors.
* Android framework/NDK path.
* Frida examples.

This structured approach ensures that all aspects of the prompt are addressed comprehensively and in a logical order. The iterative process of scanning, analyzing, connecting, and explaining, combined with attention to specific details like error codes and platform differences, leads to a thorough understanding of the provided code and its context.
好的，让我们详细分析一下 `bionic/tests/termios_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/termios_test.cpp` 是 Android Bionic 库中用于测试 `termios.h` 头文件中声明的终端 I/O 控制相关函数的单元测试文件。它使用 Google Test 框架来验证这些函数的行为是否符合预期。

具体来说，这个文件包含了对以下 `termios` 函数的测试：

* **`cfgetispeed` / `cfsetispeed`**: 获取和设置输入波特率。
* **`cfgetospeed` / `cfsetospeed`**: 获取和设置输出波特率。
* **`cfsetspeed`**: 同时设置输入和输出波特率。
* **`cfmakeraw`**: 将终端设置为原始模式。
* **`tcgetwinsize` / `tcsetwinsize`**: 获取和设置终端窗口大小。

**与 Android 功能的关系及举例说明**

`termios` 接口是 POSIX 标准的一部分，用于控制终端设备的属性，例如波特率、奇偶校验、字符大小、回显等等。在 Android 中，这个接口被广泛用于以下场景：

1. **终端模拟器 (Terminal Emulator)：** 像 Termux 这样的终端模拟器应用会使用 `termios` 函数来配置其伪终端 (pseudo-terminal, pty) 的行为，以便用户能够像在传统的命令行界面中一样进行交互。例如，设置波特率、启用/禁用回显、控制输入/输出处理等。

   * **例子：** 当你启动 Termux 并输入命令时，Termux 内部会使用 `termios` 函数来设置 pty 的属性，例如禁用行缓冲 (`ICANON` 标志)，这样你输入的每个字符都会立即被发送到 shell 进程，而不是等待按下回车键。

2. **ADB Shell：** 当你通过 `adb shell` 连接到 Android 设备时，实际上是在设备上创建了一个新的伪终端会话。`adb` 服务会使用 `termios` 函数来配置这个伪终端，以便你的本地终端能够与设备上的 shell 进程进行通信。

   * **例子：**  `adb shell` 连接时，可能会设置一些默认的终端属性，例如字符编码 (UTF-8) 等。

3. **系统服务和守护进程：** 一些系统服务或守护进程可能需要与串口或其他类型的终端设备进行通信。它们会使用 `termios` 函数来配置这些设备的通信参数。

   * **例子：**  如果一个 Android 设备连接了一个外部串口设备，负责处理串口通信的系统服务可能会使用 `termios` 函数来设置串口的波特率、数据位、停止位和校验位。

4. **NDK 开发：** 使用 NDK 进行原生开发的开发者可以直接调用 `termios` 函数来控制终端设备，例如在开发一个串口通信的应用程序时。

**libc 函数的功能实现详解**

以下是 `termios_test.cpp` 中测试的 libc 函数的功能实现的大致解释：

* **`cfgetispeed(const struct termios *termios_p)` 和 `cfgetospeed(const struct termios *termios_p)`:**
    * **功能:** 这两个函数分别用于从 `termios` 结构体中提取输入和输出波特率。
    * **实现:**  `termios` 结构体中包含一个成员 `c_cflag` (control flags)，其中包含了波特率信息。不同的波特率值对应 `c_cflag` 中的特定位模式。这两个函数通过位运算（通常是位掩码和移位操作）从 `c_cflag` 中提取相应的波特率值。这些波特率值通常定义为 `Bxxxx` 形式的宏，例如 `B9600`, `B115200` 等。

* **`cfsetispeed(struct termios *termios_p, speed_t speed)` 和 `cfsetospeed(struct termios *termios_p, speed_t speed)`:**
    * **功能:** 这两个函数分别用于设置 `termios` 结构体中的输入和输出波特率。
    * **实现:** 它们接收一个 `speed_t` 类型的波特率值作为参数。内部实现会根据传入的波特率值，修改 `termios_p->c_cflag` 中相应的位。这通常涉及到清除与波特率相关的旧位，然后根据新的波特率值设置新的位。会进行错误检查，例如传入的 `speed` 值是否是有效的波特率。

* **`cfsetspeed(struct termios *termios_p, speed_t speed)`:**
    * **功能:**  同时设置 `termios` 结构体中的输入和输出波特率。
    * **实现:**  其内部实现通常会分别调用 `cfsetispeed` 和 `cfsetospeed` 来完成操作。

* **`cfmakeraw(struct termios *termios_p)`:**
    * **功能:**  将 `termios` 结构体设置为 "raw" 模式。在 raw 模式下，终端的大部分处理功能都会被禁用，例如行缓冲、回显、信号处理等。这使得程序可以完全控制终端的输入和输出。
    * **实现:**  这个函数会修改 `termios_p` 的多个标志位：
        * 清除 `c_iflag` 中的 `IGNBRK`、`BRKINT`、`PARMRK`、`ISTRIP`、`INLCR`、`IGNCR`、`ICRNL`、`IXON` 等标志，禁用输入处理。
        * 清除 `c_oflag` 中的 `OPOST` 标志，禁用输出处理。
        * 清除 `c_lflag` 中的 `ECHO`、`ECHONL`、`ICANON`、`ISIG`、`IEXTEN` 等标志，禁用本地模式处理。
        * 清除 `c_cflag` 中的 `PARENB` 标志，禁用奇偶校验。
        * 设置字符大小为 8 位 (`CS8`)。
        * 设置最小读取字符数为 1 (`VMIN = 1`)。
        * 设置读取超时时间为 0 (`VTIME = 0`)。

* **`tcgetwinsize(int fd, struct winsize *winsize_p)`:**
    * **功能:** 获取与文件描述符 `fd` 关联的终端窗口大小。
    * **实现:**  这个函数通常会使用 `ioctl` 系统调用，并传递 `TIOCGWINSZ` 命令。操作系统内核会返回与该终端关联的窗口大小信息，包括行数、列数以及像素宽度和高度，并将结果存储在 `winsize_p` 指向的结构体中。

* **`tcsetwinsize(int fd, const struct winsize *winsize_p)`:**
    * **功能:** 设置与文件描述符 `fd` 关联的终端窗口大小。
    * **实现:** 这个函数也会使用 `ioctl` 系统调用，并传递 `TIOCSWINSZ` 命令。操作系统内核会根据 `winsize_p` 指向的结构体中的信息，更新与该终端关联的窗口大小。

**涉及 dynamic linker 的功能**

在这个测试文件中，并没有直接测试 dynamic linker 的功能。然而，`termios` 相关的函数是 libc 库的一部分，而 libc 是一个动态链接库 (`libc.so`)。当一个程序（包括这个测试程序）调用 `termios` 函数时，dynamic linker 负责在程序运行时将这些函数调用链接到 `libc.so` 中对应的实现代码。

**so 布局样本和链接的处理过程**

假设有以下简化的 `libc.so` 布局：

```
libc.so:
    .text:
        cfgetispeed:  <cfgetispeed 的机器码>
        cfsetispeed:  <cfsetispeed 的机器码>
        cfmakeraw:    <cfmakeraw 的机器码>
        ...
    .dynsym:
        cfgetispeed  (地址指向 .text 中的 cfgetispeed)
        cfsetispeed  (地址指向 .text 中的 cfsetispeed)
        cfmakeraw    (地址指向 .text 中的 cfmakeraw)
        ...
    .dynstr:
        cfgetispeed\0
        cfsetispeed\0
        cfmakeraw\0
        ...
```

**链接处理过程：**

1. **编译时链接:** 当 `termios_test.cpp` 被编译时，编译器会识别出对 `cfgetispeed` 等函数的调用，并在生成的目标文件中记录下这些符号的引用。由于这些函数在 libc 中，链接器 (linker) 并不会尝试在当前目标文件中寻找它们的实现，而是标记为需要动态链接。

2. **运行时链接:** 当 `termios_test` 可执行文件被加载到内存中准备运行时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会介入：
   * 它会读取 `termios_test` 可执行文件的头部信息，找到其依赖的动态链接库列表，其中包括 `libc.so`。
   * dynamic linker 会将 `libc.so` 加载到内存中的某个地址空间。
   * 它会遍历 `termios_test` 中未解析的符号引用（例如 `cfgetispeed`）。
   * 对于每个未解析的符号，dynamic linker 会在 `libc.so` 的 `.dynsym` (动态符号表) 中查找对应的符号。
   * 如果找到匹配的符号，dynamic linker 会获取该符号在 `libc.so` 中的地址（从 `.dynsym` 中读取）。
   * dynamic linker 会更新 `termios_test` 中对该符号的引用，将其指向 `libc.so` 中对应函数的实际内存地址。这个过程通常涉及到修改全局偏移表 (GOT) 或过程链接表 (PLT)。

**假设输入与输出 (逻辑推理)**

我们以 `cfsetispeed` 和 `cfgetispeed` 的测试为例：

**假设输入：**

* 调用 `cfsetispeed(&t, B1200)`，其中 `t` 是一个 `termios` 结构体。

**逻辑推理：**

* `cfsetispeed` 函数会将 `termios` 结构体 `t` 的 `c_cflag` 成员中与输入波特率相关的位设置为 `B1200` 对应的位模式。

**预期输出：**

* `cfsetispeed` 函数返回 0 (表示成功)。
* 随后调用 `cfgetispeed(&t)` 应该返回 `B1200`。

**假设输入 (错误情况)：**

* 调用 `cfsetispeed(&t, 1200)`，这里传入的是一个整数 `1200`，而不是 `speed_t` 枚举值 `B1200`。

**逻辑推理：**

* `cfsetispeed` 函数会检查传入的波特率值是否有效。由于 `1200` 不是一个预定义的 `speed_t` 值，它应该被认为是无效的。

**预期输出：**

* `cfsetispeed` 函数返回 -1 (表示错误)。
* `errno` 全局变量被设置为 `EINVAL` (表示参数无效)。

**用户或编程常见的使用错误举例说明**

1. **使用错误的波特率值：** 用户可能会直接使用数字而不是 `Bxxxx` 宏来设置波特率。
   ```c++
   termios t;
   // 错误：应该使用 B9600
   if (cfsetispeed(&t, 9600) == -1) {
       perror("cfsetispeed");
   }
   ```
   **后果：**  `cfsetispeed` 或 `cfsetospeed` 会返回错误，`errno` 会设置为 `EINVAL`。

2. **忘记检查返回值和 `errno`：**  在调用 `termios` 相关函数后，没有检查返回值是否为 -1，也没有检查 `errno` 的值来判断错误原因。
   ```c++
   termios t;
   cfsetattr(fd, TCSANOW, &t); // 如果设置失败，你不会知道
   ```
   **后果：**  程序可能在终端属性未正确设置的情况下继续运行，导致不可预测的行为。

3. **在错误的文件描述符上调用函数：** 尝试在一个未打开或无效的文件描述符上调用 `termios` 函数。
   ```c++
   int fd = -1; // 无效的文件描述符
   termios t;
   if (tcgetattr(fd, &t) == -1) {
       perror("tcgetattr"); // 应该会输出 "Bad file descriptor"
   }
   ```
   **后果：**  相关的 `termios` 函数会返回错误，`errno` 会设置为 `EBADF` (Bad file descriptor)。

4. **未初始化 `termios` 结构体：**  在使用 `termios` 结构体之前，没有正确地初始化它。
   ```c++
   termios t; // t 的内容是未定义的
   cfmakeraw(&t); // 可能导致未定义的行为
   ```
   **后果：**  `cfmakeraw` 等函数可能会基于未初始化的数据进行操作，导致不可预测的结果。正确的做法是先使用 `tcgetattr` 获取当前终端的属性，或者手动将结构体清零。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 开发：**
   * 开发者在 C/C++ 代码中 `#include <termios.h>`。
   * 调用 `cfsetispeed`、`tcgetattr` 等 `termios` 相关的函数。
   * NDK 编译工具链会将这些函数调用链接到 Android 系统提供的 `libc.so`。
   * 当应用在 Android 设备上运行时，dynamic linker 会加载 `libc.so` 并解析这些函数调用。

2. **Android Framework：**
   * Android Framework 的某些组件（通常是用 Java 编写）可能需要与终端或串口进行交互。
   * 这些组件可能会使用 JNI (Java Native Interface) 调用底层的 C/C++ 代码。
   * 这些 C/C++ 代码会调用 `termios` 函数。例如，`system/core/toolbox/getty` 这个进程负责处理终端登录，它会使用 `termios` 函数来配置终端属性。
   * **路径示例：**
      * Java 代码 (Framework) -> JNI 调用 -> Native C/C++ 代码 (例如，某个系统服务或库) -> `cfsetattr` 等 `termios` 函数 -> `libc.so` 中的实现。

**Frida Hook 示例调试步骤**

假设我们想 hook `cfsetispeed` 函数，查看其被调用时的参数：

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, "libc.so");
  if (libc) {
    const cfsetispeed = Module.findExportByName(libc.name, "cfsetispeed");
    if (cfsetispeed) {
      Interceptor.attach(cfsetispeed, {
        onEnter: function (args) {
          const termios_ptr = ptr(args[0]);
          const speed = args[1].toInt();
          console.log(`[cfsetispeed] termios*: ${termios_ptr}, speed: ${speed}`);
          // 你可以进一步读取 termios 结构体的内容，如果需要
        },
        onLeave: function (retval) {
          console.log(`[cfsetispeed] 返回值: ${retval}`);
        }
      });
      console.log("成功 Hook cfsetispeed");
    } else {
      console.log("未找到 cfsetispeed");
    }
  } else {
    console.log("未找到 libc.so");
  }
} else {
  console.log("当前平台不是 Android");
}
```

**调试步骤：**

1. **准备环境：** 确保你的 Android 设备已 root，并且安装了 Frida 和 frida-server。
2. **找到目标进程：** 确定你想要 hook 的进程。例如，如果你想 hook Termux，你需要找到 Termux 的进程 ID。
3. **运行 Frida 命令：** 使用 Frida 连接到目标进程并加载你的 hook 脚本。
   ```bash
   frida -U -f <目标进程包名或进程名> -l your_hook_script.js --no-pause
   # 或者，如果进程已经在运行：
   frida -U <目标进程包名或进程名> -l your_hook_script.js
   ```
4. **触发目标代码：**  在目标应用中执行会调用 `cfsetispeed` 的操作。例如，在 Termux 中，你可能会改变终端的设置。
5. **查看 Frida 输出：** Frida 会拦截对 `cfsetispeed` 的调用，并在控制台上打印出你设置的日志信息，包括 `termios` 结构体的指针和设置的波特率值。

**其他可以 hook 的 `termios` 函数示例：**

* **Hook `tcsetattr`：** 可以查看设置的完整的 `termios` 结构体内容。
* **Hook `openpty`：** 可以查看伪终端的创建过程。
* **Hook `ioctl`：** 可以查看更底层的终端控制命令。

通过 Frida Hook，你可以动态地观察和分析 `termios` 相关函数在 Android 系统中的行为，这对于调试和理解终端控制机制非常有帮助。

希望以上详细的解答能够帮助你理解 `bionic/tests/termios_test.cpp` 文件及其在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/termios_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2017 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <termios.h>

#include <errno.h>
#include <fcntl.h>
#include <pty.h>

#include <gtest/gtest.h>

#include "utils.h"

// TODO:
// tcdrain
// tcflow
// tcflush
// tcgetattr
// tcgetsid
// tcsendbreak
// tcsetattr

TEST(termios, cfgetispeed_cfsetispeed) {
  termios t = {};
  ASSERT_EQ(0, cfsetispeed(&t, B1200));
  ASSERT_EQ(static_cast<speed_t>(B1200), cfgetispeed(&t));
}

TEST(termios, cfsetispeed_EINVAL) {
  termios t = {};
  errno = 0;
  ASSERT_EQ(-1, cfsetispeed(&t, 1200));
  ASSERT_ERRNO(EINVAL);
}

TEST(termios, cfgetospeed_cfsetospeed) {
  termios t = {};
  ASSERT_EQ(0, cfsetospeed(&t, B1200));
  ASSERT_EQ(static_cast<speed_t>(B1200), cfgetospeed(&t));
}

TEST(termios, cfsetospeed_EINVAL) {
  termios t = {};
  errno = 0;
  ASSERT_EQ(-1, cfsetospeed(&t, 1200));
  ASSERT_ERRNO(EINVAL);
}

TEST(termios, cfsetspeed) {
  termios t = {};
  ASSERT_EQ(0, cfsetspeed(&t, B1200));
  ASSERT_EQ(static_cast<speed_t>(B1200), cfgetispeed(&t));
  ASSERT_EQ(static_cast<speed_t>(B1200), cfgetospeed(&t));
}

TEST(termios, cfsetspeed_EINVAL) {
  termios t = {};
  errno = 0;
  // glibc seems to allow 1200 as well as B1200 here, presumably for
  // BSD compatibility (where Bxxx == xxx, unlike Linux).
  ASSERT_EQ(-1, cfsetspeed(&t, 123));
  ASSERT_ERRNO(EINVAL);
}

TEST(termios, cfmakeraw) {
  termios t;
  memset(&t, 0xff, sizeof(t));
  cfmakeraw(&t);

  EXPECT_EQ(0U, (t.c_iflag & (IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON)));
  EXPECT_EQ(0U, (t.c_oflag & OPOST));
  EXPECT_EQ(0U, (t.c_lflag & (ECHO|ECHONL|ICANON|ISIG|IEXTEN)));
  EXPECT_EQ(0U, (t.c_cflag & PARENB));
  EXPECT_EQ(static_cast<unsigned>(CS8), (t.c_cflag & CSIZE));
  EXPECT_EQ(1, t.c_cc[VMIN]);
  EXPECT_EQ(0, t.c_cc[VTIME]);
}

TEST(termios, tcgetwinsize_tcsetwinsize_invalid) {
#if !defined(__GLIBC__)
  winsize ws = {};

  errno = 0;
  ASSERT_EQ(-1, tcgetwinsize(-1, &ws));
  ASSERT_ERRNO(EBADF);

  errno = 0;
  ASSERT_EQ(-1, tcsetwinsize(-1, &ws));
  ASSERT_ERRNO(EBADF);
#else
  GTEST_SKIP() << "glibc too old";
#endif
}

TEST(termios, tcgetwinsize_tcsetwinsize) {
#if !defined(__GLIBC__)
  int pty, tty;
  winsize ws = {123, 456, 9999, 9999};
  ASSERT_EQ(0, openpty(&pty, &tty, nullptr, nullptr, &ws));

  winsize actual = {};
  ASSERT_EQ(0, tcgetwinsize(tty, &actual));
  EXPECT_EQ(ws.ws_xpixel, actual.ws_xpixel);
  EXPECT_EQ(ws.ws_ypixel, actual.ws_ypixel);
  EXPECT_EQ(ws.ws_row, actual.ws_row);
  EXPECT_EQ(ws.ws_col, actual.ws_col);

  ws = {1, 2, 3, 4};
  ASSERT_EQ(0, tcsetwinsize(tty, &ws));

  actual = {};
  ASSERT_EQ(0, tcgetwinsize(tty, &actual));
  EXPECT_EQ(ws.ws_xpixel, actual.ws_xpixel);
  EXPECT_EQ(ws.ws_ypixel, actual.ws_ypixel);
  EXPECT_EQ(ws.ws_row, actual.ws_row);
  EXPECT_EQ(ws.ws_col, actual.ws_col);

  close(pty);
  close(tty);
#else
  GTEST_SKIP() << "glibc too old";
#endif
}
```