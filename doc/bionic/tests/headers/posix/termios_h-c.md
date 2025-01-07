Response:
Let's break down the thought process for analyzing this `termios_h.c` file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of this C file, which is a header check for `termios.h` in Android's Bionic library. The key is to understand what this file *does* and its implications. The decomposed requests are:

* **Functionality:** What does this specific C file achieve?
* **Android Relevance:** How does `termios.h` relate to broader Android functionality?
* **Libc Function Implementation:** How are the `termios` functions implemented? (This is tricky since this file *checks* the header, not *implements* the functions.)
* **Dynamic Linker:** Are there dynamic linking aspects? (Again, this is primarily a header check, so the direct impact is limited.)
* **Logic & I/O:** Any logical flow or input/output within *this specific file*?
* **Common Errors:** How might a programmer misuse `termios`?
* **Android Integration:** How does the framework or NDK lead to using these definitions?
* **Frida Hooking:** How can we observe the usage of `termios` at runtime?

**2. Initial Observation & Key Insight:**

The first and most crucial realization is that this `.c` file isn't implementing `termios.h`; it's **testing** the presence and correctness of the declarations within the `termios.h` header file. The functions like `TYPE()`, `STRUCT_MEMBER()`, `MACRO()`, and `FUNCTION()` are not standard C library functions. They are likely part of a build system or testing framework within Bionic.

**3. Deconstructing the Code:**

Now, let's go through the code section by section:

* **Copyright & License:** Standard boilerplate, indicating the origin and usage terms.
* **`#include <termios.h>`:** This confirms the file's purpose: to examine the `termios.h` header.
* **`#include "header_checks.h"`:** This is the giveaway. This include suggests the existence of a custom header checking mechanism. The functions used later are likely defined in `header_checks.h`.
* **`static void termios_h() { ... }`:** This is the main function of the test. It's named after the header being tested.
* **`TYPE(cc_t);`, `TYPE(speed_t);`, `TYPE(tcflag_t);`:** The `TYPE()` macro likely checks if these type definitions exist.
* **`TYPE(struct termios);`:** Checks for the existence of the `termios` structure.
* **`STRUCT_MEMBER(struct termios, ...);`:**  This macro verifies the presence and type of specific members within the `termios` structure.
* **`MACRO(NCCS);`, `MACRO(VEOF);`, ...:**  The `MACRO()` macro checks if these symbolic constants (macros) are defined. These constants represent control characters and flags for terminal settings.
* **`FUNCTION(cfgetispeed, speed_t (*f)(const struct termios*));`, ...:** The `FUNCTION()` macro checks for the existence and signature (return type and arguments) of the listed `termios` functions.
* **`#if !defined(__GLIBC__)` blocks:** This indicates that certain definitions (`struct winsize`, `tcgetwinsize`, `tcsetwinsize`) might not be present in older versions of glibc, and Bionic handles this.

**4. Answering the Specific Questions (Iterative Refinement):**

Now, let's map the understanding back to the original questions:

* **Functionality:** The file's primary function is **header checking**. It ensures the necessary types, structure members, macros, and function declarations related to terminal I/O are present in `termios.h`.
* **Android Relevance:** `termios.h` is crucial for terminal management, which is essential for Android's shell access (adb shell), terminal emulators, and potentially other system-level interactions involving character devices.
* **Libc Function Implementation:**  This file doesn't implement the functions. It only checks their declaration. The *actual implementation* resides in other Bionic source files. It's important to clarify this distinction.
* **Dynamic Linker:**  While `termios.h` doesn't directly involve the dynamic linker, the functions *declared* here (like `tcgetattr`, `tcsetattr`, etc.) are part of libc.so and are dynamically linked. The SO layout would be the standard libc.so layout, and linking would be the standard dynamic linking process.
* **Logic & I/O:** This file is primarily declarative/checking. There's minimal logical flow within `termios_h()`. The "output" is implicit – the success or failure of the header check during the build process.
* **Common Errors:**  Programmers might misuse `termios` by incorrect flag settings, forgetting to restore terminal settings, or using blocking calls incorrectly, leading to hangs.
* **Android Integration:**  The path from the framework/NDK involves system calls that eventually interact with the terminal driver, and `termios` provides the interface to configure this interaction.
* **Frida Hooking:** We can use Frida to intercept calls to the `termios` functions to inspect their arguments and return values.

**5. Structuring the Response:**

Organize the findings logically, addressing each point in the prompt. Use clear headings and bullet points for readability. Emphasize the key takeaway: this is a *header check* file.

**6. Adding Detail and Examples:**

Provide specific examples for Android usage, common errors, and the Frida hooking. For the dynamic linker, describe the general process and the role of libc.so.

**7. Review and Refine:**

Read through the response to ensure accuracy and clarity. Correct any misunderstandings or ambiguities. For example, initially, one might be tempted to explain the implementation of the `termios` functions, but a closer look reveals that this file only checks their declarations.

This detailed thought process helps to understand the nuances of the provided code snippet and address all aspects of the prompt accurately. The key is to recognize the purpose of the file and then connect it to the broader context of Android and the C library.
这个文件 `bionic/tests/headers/posix/termios_h.c` 的主要功能是**测试 `termios.h` 头文件的正确性**。它并不实现任何与终端控制相关的具体功能，而是验证 `termios.h` 中定义的类型、结构体成员和宏定义是否符合预期。这属于 Android Bionic C 库的**单元测试**的一部分。

更具体地说，这个文件会：

1. **检查类型定义:** 确认 `cc_t`, `speed_t`, `tcflag_t` 等类型是否已定义。
2. **检查结构体定义:** 确认 `struct termios` 和 (在非 GLIBC 环境下) `struct winsize` 结构体是否存在，并且包含预期的成员变量，例如 `c_iflag`, `c_oflag`, `c_cflag`, `c_lflag`, `c_cc`, `ws_row`, `ws_col` 等。
3. **检查宏定义:** 验证各种与终端控制相关的宏定义是否存在，例如：
    * **控制字符索引:** `NCCS`, `VEOF`, `VEOL`, 等。
    * **输入标志:** `BRKINT`, `ICRNL`, `IGNBRK`, 等。
    * **输出标志:** `OPOST`, `ONLCR`, `OCRNL`, 等。
    * **控制标志:** `B0`, `B50`, `CSIZE`, `CS5`, 等。
    * **本地标志:** `ECHO`, `ECHOE`, `ICANON`, 等。
    * **TCSANOW, TCSADRAIN, TCSAFLUSH:** 用于 `tcsetattr` 函数的标志。
    * **TCIFLUSH, TCIOFLUSH, TCOFLUSH:** 用于 `tcflush` 函数的标志。
    * **TCIOFF, TCION, TCOOFF, TCOON:** 用于 `tcflow` 函数的标志。
4. **检查函数声明:** 确认与 `termios` 相关的函数是否已声明，并具有预期的函数签名（参数和返回类型），例如 `cfgetispeed`, `cfsetispeed`, `tcgetattr`, `tcsetattr` 等。

**与 Android 功能的关系及举例说明：**

`termios.h` 定义了 POSIX 标准中用于控制终端接口的函数和数据结构。在 Android 中，这些功能对于以下方面至关重要：

* **终端模拟器应用:**  像 Termux 这样的应用需要使用 `termios` 函数来配置终端的行为，例如设置波特率、字符大小、校验位、回显、行缓冲等。
* **ADB Shell:** 当你通过 `adb shell` 连接到 Android 设备时，shell 的行为（例如回显你输入的命令，处理 Ctrl+C 等中断信号）是由 `termios` 设置控制的。
* **守护进程和后台服务:** 某些需要与字符设备（例如串口）交互的后台服务也可能使用 `termios` 来配置通信参数。

**举例说明:**

假设一个终端模拟器应用需要禁用本地回显，以便用户输入的字符不会在终端上显示两次。它会使用 `tcgetattr` 获取当前的终端属性，修改 `c_lflag` 中的 `ECHO` 位，然后使用 `tcsetattr` 应用新的设置。

```c
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main() {
  struct termios term;
  int fd = STDIN_FILENO; // 标准输入文件描述符

  // 获取当前的终端属性
  if (tcgetattr(fd, &term) == -1) {
    perror("tcgetattr");
    return 1;
  }

  // 禁用回显
  term.c_lflag &= ~ECHO;

  // 应用新的终端属性，TCSANOW 表示立即生效
  if (tcsetattr(fd, TCSANOW, &term) == -1) {
    perror("tcsetattr");
    return 1;
  }

  printf("回显已禁用，请输入内容：\n");
  char buffer[256];
  fgets(buffer, sizeof(buffer), stdin); // 读取用户输入

  printf("你输入的是： %s\n", buffer);

  // 恢复原始终端属性 (通常在程序退出时做)
  if (tcgetattr(fd, &term) == -1) {
    perror("tcgetattr");
    return 1;
  }
  term.c_lflag |= ECHO;
  if (tcsetattr(fd, TCSANOW, &term) == -1) {
    perror("tcsetattr");
    return 1;
  }

  return 0;
}
```

**详细解释每一个 libc 函数的功能是如何实现的：**

这个 `termios_h.c` 文件本身并不实现这些 libc 函数。它只是一个测试文件，用来验证这些函数是否在 `termios.h` 中正确声明。

`termios` 函数的实际实现位于 Android Bionic C 库的其他源文件中。 这些函数的具体实现会涉及到与操作系统内核的交互，通过系统调用来操作底层的终端驱动程序。

例如：

* **`tcgetattr(int fd, struct termios *termios_p)`:**  这个函数会调用底层的系统调用（在 Linux 内核中可能是 `ioctl`，并带上 `TCGETS` 命令）来获取与文件描述符 `fd` 关联的终端的当前属性，并将这些属性填充到 `termios_p` 指向的结构体中。
* **`tcsetattr(int fd, int optional_actions, const struct termios *termios_p)`:**  这个函数会调用底层的系统调用（可能是 `ioctl`，并带上 `TCSETS`, `TCSETAW`, 或 `TCSETAF` 命令，具体取决于 `optional_actions` 参数）来设置与文件描述符 `fd` 关联的终端的属性。
* **`cfgetispeed(const struct termios *termios_p)`:** 这是一个辅助函数，用于从 `termios` 结构体的 `c_cflag` 成员中提取输入波特率。它通常通过位运算和预定义的掩码来实现。
* **`cfsetospeed(struct termios *termios_p, speed_t speed)`:** 这是一个辅助函数，用于设置 `termios` 结构体的 `c_cflag` 成员中的输出波特率。它也通常通过位运算和预定义的掩码来实现。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`termios.h` 中声明的函数（例如 `tcgetattr`, `tcsetattr` 等）是 Android Bionic C 库 (`libc.so`) 的一部分。当一个应用程序调用这些函数时，会涉及到动态链接的过程。

**SO 布局样本 (libc.so 的简化示意):**

```
libc.so:
    .text:  // 包含可执行代码
        ...
        _ZN6__gnu_cxx17__verbose_terminate_handlerEv: // 示例函数
        __sFls: // 示例函数
        tcgetattr: // tcgetattr 函数的实现代码
        tcsetattr: // tcsetattr 函数的实现代码
        cfgetispeed: // cfgetispeed 函数的实现代码
        ...
    .rodata: // 只读数据，例如字符串常量
        ...
    .data:   // 可读写数据，例如全局变量
        ...
    .bss:    // 未初始化数据
        ...
    .dynsym: // 动态符号表，包含导出的符号（函数和变量）
        tcgetattr
        tcsetattr
        cfgetispeed
        ...
    .dynstr: // 动态字符串表，包含符号名称
        "tcgetattr"
        "tcsetattr"
        "cfgetispeed"
        ...
    .rel.dyn: // 重定位表，用于在加载时修改代码或数据中的地址
        ...
```

**链接的处理过程：**

1. **编译时:** 当你编译一个使用 `termios.h` 中函数的程序时，编译器会识别到这些函数调用，但由于这些函数的实现不在你的源代码中，编译器会生成对这些函数的**未定义引用**。
2. **链接时:** 链接器（通常是 `ld`）会将你的目标文件与所需的共享库 (`libc.so`) 链接在一起。链接器会查看 `libc.so` 的动态符号表 (`.dynsym`)，找到与你的程序中未定义引用相匹配的符号（例如 `tcgetattr`）。
3. **运行时:**
    * **加载:** 当你的 Android 应用启动时，系统会使用动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 将程序加载到内存中。
    * **重定位:** 动态链接器会根据共享库的加载地址，修改程序中对共享库函数的引用，使其指向 `libc.so` 中对应函数的实际地址。这个过程就是**重定位**。
    * **符号查找:** 当程序执行到调用 `tcgetattr` 的地方时，由于在链接时已经建立了符号引用，程序会跳转到 `libc.so` 中 `tcgetattr` 函数的实现代码执行。

**如果做了逻辑推理，请给出假设输入与输出:**

由于 `termios_h.c` 是一个测试文件，它主要进行静态检查，没有实际的输入和输出的概念，除非考虑到编译构建过程。

**假设输入:** 编译系统读取 `termios_h.c` 文件和相关的 Bionic 库头文件。

**假设输出:**
* **编译成功:** 如果 `termios.h` 的定义符合预期，`termios_h.c` 中的测试代码会编译通过，表示头文件是正确的。
* **编译失败:** 如果 `termios.h` 中缺少某些定义、类型不匹配或宏定义的值不正确，`termios_h.c` 中的 `TYPE`, `STRUCT_MEMBER`, `MACRO`, `FUNCTION` 等宏可能会导致编译错误，从而指示头文件存在问题。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **忘记包含头文件:**  在使用 `termios` 相关函数和结构体时，必须包含 `<termios.h>` 头文件。否则，编译器会报错，因为相关的类型和函数声明不可见。
* **错误地设置终端属性:**  `struct termios` 中的各个标志位非常多，理解其含义并正确设置至关重要。例如，错误地设置波特率可能导致通信失败，错误地设置本地模式可能导致输入输出异常。
* **不恰当地使用 `tcsetattr` 的 `optional_actions` 参数:** `tcsetattr` 函数的第二个参数决定了何时应用新的终端属性。使用 `TCSANOW` 会立即生效，`TCSADRAIN` 会等待所有输出数据发送完毕后再生效，`TCSAFLUSH` 除了等待输出完成外，还会丢弃未读取的输入数据。不理解这些选项的含义可能导致程序行为异常。
* **忘记恢复终端属性:**  在修改终端属性后，特别是在需要恢复到用户默认设置的情况下，程序应该在退出前将终端属性恢复到修改前的状态。否则，可能会影响后续在同一个终端中运行的其他程序。可以使用 `tcgetattr` 保存原始设置，然后在程序退出前使用 `tcsetattr` 恢复。
* **在非终端设备上调用 `termios` 函数:** `termios` 函数主要用于控制终端设备。在非终端设备（例如普通文件）的文件描述符上调用这些函数通常会返回错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 或 NDK 到达 `termios` 的步骤：**

1. **应用程序 (Java/Kotlin 或 Native):** 应用程序可能通过以下方式间接或直接使用 `termios` 功能：
    * **终端模拟器应用:** 直接使用 NDK 调用 `termios` 函数来控制伪终端 (pty) 的行为。
    * **通过 Framework API 交互:**  某些 Framework API 可能会在底层使用与终端相关的操作，例如与串口通信。虽然 Framework 层通常会抽象这些细节，但最终可能会涉及到系统调用和 `termios` 的底层操作。
    * **NDK 开发的系统工具:**  使用 NDK 开发的命令行工具或系统服务可能会直接调用 `termios` 函数来与字符设备交互。

2. **NDK (Native Development Kit) 或 Framework (通过 JNI 调用):**
    * **NDK:**  如果应用程序是使用 NDK 开发的，可以直接 `#include <termios.h>` 并调用其中的函数。
    * **Framework:**  如果应用程序是使用 Java/Kotlin 开发的，需要通过 JNI (Java Native Interface) 调用 native 代码，而 native 代码中可能会使用 `termios` 函数。

3. **Bionic C 库 (`libc.so`):**  无论通过 NDK 直接调用还是通过 Framework/JNI 间接调用，最终都会链接到 Android 的 Bionic C 库 (`libc.so`)。`termios.h` 中声明的函数的实现在 `libc.so` 中。

4. **系统调用:**  Bionic C 库中的 `termios` 函数实现会通过系统调用与 Linux 内核进行交互。例如，`tcgetattr` 和 `tcsetattr` 通常会转换为 `ioctl` 系统调用，并带有特定的命令参数（如 `TCGETS`, `TCSETS` 等）。

5. **Linux 内核:**  内核中的终端驱动程序会处理这些系统调用，并根据 `termios` 结构体中设置的属性来管理终端的行为。

**Frida Hook 示例：**

假设你想监控一个应用对 `tcgetattr` 和 `tcsetattr` 函数的调用，可以使用 Frida 来 hook 这些函数。

```javascript
// hook_termios.js

if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, 'libc.so');
  if (libc) {
    const tcgetattrPtr = Module.findExportByName(libc.name, 'tcgetattr');
    const tcsetattrPtr = Module.findExportByName(libc.name, 'tcsetattr');

    if (tcgetattrPtr) {
      Interceptor.attach(tcgetattrPtr, {
        onEnter: function (args) {
          const fd = args[0].toInt32();
          console.log(`[tcgetattr] FD: ${fd}`);
        },
        onLeave: function (retval) {
          console.log(`[tcgetattr] Return value: ${retval}`);
          if (retval.toInt32() === 0) {
            const termiosPtr = this.context.r1; //  根据架构可能需要调整寄存器
            const termios = Memory.readByteArray(termiosPtr, Process.pointerSize * 20); // 假设 termios 结构体大小
            console.log(`[tcgetattr] termios struct: ${hexdump(termios)}`);
          }
        }
      });
    } else {
      console.log('[-] tcgetattr not found');
    }

    if (tcsetattrPtr) {
      Interceptor.attach(tcsetattrPtr, {
        onEnter: function (args) {
          const fd = args[0].toInt32();
          const optional_actions = args[1].toInt32();
          const termiosPtr = args[2];
          console.log(`[tcsetattr] FD: ${fd}, Optional Actions: ${optional_actions}`);
          const termios = Memory.readByteArray(termiosPtr, Process.pointerSize * 20); // 假设 termios 结构体大小
          console.log(`[tcsetattr] termios struct: ${hexdump(termios)}`);
        },
        onLeave: function (retval) {
          console.log(`[tcsetattr] Return value: ${retval}`);
        }
      });
    } else {
      console.log('[-] tcsetattr not found');
    }
  } else {
    console.log('[-] libc.so not found');
  }
} else {
  console.log('[-] Not running on Android');
}
```

**使用 Frida 运行 Hook:**

1. 将上述 JavaScript 代码保存为 `hook_termios.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_termios.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_termios.js
   ```
   将 `<package_name>` 替换为目标应用的包名。

**输出示例:**

当你运行被 hook 的应用并触发 `tcgetattr` 或 `tcsetattr` 调用时，Frida 控制台会输出类似以下的信息：

```
[Pixel 4::com.example.terminalapp]-> [tcgetattr] FD: 0
[Pixel 4::com.example.terminalapp]-> [tcgetattr] Return value: 0
[Pixel 4::com.example.terminalapp]-> [tcgetattr] termios struct:
           0  01 00 00 00 03 00 00 00  ff ff 00 00 ff ff 00 00  ................
          10  0f 00 06 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
[Pixel 4::com.example.terminalapp]-> [tcsetattr] FD: 0, Optional Actions: 0
[Pixel 4::com.example.terminalapp]-> [tcsetattr] termios struct:
           0  01 00 00 00 03 00 00 00  fb ff 00 00 ff ff 00 00  ................
          10  0f 00 06 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
[Pixel 4::com.example.terminalapp]-> [tcsetattr] Return value: 0
```

通过 Frida Hook，你可以动态地观察应用程序是如何使用 `termios` 函数的，包括传递的文件描述符、终端属性的设置以及函数的返回值，这对于理解和调试终端相关的行为非常有帮助。

Prompt: 
```
这是目录为bionic/tests/headers/posix/termios_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "header_checks.h"

static void termios_h() {
  TYPE(cc_t);
  TYPE(speed_t);
  TYPE(tcflag_t);

  TYPE(struct termios);
  STRUCT_MEMBER(struct termios, tcflag_t, c_iflag);
  STRUCT_MEMBER(struct termios, tcflag_t, c_oflag);
  STRUCT_MEMBER(struct termios, tcflag_t, c_cflag);
  STRUCT_MEMBER(struct termios, tcflag_t, c_lflag);
  STRUCT_MEMBER_ARRAY(struct termios, cc_t/*[]*/, c_cc);

#if !defined(__GLIBC__)  // Our glibc is too old.
  TYPE(struct winsize);
  STRUCT_MEMBER(struct winsize, unsigned short, ws_row);
  STRUCT_MEMBER(struct winsize, unsigned short, ws_col);
#endif

  MACRO(NCCS);

  MACRO(VEOF);
  MACRO(VEOL);
  MACRO(VERASE);
  MACRO(VINTR);
  MACRO(VKILL);
  MACRO(VMIN);
  MACRO(VQUIT);
  MACRO(VSTART);
  MACRO(VSTOP);
  MACRO(VSUSP);
  MACRO(VTIME);

  MACRO(BRKINT);
  MACRO(ICRNL);
  MACRO(IGNBRK);
  MACRO(IGNCR);
  MACRO(IGNPAR);
  MACRO(INLCR);
  MACRO(INPCK);
  MACRO(ISTRIP);
  MACRO(IXANY);
  MACRO(IXOFF);
  MACRO(IXON);
  MACRO(PARMRK);

  MACRO(OPOST);
  MACRO(ONLCR);
  MACRO(OCRNL);
  MACRO(ONOCR);
  MACRO(ONLRET);
  MACRO(OFDEL);
  MACRO(OFILL);
  MACRO(NLDLY);
  MACRO(NL0);
  MACRO(NL1);
  MACRO(CRDLY);
  MACRO(CR0);
  MACRO(CR1);
  MACRO(CR2);
  MACRO(CR3);
  MACRO(TABDLY);
  MACRO(TAB0);
  MACRO(TAB1);
  MACRO(TAB2);
  MACRO(TAB3);
  MACRO(BSDLY);
  MACRO(BS0);
  MACRO(BS1);
  MACRO(VTDLY);
  MACRO(VT0);
  MACRO(VT1);
  MACRO(FFDLY);
  MACRO(FF0);
  MACRO(FF1);

  MACRO(B0);
  MACRO(B50);
  MACRO(B75);
  MACRO(B110);
  MACRO(B134);
  MACRO(B150);
  MACRO(B200);
  MACRO(B300);
  MACRO(B600);
  MACRO(B1200);
  MACRO(B1800);
  MACRO(B2400);
  MACRO(B4800);
  MACRO(B9600);
  MACRO(B19200);
  MACRO(B38400);

  MACRO(CSIZE);
  MACRO(CS5);
  MACRO(CS6);
  MACRO(CS7);
  MACRO(CS8);
  MACRO(CSTOPB);
  MACRO(CREAD);
  MACRO(PARENB);
  MACRO(PARODD);
  MACRO(HUPCL);
  MACRO(CLOCAL);

  MACRO(ECHO);
  MACRO(ECHOE);
  MACRO(ECHOK);
  MACRO(ECHONL);
  MACRO(ICANON);
  MACRO(IEXTEN);
  MACRO(ISIG);
  MACRO(NOFLSH);
  MACRO(TOSTOP);

  MACRO(TCSANOW);
  MACRO(TCSADRAIN);
  MACRO(TCSAFLUSH);

  MACRO(TCIFLUSH);
  MACRO(TCIOFLUSH);
  MACRO(TCOFLUSH);

  MACRO(TCIOFF);
  MACRO(TCION);
  MACRO(TCOOFF);
  MACRO(TCOON);

  TYPE(pid_t);

  FUNCTION(cfgetispeed, speed_t (*f)(const struct termios*));
  FUNCTION(cfgetospeed, speed_t (*f)(const struct termios*));
  FUNCTION(cfsetispeed, int (*f)(struct termios*, speed_t));
  FUNCTION(cfsetospeed, int (*f)(struct termios*, speed_t));
  FUNCTION(tcdrain, int (*f)(int));
  FUNCTION(tcflow, int (*f)(int, int));
  FUNCTION(tcflush, int (*f)(int, int));
  FUNCTION(tcgetattr, int (*f)(int, struct termios*));
  FUNCTION(tcgetsid, pid_t (*f)(int));
#if !defined(__GLIBC__)  // Our glibc is too old.
  FUNCTION(tcgetwinsize, int (*f)(int, struct winsize*));
#endif
  FUNCTION(tcsendbreak, int (*f)(int, int));
  FUNCTION(tcsetattr, int (*f)(int, int, const struct termios*));
#if !defined(__GLIBC__)  // Our glibc is too old.
  FUNCTION(tcsetwinsize, int (*f)(int, const struct winsize*));
#endif
}

"""

```