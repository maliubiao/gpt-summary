Response:
Let's break down the thought process to generate the comprehensive answer about `termbits.h`.

**1. Understanding the Request:**

The request asks for a detailed analysis of the provided C header file (`termbits.h`) within the context of Android's Bionic library. Key areas to address are: functionality, relation to Android, libc function implementation details, dynamic linker involvement, logical reasoning (with examples), common usage errors, and how Android framework/NDK interacts with it, including a Frida hook example.

**2. Initial Analysis of the Header File:**

* **File Purpose:** The header file defines structures (`termios`, `termios2`, `ktermios`) and constants related to terminal I/O settings. The comment indicates it's auto-generated and part of the kernel UAPI (User API), meaning it's an interface between the kernel and user-space applications.
* **Key Structures:** The `termios` family of structures holds various flags and control characters that govern how a terminal behaves (input processing, output processing, control modes, local modes, and special characters).
* **Constants:**  The `#define` directives define bitmasks and values for configuring the fields within the `termios` structures. These are divided into categories based on which member of the `termios` structure they affect (e.g., `c_iflag`, `c_oflag`, `c_cc`).
* **Inclusion:** The inclusion of `asm-generic/termbits-common.h` suggests this file provides a generic base for terminal bit definitions, potentially overridden or extended in architecture-specific versions.

**3. Addressing Each Point of the Request:**

* **功能 (Functionality):**  The core function is to define the data structures and constants necessary for configuring terminal devices. This includes controlling things like baud rate, parity, stop bits, echoing, signal generation, and special character handling (like Ctrl+C, Ctrl+Z).

* **与 Android 功能的关系 (Relation to Android):**  Think about where terminals are used in Android. The most prominent example is the shell (command line). Applications that interact with serial ports or pseudo-terminals also rely on these settings. Examples: `adb shell`, terminal emulators, SSH clients, serial communication.

* **libc 函数的实现 (libc Function Implementation):** The header file *itself* doesn't implement libc functions. It defines the *data types* used by functions like `tcgetattr()` and `tcsetattr()`. These functions are responsible for *getting* and *setting* the terminal attributes defined by this header. The explanation needs to focus on *what* these functions do and *how* they use the `termios` structures. Mention the system calls involved (`ioctl`) as that's the underlying mechanism.

* **dynamic linker 功能 (Dynamic Linker):**  This header file is a *header file*. It doesn't contain executable code. Therefore, the dynamic linker isn't directly involved in processing this file. The linker links against libraries (like libc), which *use* the definitions from this header. The SO layout example needs to show a typical libc.so and how an application might link to it. The linking process involves resolving symbols – here, the relevant symbols would be the `tcgetattr` and `tcsetattr` functions.

* **逻辑推理 (Logical Reasoning):**  Create simple scenarios to illustrate how different flags affect terminal behavior. Example: disabling echo, changing the erase character. Provide input and expected output.

* **用户或编程常见的使用错误 (Common Usage Errors):** Think about mistakes developers might make when using terminal settings. Examples: incorrect baud rate leading to garbled communication, forgetting to restore terminal settings after modification, and misunderstanding the effect of specific flags.

* **Android framework or ndk 如何到达这里 (Android Framework/NDK Path):** Trace the path from a high-level Android component down to the usage of these terminal settings.
    * **Framework:**  Start with the Terminal Emulator app. It uses Java APIs, which call down to native code (potentially through JNI).
    * **NDK:** An NDK application might directly call the libc functions (`tcgetattr`, `tcsetattr`).
    * Explain the JNI bridge if the framework is involved.

* **Frida hook 示例 (Frida Hook Example):**  Provide concrete Frida code to intercept calls to `tcgetattr` or `tcsetattr`. The example should demonstrate how to read and potentially modify the arguments (the `termios` structure). Include explanations of the Frida API used.

**4. Structuring the Answer:**

Organize the information logically, following the points of the request. Use clear headings and bullet points for readability. Provide code snippets and examples where appropriate.

**5. Refining and Expanding:**

* **Clarity:** Ensure the language is clear and avoids jargon where possible. Explain technical terms.
* **Completeness:**  Address all aspects of the request thoroughly.
* **Accuracy:** Double-check technical details and code examples.
* **Context:**  Emphasize the role of this header file in the broader context of terminal I/O and Android.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing too much on the *content* of the flags without explaining *why* they matter. *Correction:*  Emphasize the *effects* of the flags on terminal behavior.
* **Initial thought:**  Thinking the dynamic linker *directly* processes header files. *Correction:*  The linker processes compiled object code and libraries, which *use* the definitions from header files.
* **Initial thought:** Providing a very basic Frida example. *Correction:*  Make the Frida example more illustrative by showing how to access and interpret the `termios` structure members.
* **Initial thought:** Not clearly explaining the JNI bridge in the framework path. *Correction:*  Explicitly mention JNI as the mechanism for calling native code from the Java framework.

By following this structured approach and iteratively refining the answer, we can generate a comprehensive and accurate response to the request.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/asm-generic/termbits.handroid` 这个头文件。

**功能列举**

这个头文件定义了与终端设备属性相关的结构体和常量，主要用于控制和配置终端的行为。具体功能包括：

1. **定义了终端属性结构体：**  `termios`, `termios2`, `ktermios`，这些结构体用于存储终端的各种配置信息。
2. **定义了终端控制标志：**  例如输入模式标志 (`c_iflag`)、输出模式标志 (`c_oflag`)、控制模式标志 (`c_cflag`)、本地模式标志 (`c_lflag`)。
3. **定义了特殊控制字符索引：**  例如 `VINTR` (中断字符)、`VQUIT` (退出字符)、`VERASE` (擦除字符) 等，它们对应 `c_cc` 数组中的索引。
4. **定义了各种控制标志的位掩码：**  例如 `IXON` (启用软件流控制)、`ECHO` (回显输入字符)、`CRTSCTS` (启用硬件流控制) 等。
5. **定义了波特率常量：**  例如 `B9600`, `B115200` 等。

**与 Android 功能的关系及举例**

这个头文件定义的内容是 POSIX 标准的一部分，与 Linux 系统（Android 的内核是基于 Linux 的）的终端操作密切相关。Android 的许多功能都依赖于终端或伪终端（pty）的概念。

* **Shell (命令行界面)：**  当你在 Android 设备上使用 `adb shell` 或终端模拟器应用时，这些操作都涉及到终端的配置。例如，当你输入命令时，终端需要处理你的输入（是否回显、如何处理特殊字符），并将输出显示在屏幕上。这些行为都受到 `termios` 结构体中定义的标志控制。
* **串口通信：**  如果 Android 设备通过串口与其他设备通信，那么就需要配置串口的参数，例如波特率、数据位、校验位等，这些参数会映射到 `termios` 结构体的 `c_cflag` 成员。
* **伪终端（pty）：**  Android 系统内部使用伪终端来实现进程间的通信，例如 `ssh` 服务。伪终端的行为也需要通过 `termios` 结构体进行配置。

**举例说明：**

假设你希望在 Android 的终端模拟器中禁用输入字符的回显。这可以通过修改 `termios` 结构体的 `c_lflag` 成员来实现，具体是清除 `ECHO` 标志。相关的 libc 函数会使用这个头文件中定义的 `ECHO` 常量。

**详细解释 libc 函数的功能及其实现**

这个头文件本身并不包含 libc 函数的实现，它只是定义了数据结构和常量。与这个头文件相关的 libc 函数主要有以下几个：

* **`tcgetattr(int fd, struct termios *termios_p)`:**
    * **功能：** 获取与文件描述符 `fd` 关联的终端的当前属性，并将属性存储在 `termios_p` 指向的 `termios` 结构体中。
    * **实现：**  `tcgetattr` 函数通常会通过系统调用（例如 `ioctl`）与内核进行交互。内核会读取与该终端设备相关的数据结构，并将当前的终端配置信息填充到用户空间提供的 `termios` 结构体中。
    * **涉及 dynamic linker：** `tcgetattr` 函数是 libc 库提供的，应用程序需要链接到 libc 库才能使用它。dynamic linker 负责在程序运行时加载 libc 库，并将应用程序中对 `tcgetattr` 的调用链接到 libc 库中对应的实现。

* **`tcsetattr(int fd, int optional_actions, const struct termios *termios_p)`:**
    * **功能：** 设置与文件描述符 `fd` 关联的终端的属性。`optional_actions` 参数指定了何时应用这些更改（例如，立即应用 `TCSANOW`，等待所有输出完成 `TCSADRAIN`，刷新输入输出队列 `TCSAFLUSH`）。终端的期望属性由 `termios_p` 指向的 `termios` 结构体指定。
    * **实现：** `tcsetattr` 函数同样会通过系统调用（例如 `ioctl`) 与内核交互。内核会根据 `termios_p` 中提供的新配置信息更新终端设备的状态。
    * **涉及 dynamic linker：** 类似于 `tcgetattr`，`tcsetattr` 也是 libc 库提供的，需要 dynamic linker 进行链接。

* **`cfsetispeed(struct termios *termios_p, speed_t speed)` 和 `cfsetospeed(struct termios *termios_p, speed_t speed)`:**
    * **功能：** 分别设置 `termios` 结构体中的输入和输出波特率。
    * **实现：** 这两个函数直接操作 `termios` 结构体的 `c_ispeed` 和 `c_ospeed` 成员。它们本身不涉及系统调用，只是辅助修改 `termios` 结构体。最终需要通过 `tcsetattr` 将修改后的属性应用到终端。

* **`cfgetispeed(const struct termios *termios_p)` 和 `cfgetospeed(const struct termios *termios_p)`:**
    * **功能：** 分别获取 `termios` 结构体中的输入和输出波特率。
    * **实现：** 这两个函数直接读取 `termios` 结构体的 `c_ispeed` 和 `c_ospeed` 成员。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

**SO 布局样本 (libc.so):**

```
libc.so:
    .text:  # 存放可执行代码
        ...
        _ZN6android4base17LogMessageData流操作相关函数... # Android 特有的日志函数
        tcgetattr:                      # tcgetattr 函数的实现代码
            push   %ebp
            mov    %esp,%ebp
            ...
            call   ioctl                 # 系统调用
            ...
            pop    %ebp
            ret
        tcsetattr:                      # tcsetattr 函数的实现代码
            push   %ebp
            mov    %esp,%ebp
            ...
            call   ioctl                 # 系统调用
            ...
            pop    %ebp
            ret
        ...
    .data:  # 存放已初始化的全局变量和静态变量
        ...
    .bss:   # 存放未初始化的全局变量和静态变量
        ...
    .dynsym: # 动态符号表，包含导出的和导入的符号信息
        ...
        tcgetattr
        tcsetattr
        ...
    .dynstr: # 动态字符串表，存储符号名
        ...
        tcgetattr
        tcsetattr
        ...
    .plt:   # 程序链接表，用于延迟绑定
        tcgetattr@plt:
            jmp    *(%GOT+offset_tcgetattr)
        tcsetattr@plt:
            jmp    *(%GOT+offset_tcsetattr)
        ...
    .got:   # 全局偏移表，存放外部符号的地址
        offset_tcgetattr: 0x...
        offset_tcsetattr: 0x...
        ...
```

**链接的处理过程：**

1. **编译时：** 当你编译一个使用 `tcgetattr` 或 `tcsetattr` 的 C/C++ 程序时，编译器会生成对这些函数的调用。由于这些函数定义在 libc 中，编译器会将这些调用标记为外部符号。
2. **链接时：** 链接器（如 `ld`）会将你的目标文件与 libc.so 链接在一起。链接器会查找 libc.so 的动态符号表 (`.dynsym`)，找到 `tcgetattr` 和 `tcsetattr` 的符号信息。链接器会在你的程序中生成程序链接表 (`.plt`) 和全局偏移表 (`.got`) 的条目，用于在运行时动态地解析这些外部符号的地址。
3. **运行时：**
   * 当你的程序启动时，dynamic linker（如 `linker` 或 `linker64`）会被加载。
   * Dynamic linker 会加载所有需要的共享库，包括 libc.so。
   * Dynamic linker 会解析程序中对外部符号的引用。对于 `tcgetattr` 和 `tcsetattr`，dynamic linker 会在 libc.so 的 `.text` 段中找到它们的实际地址，并将这些地址填充到程序的全局偏移表 (`.got`) 中对应的条目。
   * 当程序第一次调用 `tcgetattr` 或 `tcsetattr` 时，会通过程序链接表 (`.plt`) 跳转到全局偏移表 (`.got`) 中相应的条目。由于此时地址已经被 dynamic linker 填充，所以会直接跳转到 libc.so 中函数的实际实现。这就是所谓的**延迟绑定**。

**如果做了逻辑推理，请给出假设输入与输出**

**假设输入：**

一个 Android 应用程序需要配置串口设备 `/dev/ttyS0`，设置波特率为 115200，8 个数据位，无校验，1 个停止位。

**逻辑推理步骤：**

1. **获取当前串口属性：** 使用 `tcgetattr(fd, &oldtio)` 获取 `/dev/ttyS0` 的当前属性，存储在 `oldtio` 结构体中。
2. **复制当前属性：** 将 `oldtio` 的内容复制到新的 `termios` 结构体 `newtio` 中，`newtio = oldtio;`。
3. **配置控制模式 (c_cflag)：**
   * 清除所有控制模式标志：`newtio.c_cflag = 0;`
   * 设置波特率：`cfsetospeed(&newtio, B115200); cfsetispeed(&newtio, B115200);` 或直接设置 `newtio.c_cflag |= B115200;`
   * 设置数据位：清除 `CSIZE` 掩码，设置 8 个数据位 `newtio.c_cflag |= CS8;`
   * 设置无校验：清除 `PARENB` 和 `PARODD` 标志。
   * 设置 1 个停止位：不设置 `CSTOPB` 标志。
   * 启用接收：`newtio.c_cflag |= CREAD;`
4. **配置本地模式 (c_lflag)：**  可能需要关闭一些本地模式，例如禁用回显 `newtio.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);`（根据具体需求）。
5. **配置输入模式 (c_iflag)：** 可能需要禁用一些输入处理，例如禁用软件流控制 `newtio.c_iflag &= ~(IXON | IXOFF | IXANY);`（根据具体需求）。
6. **应用新的属性：** 使用 `tcsetattr(fd, TCSANOW, &newtio)` 将新的属性应用到串口设备。

**假设输出：**

经过上述步骤，`/dev/ttyS0` 串口设备的属性应该被成功修改为波特率 115200，8 个数据位，无校验，1 个停止位。后续对该串口的读写操作将按照这些新的参数进行。

**如果涉及用户或者编程常见的使用错误，请举例说明**

1. **忘记检查返回值：** `tcgetattr` 和 `tcsetattr` 函数在出错时会返回 -1，并设置 `errno`。程序员可能会忘记检查返回值，导致在错误发生时没有进行处理。
   ```c
   struct termios tio;
   int fd = open("/dev/ttyS0", O_RDWR);
   tcgetattr(fd, &tio); // 如果 open 失败，fd 可能无效，导致 tcgetattr 失败
   // ... 修改 tio ...
   tcsetattr(fd, TCSANOW, &tio); // 如果 tcgetattr 失败，tio 的内容可能未定义
   ```

2. **不正确地使用 `optional_actions` 参数：**  `tcsetattr` 的第二个参数控制何时应用更改。使用错误的参数可能会导致意想不到的行为。例如，使用 `TCSADRAIN` 会等待所有输出完成，如果输出缓冲区很大，可能会导致程序阻塞。

3. **不恢复终端原始属性：**  在程序结束前，应该将终端属性恢复到原始状态，特别是对于交互式程序。如果不恢复，可能会影响后续在同一终端上运行的其他程序。
   ```c
   struct termios oldtio, newtio;
   int fd = 0; // 标准输入
   tcgetattr(fd, &oldtio);
   newtio = oldtio;
   newtio.c_lflag &= ~ECHO; // 关闭回显
   tcsetattr(fd, TCSANOW, &newtio);
   // ... 执行一些操作 ...
   // 忘记恢复原始属性
   ```

4. **对非终端设备调用终端函数：**  `tcgetattr` 和 `tcsetattr` 只能用于终端设备。如果对普通文件或其他类型的描述符调用这些函数，会导致错误。

5. **波特率设置错误：**  设置了硬件不支持的波特率会导致通信失败。应该使用头文件中定义的标准波特率常量。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤 (以 Terminal Emulator 应用为例)：**

1. **Java 层：** 用户在 Terminal Emulator 应用中输入命令或进行操作。
2. **JNI 调用：** Terminal Emulator 应用的 Java 代码会通过 JNI (Java Native Interface) 调用到 native 层（C/C++ 代码）。
3. **Native 层 (通常在应用自身的 native 库中)：**  Native 代码可能会调用 Android 的 Bionic 库提供的终端相关函数，例如 `open()`, `read()`, `write()`, `ioctl()` (间接地通过 `tcgetattr`, `tcsetattr` 等)。
4. **Bionic libc：** Bionic libc 实现了 `tcgetattr` 和 `tcsetattr` 等函数。这些函数会最终通过 `ioctl()` 系统调用与内核交互。
5. **内核驱动：** 内核接收到 `ioctl()` 系统调用后，会调用相应的终端驱动程序来处理请求，修改或读取终端设备的属性。

**NDK 应用到达这里的步骤：**

1. **NDK C/C++ 代码：** NDK 应用程序可以直接调用 Bionic libc 提供的终端相关函数，例如 `tcgetattr()`, `tcsetattr()`, `open()`.
2. **Bionic libc：**  NDK 应用调用的 libc 函数直接链接到 Bionic libc 的实现。
3. **内核驱动：** Bionic libc 的函数通过 `ioctl()` 系统调用与内核终端驱动交互。

**Frida Hook 示例调试步骤：**

假设你想 hook `tcsetattr` 函数，查看应用程序设置的终端属性。

**Frida 脚本 (`hook_tcsetattr.js`):**

```javascript
if (Process.platform === 'linux') {
  const tcsetattr = Module.findExportByName("libc.so", "tcsetattr");
  if (tcsetattr) {
    Interceptor.attach(tcsetattr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const optional_actions = args[1].toInt32();
        const termiosPtr = ptr(args[2]);

        console.log("tcsetattr called with fd:", fd, "optional_actions:", optional_actions);

        if (termiosPtr) {
          const termios = {
            c_iflag: termiosPtr.readU32(),
            c_oflag: termiosPtr.add(4).readU32(),
            c_cflag: termiosPtr.add(8).readU32(),
            c_lflag: termiosPtr.add(12).readU32(),
            c_line: termiosPtr.add(16).readU8(),
            c_cc: Array.from({ length: 19 }, (_, i) => termiosPtr.add(17 + i).readU8()),
            c_ispeed: termiosPtr.add(36).readU32(),
            c_ospeed: termiosPtr.add(40).readU32(),
          };
          console.log("termios structure:", termios);
        }
      }
    });
  } else {
    console.log("tcsetattr not found in libc.so");
  }
} else {
  console.log("This script is for Linux (Android) only.");
}
```

**Frida 调试步骤：**

1. **找到目标进程：**  使用 `adb shell ps | grep <process_name>` 找到你想要调试的应用程序的进程 ID (PID)。例如，对于 Terminal Emulator 应用，进程名可能是 `com.termux` 或类似的。
2. **运行 Frida：** 使用 Frida 连接到目标进程并加载 hook 脚本。
   ```bash
   frida -U -f <package_name> -l hook_tcsetattr.js --no-pause
   # 或者如果进程已经在运行：
   frida -U <process_id> -l hook_tcsetattr.js
   ```
   将 `<package_name>` 替换为应用程序的包名，`<process_id>` 替换为进程 ID。
3. **操作应用程序：**  在应用程序中执行会导致调用 `tcsetattr` 的操作。例如，在 Terminal Emulator 中输入命令或连接到 SSH 服务器。
4. **查看 Frida 输出：** Frida 会拦截对 `tcsetattr` 的调用，并在控制台上打印出文件描述符、`optional_actions` 参数以及 `termios` 结构体的各个成员的值。通过查看这些输出，你可以了解应用程序是如何配置终端属性的。

**注意：**  你需要 root 权限才能使用 Frida hook 其他应用程序的进程。

希望这个详细的解释能够帮助你理解 `bionic/libc/kernel/uapi/asm-generic/termbits.handroid` 文件及其在 Android 中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-generic/termbits.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __ASM_GENERIC_TERMBITS_H
#define __ASM_GENERIC_TERMBITS_H
#include <asm-generic/termbits-common.h>
typedef unsigned int tcflag_t;
#define NCCS 19
struct termios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[NCCS];
};
struct termios2 {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[NCCS];
  speed_t c_ispeed;
  speed_t c_ospeed;
};
struct ktermios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[NCCS];
  speed_t c_ispeed;
  speed_t c_ospeed;
};
#define VINTR 0
#define VQUIT 1
#define VERASE 2
#define VKILL 3
#define VEOF 4
#define VTIME 5
#define VMIN 6
#define VSWTC 7
#define VSTART 8
#define VSTOP 9
#define VSUSP 10
#define VEOL 11
#define VREPRINT 12
#define VDISCARD 13
#define VWERASE 14
#define VLNEXT 15
#define VEOL2 16
#define IUCLC 0x0200
#define IXON 0x0400
#define IXOFF 0x1000
#define IMAXBEL 0x2000
#define IUTF8 0x4000
#define OLCUC 0x00002
#define ONLCR 0x00004
#define NLDLY 0x00100
#define NL0 0x00000
#define NL1 0x00100
#define CRDLY 0x00600
#define CR0 0x00000
#define CR1 0x00200
#define CR2 0x00400
#define CR3 0x00600
#define TABDLY 0x01800
#define TAB0 0x00000
#define TAB1 0x00800
#define TAB2 0x01000
#define TAB3 0x01800
#define XTABS 0x01800
#define BSDLY 0x02000
#define BS0 0x00000
#define BS1 0x02000
#define VTDLY 0x04000
#define VT0 0x00000
#define VT1 0x04000
#define FFDLY 0x08000
#define FF0 0x00000
#define FF1 0x08000
#define CBAUD 0x0000100f
#define CSIZE 0x00000030
#define CS5 0x00000000
#define CS6 0x00000010
#define CS7 0x00000020
#define CS8 0x00000030
#define CSTOPB 0x00000040
#define CREAD 0x00000080
#define PARENB 0x00000100
#define PARODD 0x00000200
#define HUPCL 0x00000400
#define CLOCAL 0x00000800
#define CBAUDEX 0x00001000
#define BOTHER 0x00001000
#define B57600 0x00001001
#define B115200 0x00001002
#define B230400 0x00001003
#define B460800 0x00001004
#define B500000 0x00001005
#define B576000 0x00001006
#define B921600 0x00001007
#define B1000000 0x00001008
#define B1152000 0x00001009
#define B1500000 0x0000100a
#define B2000000 0x0000100b
#define B2500000 0x0000100c
#define B3000000 0x0000100d
#define B3500000 0x0000100e
#define B4000000 0x0000100f
#define CIBAUD 0x100f0000
#define ISIG 0x00001
#define ICANON 0x00002
#define XCASE 0x00004
#define ECHO 0x00008
#define ECHOE 0x00010
#define ECHOK 0x00020
#define ECHONL 0x00040
#define NOFLSH 0x00080
#define TOSTOP 0x00100
#define ECHOCTL 0x00200
#define ECHOPRT 0x00400
#define ECHOKE 0x00800
#define FLUSHO 0x01000
#define PENDIN 0x04000
#define IEXTEN 0x08000
#define EXTPROC 0x10000
#define TCSANOW 0
#define TCSADRAIN 1
#define TCSAFLUSH 2
#endif

"""

```